use std::{collections::HashMap};

use consensus::{LargeField, vandermonde_matrix, inverse_vandermonde, matrix_vector_multiply};
use ha_crypto::hash::Hash;
use lambdaworks_math::{traits::ByteConversion, polynomial::Polynomial};
use types::Replica;

use rayon::prelude::{IntoParallelIterator, ParallelIterator};


use crate::{Context, AcssSKEShares, protocol::ACSSABState};

impl Context{
    pub async fn process_pub_rec_quad_msg(&mut self, instance_id: usize, acss_msg: AcssSKEShares, share_sender: Replica){
        log::info!("Received PubRecL1 message for instance {} of party {}, shares received from party {}", instance_id, acss_msg.rep, share_sender);
        if !self.acss_ab_state.contains_key(&instance_id){
            let acss_ab_state = ACSSABState::new();
            self.acss_ab_state.insert(instance_id, acss_ab_state);
        }

        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        
        if acss_ab_state.public_reconstruction_quad_status.contains(&acss_msg.rep){
            log::info!("Public reconstruction l1 already complete for party {} in instance {}", acss_msg.rep, instance_id);
            return;
        }
        if !acss_ab_state.commitments.contains_key(&acss_msg.rep){
            log::error!("No commitments found for party {} in instance {}", acss_msg.rep, instance_id);
            return;
        }
        // Generate and verify commitments
        let va_commitment = acss_ab_state.commitments.get(&acss_msg.rep).unwrap();

        let sender = acss_msg.rep.clone();
        let shares_full = acss_msg;
        // let shares = acss_msg.evaluations.0.clone();
        // let nonce_share = acss_msg.evaluations.1[0].clone();
        // let share_mp = acss_msg.evaluations.2[0].clone();
        
        let shares: Vec<LargeField> = shares_full.evaluations.0.into_iter().map(|el| 
            LargeField::from_bytes_be(el.as_slice()).unwrap()
        ).collect();
        let nonce_shares = shares_full.evaluations.1.into_iter().map(|el| 
            LargeField::from_bytes_be(el.as_slice()).unwrap()
        ).collect();
        let merkle_proofs = shares_full.evaluations.2;
        
        let evaluation_points;
        if !self.use_fft{
            evaluation_points = (1..self.num_nodes+1).into_iter().map(|x| LargeField::from(x as u64)).collect();
        }
        else{
            evaluation_points = self.roots_of_unity.clone();
        }

        let roots_from_proofs: Vec<Hash> = merkle_proofs.iter().map(|proof| proof.root()).collect();
        
        if roots_from_proofs != va_commitment.column_roots {
            log::error!("Share commitment roots mismatch for instance {} from sender {}", instance_id, sender);
            return;
        }
        if !Self::verify_commitments(
            self.num_faults+1, 
            evaluation_points.clone(), 
            shares.clone(), 
            nonce_shares, 
            merkle_proofs, 
            &self.hash_context
        ){
            log::error!("Share commitment verification failed for instance {} from sender {}", instance_id, sender);
            return;
        }

        log::info!("Successfully verified commitments of shares sent by sender {} in instance_id {}", sender, instance_id);
        // Blinding share verification next
        let blinding_shares: Vec<LargeField> = shares_full.blinding_evaluations.0.into_iter().map(|el| 
            LargeField::from_bytes_be(el.as_slice()).unwrap()
        ).collect();
        let blinding_nonce_shares = shares_full.blinding_evaluations.1.into_iter().map(|el| 
            LargeField::from_bytes_be(el.as_slice()).unwrap()
        ).collect();
        let blinding_merkle_proofs = shares_full.blinding_evaluations.2;

        let blinding_merkle_roots: Vec<Hash> = blinding_merkle_proofs.iter().map(|proof| proof.root()).collect();
        if blinding_merkle_roots != va_commitment.blinding_column_roots {
            log::error!("Blinding share commitment roots mismatch for instance {} from sender {}", instance_id, sender);
            return;
        }

        if !Self::verify_blinding_commitments(
            blinding_shares.clone(), 
            blinding_nonce_shares,
            blinding_merkle_proofs, 
            &self.hash_context
        ){
            log::error!("Blinding share commitment verification failed for instance {} from sender {}", instance_id, sender);
            return;
        }

        log::info!("Successfully verified blinding commitments of shares sent by sender {} in instance_id {}", sender, instance_id);
        // Finally, verify DZK proofs
        let grouped_points = Self::group_points_for_public_reconstruction(
            shares.clone(), 
            evaluation_points.clone(), 
            self.num_faults+1
        );

        let root_comm_fe: Vec<LargeField> = roots_from_proofs.iter().zip(blinding_merkle_roots.iter()).map(|(root, b_root)|{
            //let root = mt.root();
            let root_combined = self.hash_context.hash_two(root.clone(), b_root.clone());
            return LargeField::from_bytes_be(root_combined.as_slice()).unwrap();
        }).collect();

        let dzk_aggregated_points: Vec<LargeField> = grouped_points.into_iter().zip(
            root_comm_fe.clone().into_iter()).map(|(shares, root)|{
                return self.folding_dzk_context.gen_agg_poly_dzk(shares, root.to_bytes_be());
            }).collect();

        let status = self.folding_dzk_context.verify_dzk_proof_row(
            shares_full.dzk_iters.clone(), 
            va_commitment.dzk_roots.clone(), 
            va_commitment.polys.clone(), 
            root_comm_fe.into_iter().map(|el| el.to_bytes_be()).collect(), 
            dzk_aggregated_points, 
            blinding_shares.clone(), 
            share_sender+1
        );

        if !status{
            log::error!("DZK proof verification failed for instance {} from sender {}", instance_id, sender);
            return;
        }

        log::info!("Successfully verified DZK proofs of shares sent by sender {} for ACSS of instance {} in instance_id {}", share_sender, sender, instance_id);

        if !acss_ab_state.public_reconstruction_quad_shares.contains_key(&sender){
            acss_ab_state.public_reconstruction_quad_shares.insert(sender, HashMap::default());
        }

        let tot_share_count = shares.len();

        let quad_pub_rec_map = acss_ab_state.public_reconstruction_quad_shares.get_mut(&sender).unwrap();
        quad_pub_rec_map.insert(share_sender, shares);

        if quad_pub_rec_map.len() == self.num_faults+1{
            // Reconstruct secrets
            // Reconstruct the secrets
            log::info!("t+1 shares received for share polynomials of party {}", sender);
            let mut eval_points = Vec::new();
            let mut shares_indexed: Vec<Vec<LargeField>> = Vec::new();
            for _ in 0..tot_share_count{
                shares_indexed.push(Vec::new());
            }
            for party in 0..self.num_nodes{
                if quad_pub_rec_map.contains_key(&party){
                    eval_points.push(LargeField::from((party+1) as u64));
                    let shares_party = quad_pub_rec_map.get(&party).unwrap();
                    for (index,share) in shares_party.into_iter().enumerate(){
                        shares_indexed[index].push(share.clone());
                    }
                }
            }
            // Interpolate polynomials
            let secret_evaluation_point;
            if !self.use_fft{
                secret_evaluation_point = LargeField::from(0 as u64);
            }
            else{
                secret_evaluation_point = self.roots_of_unity.get(0).unwrap().clone();
            }

            // Generate vandermonde matrix
            let vandermonde = vandermonde_matrix(eval_points.clone());
            let inverse_vandermonde = inverse_vandermonde(vandermonde);

            let secrets : Vec<LargeField> = shares_indexed.into_par_iter().map(|evals|{
                let coefficients = matrix_vector_multiply(&inverse_vandermonde, &evals);
                return Polynomial::new(&coefficients).evaluate(&secret_evaluation_point);
            }).collect();

            acss_ab_state.public_reconstruction_l1_status.insert(sender);
            log::info!("Successfully interpolated shares for l2 public reconstruction for instance id {} and source party {}", instance_id, sender);
            let _status = self.out_pub_rec_out.send((instance_id, sender, secrets)).await;
        }
    }
}