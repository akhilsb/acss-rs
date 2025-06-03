use std::{ops::{Add, Mul, Div}, collections::HashMap};

use consensus::{LargeField, LargeFieldSer, DZKProof, vandermonde_matrix, inverse_vandermonde, matrix_vector_multiply};
use crypto::{aes_hash::{MerkleTree, HashState, Proof}, hash::{Hash, do_hash}};
use lambdaworks_math::{polynomial::Polynomial, traits::ByteConversion};
use rayon::prelude::{IntoParallelIterator, ParallelIterator, IntoParallelRefIterator, IndexedParallelIterator};
use types::{Replica, WrapperMsg};

use crate::{Context, msg::{AcssSKEShares, ProtMsg}, protocol::ACSSABState};

impl Context{
    pub fn group_polynomials_for_public_reconstruction(
        polynomials: Vec<Polynomial<LargeField>>,
        evaluation_points: Vec<LargeField>,
        group_degree: usize
    )-> Vec<Vec<Polynomial<LargeField>>>{
        let coefficients_grouped: Vec<Vec<Polynomial<LargeField>>> = polynomials.chunks(group_degree).map(|el_vec| el_vec.to_vec()).collect();
        
        let collection_evaluation_points: Vec<Vec<Polynomial<LargeField>>> = evaluation_points.into_par_iter().map(|element|{
            // Compute t+1 powers
            let mut powers = vec![LargeField::one()];
            let mut element_power = LargeField::one();
            for _ in 0..group_degree-1{
                element_power = element_power*element;
                powers.push(element_power.clone());
            }
            // Use these powers zipped with the coefficients
            let agg_polys: Vec<Polynomial<LargeField>> = coefficients_grouped.par_iter().map(|group| {
                let dot_product: Vec<Polynomial<LargeField>> 
                    = group.iter().zip(powers.iter()).map(|(poly,power)| poly*power).collect();
                let sum: Polynomial<LargeField> 
                    = dot_product.iter().fold(Polynomial::zero(), |acc, poly| acc + poly);
                return sum;
            }).collect();
            return agg_polys;
        }).collect();
        collection_evaluation_points
    }

    pub fn group_points_for_public_reconstruction(
        evaluations: Vec<LargeField>,
        evaluation_points: Vec<LargeField>,
        group_degree: usize
    )-> Vec<Vec<LargeField>>{
        let coefficients_grouped: Vec<Vec<LargeField>> = evaluations.chunks(group_degree).map(|el_vec| el_vec.to_vec()).collect();
        
        let collection_evaluation_points: Vec<Vec<LargeField>> = evaluation_points.into_par_iter().map(|element|{
            // Compute t+1 powers
            let mut powers = vec![LargeField::one()];
            let mut element_power = LargeField::one();
            for _ in 0..group_degree-1{
                element_power = element_power*element;
                powers.push(element_power.clone());
            }
            // Use these powers zipped with the coefficients
            let agg_polys: Vec<LargeField> = coefficients_grouped.par_iter().map(|group| {
                let dot_product: Vec<LargeField> 
                    = group.iter().zip(powers.iter()).map(|(poly,power)| poly*power).collect();
                let sum: LargeField 
                    = dot_product.iter().fold(LargeField::zero(), |acc, poly| acc + poly);
                return sum;
            }).collect();
            return agg_polys;
        }).collect();

        collection_evaluation_points
    }

    pub fn compute_commitments(
        coefficients: Vec<Vec<Polynomial<LargeField>>>,
        evaluation_points: Vec<LargeField>,
        nonce_evaluations: Vec<Vec<LargeField>>,
        hash_context: &HashState
    )-> Vec<MerkleTree> {
        let merkle_trees: Vec<MerkleTree> = coefficients.par_iter().zip(nonce_evaluations.par_iter()).map(|(eval_vec, nonce_vec)|{
            let evaluations: Vec<Vec<LargeFieldSer>> = eval_vec.into_par_iter().map(|poly| {
                let evaluations: Vec<LargeFieldSer> = evaluation_points.iter().map(|point| poly.evaluate(point).clone().to_bytes_be()).collect();
                return evaluations;
            }).collect();
            let mut appended_shares: Vec<Vec<u8>> = vec![vec![]; evaluation_points.len()];
            for evaluation_single_poly in evaluations.into_iter(){
                for (index,eval_serialized) in evaluation_single_poly.into_iter().enumerate(){
                    appended_shares[index].extend(eval_serialized);
                }
            }
            // append nonce shares to appended_shares
            for (index, nonce_share) in nonce_vec.iter().enumerate(){
                appended_shares[index].extend(nonce_share.to_bytes_be());
            }
            // Build Merkle tree on these appended shares
            let hashes: Vec<Hash> = appended_shares.into_iter().map(|share|{
                do_hash(share.as_slice())
            }).collect();

            MerkleTree::new(hashes, hash_context)
        }).collect();
        merkle_trees
    }

    pub fn verify_commitments(
        chunk_size: usize,
        evaluation_points: Vec<LargeField>,
        shares: Vec<LargeField>,
        nonce_shares: Vec<LargeField>,
        merkle_proofs: Vec<Proof>,
        hc: &HashState
    )-> bool{
        let grouped_shares: Vec<Vec<LargeField>> = Self::group_points_for_public_reconstruction(
            shares, 
            evaluation_points, 
            chunk_size
        );
        let hashes: Vec<Hash> = grouped_shares.into_iter().zip(nonce_shares.into_iter()).map(|(grp, nonce)|{
            let mut appended_share = vec![];
            for share in grp.into_iter() {
                appended_share.extend(share.to_bytes_be());
            }
            appended_share.extend(nonce.to_bytes_be());
            return do_hash(appended_share.as_slice());
        }).collect();

        let mut proof_flag = true;
        for (hash, proof) in hashes.into_iter().zip(merkle_proofs.into_iter()){
            proof_flag &= proof.validate(hc) && proof.item() == hash;
        }
        proof_flag
    }

    pub fn verify_blinding_commitments(
        blinding_shares: Vec<LargeField>,
        blinding_nonce_shares: Vec<LargeField>,
        blinding_merkle_proofs: Vec<Proof>,
        hc: &HashState,    
    ) -> bool{
        let hashes: Vec<Hash> = blinding_shares.into_iter().zip(blinding_nonce_shares.into_iter()).map(|(share, nonce)|{
            let mut appended_share = vec![];
            appended_share.extend(share.to_bytes_be());
            appended_share.extend(nonce.to_bytes_be());
            return do_hash(appended_share.as_slice());
        }).collect();

        let mut proof_flag = true;
        for (hash, proof) in hashes.into_iter().zip(blinding_merkle_proofs.into_iter()){
            proof_flag &= proof.validate(hc) && proof.item() == hash;
        }
        proof_flag
    }

    pub fn aggregate_polynomials_for_dzk(
        polys: Vec<Vec<Polynomial<LargeField>>>,
        blinding_polys: Vec<Polynomial<LargeField>>,
        root_fes: Vec<LargeField>
    )-> Vec<Polynomial<LargeField>>{
        let agg_poly_vector: Vec<Polynomial<LargeField>> = (polys.into_par_iter().zip(
            blinding_polys.clone().into_par_iter()
        )).zip(root_fes.clone().into_par_iter()).map(|((poly_group, b_poly), root_fe)|{
            // Start aggregation
            let mut agg_poly = b_poly.clone();
            let mut root_fe_iter_mul = root_fe.clone();
            for poly in poly_group.into_iter(){
                agg_poly = agg_poly.add(poly.mul(&root_fe_iter_mul));
                root_fe_iter_mul *= &root_fe;
            }
            return agg_poly.clone();
        }).collect();
        // Temporary, for logging purposes
        // let evaluation_points: Vec<usize> = (1..root_fes.len()+1).into_iter().collect();
        // let agg_points: Vec<Vec<LargeField>> = agg_poly_vector.iter().map(|poly|{
        //     let mut eval_vec = vec![];
        //     for point in evaluation_points.iter(){
        //         eval_vec.push(poly.evaluate(&LargeField::from(*point as u64)).clone());
        //     }
        //     eval_vec
        // }).collect();
        // let blinding_poly_points: Vec<Vec<LargeField>> = blinding_polys.iter().map(|poly|{
        //     let mut eval_vec = vec![];
        //     for point in evaluation_points.iter(){
        //         eval_vec.push(poly.evaluate(&LargeField::from(*point as u64)).clone());
        //     }
        //     eval_vec
        // }).collect();
        // log::info!("Aggregated polynomial evaluations: {:?}", agg_points);
        // log::info!("Aggregated blinding polynomial evaluations: {:?}", blinding_poly_points);
        agg_poly_vector
    }

    pub fn aggregate_points_for_dzk(
        points: Vec<Vec<LargeField>>,
        blinding_points: Vec<LargeField>,
        root_fes: Vec<LargeField>
    )-> Vec<LargeField>{
        let agg_point_vector: Vec<LargeField> = (points.into_par_iter().zip(
            blinding_points.into_par_iter()
        )).zip(root_fes.into_par_iter()).map(|((point_group, b_point), root_fe)|{
            // Start aggregation
            let mut agg_poly = b_point.clone();
            let mut root_fe_iter_mul = root_fe.clone();
            for poly in point_group.into_iter(){
                agg_poly = agg_poly.add(poly.mul(&root_fe_iter_mul));
                root_fe_iter_mul *= &root_fe;
            }
            return agg_poly.clone();
        }).collect();
        agg_point_vector
    }

    pub fn compute_dzk_proofs(
        &self,
        dzk_share_polynomials: Vec<Polynomial<LargeField>>,
        column_wise_roots: Vec<LargeField>
    ) -> (Vec<Vec<DZKProof>>, Vec<Vec<LargeFieldSer>>, Vec<Vec<LargeFieldSer>>){
        // (Replica, (g_0 values), (g_1 values), (Vector of Merkle Proofs for each g_0,g_1 value))
        let mut shares_proofs_dzk: Vec<Vec<DZKProof>> = Vec::new();
        let mut dzk_broadcast_polys = Vec::new();
        let mut hashes = Vec::new();
        for _ in 0..self.num_nodes{
            shares_proofs_dzk.push(Vec::new());
        }
        for (dzk_poly,column_root) in dzk_share_polynomials.into_iter().zip(column_wise_roots.into_iter()){
            
            let mut merkle_roots = Vec::new();
            let mut eval_points = Vec::new();
            
            let mut trees: Vec<MerkleTree> = Vec::new();
            //trees.push(mts[rep].clone());
            
            let coefficients = dzk_poly.clone();
            
            let iteration = 1;
            let root = column_root;
            //merkle_roots.push(root.clone());

            // Reliably broadcast these coefficients
            let coeffs_const_size: Vec<LargeFieldSer> = self.folding_dzk_context.gen_dzk_proof(
                &mut eval_points, 
                &mut trees, 
                coefficients.coefficients.clone(), 
                iteration, 
                root.to_bytes_be()
            ).into_iter().map(|x| x.to_bytes_be()).collect();
            
            for tree in trees.iter(){
                merkle_roots.push(tree.root());
            }
            dzk_broadcast_polys.push(coeffs_const_size);

            let mut dzk_proofs_all_nodes = Vec::new();
            for _ in 0..self.num_nodes{
                dzk_proofs_all_nodes.push(DZKProof{
                    g_0_x: Vec::new(),
                    g_1_x: Vec::new(),
                    proof: Vec::new(),
                });
            }

            
            for (g_0_g_1_shares,mt) in eval_points.into_iter().zip(trees.into_iter()){                
                for (rep,g) in (0..self.num_nodes).into_iter().zip(g_0_g_1_shares.into_iter()){
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().g_0_x.push(g.0.to_bytes_be());
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().g_1_x.push(g.1.to_bytes_be());
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().proof.push(mt.gen_proof(rep));
                }
            }

            for (rep,proof) in (0..self.num_nodes).into_iter().zip(dzk_proofs_all_nodes.into_iter()){
                shares_proofs_dzk[rep].push(proof);
            }
            hashes.push(merkle_roots);
        }
        (shares_proofs_dzk,dzk_broadcast_polys,hashes)
    }

    pub async fn init_pubrec_quad(&mut self, instance_id: usize, party: Replica){
        log::info!("Received request to publicly reconstruct secrets in instance {} with quadratic cost", instance_id);
        if !self.acss_ab_state.contains_key(&instance_id){
            log::error!("No ACSS AB state found for instance {}", instance_id);
            return;
        }
        let acss_ab_state = self.acss_ab_state.get(&instance_id).unwrap();
        if !acss_ab_state.shares.contains_key(&party){
            log::error!("No shares found for party {:?} in instance {}", party, instance_id);
            return;
        }
        let acss_all_shares = acss_ab_state.shares.get(&party).unwrap();
        let shares: Vec<LargeFieldSer> = acss_all_shares.evaluations.0.clone();

        let nonce_shares = acss_all_shares.evaluations.1.clone();
        let mps = acss_all_shares.evaluations.2.clone();

        let blinding_shares = acss_all_shares.blinding_evaluations.0.clone();
        let blinding_nonce_shares = acss_all_shares.blinding_evaluations.1.clone();
        let blinding_mps = acss_all_shares.blinding_evaluations.2.clone();

        let dzk_proofs = acss_all_shares.dzk_iters.clone();
        //let evaluation_points = self.gen_evaluation_points();
        
        let acss_ske_msg = AcssSKEShares{
            evaluations: (shares, nonce_shares, mps),
            blinding_evaluations: (blinding_shares, blinding_nonce_shares, blinding_mps),
            dzk_iters: dzk_proofs,
            rep: party,
        };

        self.broadcast(ProtMsg::PubRec(instance_id, acss_ske_msg)).await;
    }

    pub async fn init_pubrec(&mut self, instance_id: usize, party: Replica){
        log::info!("Received request to publicly reconstruct secrets in instance {}", instance_id);
        if !self.acss_ab_state.contains_key(&instance_id){
            log::error!("No ACSS AB state found for instance {}", instance_id);
            return;
        }
        let acss_ab_state = self.acss_ab_state.get(&instance_id).unwrap();
        if !acss_ab_state.shares.contains_key(&party){
            log::error!("No shares found for party {:?} in instance {}", party, instance_id);
            return;
        }
        let acss_all_shares = acss_ab_state.shares.get(&party).unwrap();
        let shares: Vec<LargeField> = acss_all_shares.evaluations.0.clone().into_iter().map(
            |x| LargeField::from_bytes_be(x.as_slice()).unwrap()
        ).collect();

        let nonce_shares = acss_all_shares.evaluations.1.clone();
        let mps = acss_all_shares.evaluations.2.clone();

        let blinding_shares = acss_all_shares.blinding_evaluations.0.clone();
        let blinding_nonce_shares = acss_all_shares.blinding_evaluations.1.clone();
        let blinding_mps = acss_all_shares.blinding_evaluations.2.clone();

        let dzk_proofs = acss_all_shares.dzk_iters.clone();
        let evaluation_points = self.gen_evaluation_points();
        
        let shares_grouped = Self::group_points_for_public_reconstruction(
            shares, 
            evaluation_points, 
            self.num_faults+1
        );
        for rep in 0..self.num_nodes{
            let share_vec: Vec<LargeFieldSer> = shares_grouped[rep].clone().into_iter().map(|el| el.to_bytes_be()).collect();
            let blinding_share = blinding_shares[rep].clone();
            let nonce_share = nonce_shares[rep].clone();
            let blinding_nonce_share = blinding_nonce_shares[rep].clone();
            
            let merkle_proof = mps[rep].clone();
            let blinding_mp = blinding_mps[rep].clone();

            let acss_ske_msg = AcssSKEShares{
                evaluations: (share_vec, vec![nonce_share], vec![merkle_proof]),
                blinding_evaluations: (vec![blinding_share], vec![blinding_nonce_share], vec![blinding_mp]),
                dzk_iters: vec![dzk_proofs[rep].clone()],
                rep: party,
            };

            let prot_msg = ProtMsg::PubRecL1(instance_id,acss_ske_msg);
            let secret_key = self.sec_key_map.get(&rep).unwrap().clone();
            let wrapper_msg = WrapperMsg::new(prot_msg, self.myid, secret_key.as_slice());

            let cancel_handler = self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }

    }

    pub async fn process_pub_rec_l1_msg(&mut self, instance_id: usize, acss_msg: AcssSKEShares, share_sender: Replica){
        log::info!("Received PubRecL1 message for instance {} of party {}, shares received from party {}", instance_id, acss_msg.rep, share_sender);
        if !self.acss_ab_state.contains_key(&instance_id){
            let acss_ab_state = ACSSABState::new();
            self.acss_ab_state.insert(instance_id, acss_ab_state);
        }

        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        
        if acss_ab_state.public_reconstruction_l1_status.contains(&acss_msg.rep){
            log::info!("Public reconstruction l1 already complete for party {} in instance {}", acss_msg.rep, instance_id);
            return;
        }
        if !acss_ab_state.commitments.contains_key(&acss_msg.rep){
            log::error!("No commitments found for party {} in instance {}", acss_msg.rep, instance_id);
            return;
        }
        // Generate and verify commitments
        let va_commitment = acss_ab_state.commitments.get(&acss_msg.rep).unwrap();

        let shares = acss_msg.evaluations.0.clone();
        let nonce_share = acss_msg.evaluations.1[0].clone();
        let share_mp = acss_msg.evaluations.2[0].clone();

        let mut appended_vec = vec![];
        for share in shares{
            appended_vec.extend(share);
        }
        appended_vec.extend(nonce_share);
        
        let commitment = do_hash(appended_vec.as_slice());
        if !share_mp.validate(&self.hash_context) ||
            share_mp.item() != commitment || 
            share_mp.root() != va_commitment.column_roots[self.myid].clone(){
                log::error!("Commitment verification failed because root: {:?}, actual roots: {:?}, commitment: {:?}, proof_commitment: {:?}", 
                share_mp.root(), 
                va_commitment.column_roots.clone(),
                commitment,
                share_mp.item()
            );
            return;
        }

        log::info!("Successfully verified commitment in PubRecL1 message for instance {} of party {}, shares received from party {}", instance_id, acss_msg.rep, share_sender);

        let blinding_share = acss_msg.blinding_evaluations.0[0].clone();
        let blinding_nonce_share = acss_msg.blinding_evaluations.1[0].clone();
        let blinding_mp = acss_msg.blinding_evaluations.2[0].clone();

        // Verify blinding share commitment

        let mut appended_vec = vec![];
        appended_vec.extend(blinding_share);
        appended_vec.extend(blinding_nonce_share);

        let blinding_commitment = do_hash(appended_vec.as_slice());

        if !blinding_mp.validate(&self.hash_context) ||
            blinding_mp.item() != blinding_commitment || 
            blinding_mp.root() != va_commitment.blinding_column_roots[self.myid].clone(){
                log::error!("Blinding commitment verification failed because root: {:?}, actual roots: {:?}, commitment: {:?}, proof_commitment: {:?}", 
                blinding_mp.root(), 
                va_commitment.blinding_column_roots.clone(),
                blinding_commitment,
                blinding_mp.item()
            );
            return;
        }
        
        log::info!("Successfully verified blinding commitment in PubRecL1 message for instance {} of party {}, shares received from party {}", instance_id, acss_msg.rep, share_sender);

        // Verify shares first
        let shares: Vec<LargeField> = acss_msg.evaluations.0.clone().into_iter().map(|el| LargeField::from_bytes_be(el.as_slice()).unwrap()).collect();
        let blinding_share = LargeField::from_bytes_be(acss_msg.blinding_evaluations.0[0].as_slice()).unwrap();
        let root_comm_fe = LargeField::from_bytes_be(self.hash_context.hash_two(share_mp.root(), blinding_mp.root()).as_slice()).unwrap();

        let share_agg_point = Self::aggregate_points_for_dzk(
            vec![shares.clone()], 
            vec![blinding_share], 
            vec![root_comm_fe]
        )[0].clone();
        let dzk_proof = acss_msg.dzk_iters[0].clone();
        let status = self.folding_dzk_context.verify_dzk_proof(
            dzk_proof, 
            va_commitment.dzk_roots[self.myid].clone(), 
            va_commitment.polys[self.myid].clone(), 
            root_comm_fe.to_bytes_be(), 
            (share_agg_point-blinding_share).div(root_comm_fe), 
            blinding_share, 
            share_sender+1
        );
        if !status{
            log::error!("Dzk proof verification failed for instance {} of party {}, shares received from party {}", instance_id, acss_msg.rep, share_sender);
            return;
        }
        log::info!("Successfully verified dzk proof in PubRecL1 message for instance {} of party {}, shares received from party {}", instance_id, acss_msg.rep, share_sender);
        
        if !acss_ab_state.public_reconstruction_l1_shares.contains_key(&acss_msg.rep){
            acss_ab_state.public_reconstruction_l1_shares.insert(acss_msg.rep, HashMap::default());
        }

        if !acss_ab_state.public_reconstruction_l2_shares.contains_key(&acss_msg.rep){
            acss_ab_state.public_reconstruction_l2_shares.insert(acss_msg.rep, HashMap::default());
        }

        let tot_share_count = shares.len();
        let share_map = acss_ab_state.public_reconstruction_l1_shares.get_mut(&acss_msg.rep).unwrap();
        share_map.insert(share_sender, shares);

        if share_map.len() == self.num_faults + 1{
            // Reconstruct the secrets
            log::info!("t+1 shares received for share polynomials of party {}", acss_msg.rep);
            let mut eval_points = Vec::new();
            let mut shares_indexed: Vec<Vec<LargeField>> = Vec::new();
            for _ in 0..tot_share_count{
                shares_indexed.push(Vec::new());
            }
            for party in 0..self.num_nodes{
                if share_map.contains_key(&party){
                    eval_points.push(LargeField::from((party+1) as u64));
                    let shares_party = share_map.get(&party).unwrap();
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

            let l2_shares : Vec<LargeFieldSer> = shares_indexed.into_par_iter().map(|evals|{
                let coefficients = matrix_vector_multiply(&inverse_vandermonde, &evals);
                return Polynomial::new(&coefficients).evaluate(&secret_evaluation_point).to_bytes_be();
            }).collect();

            acss_ab_state.public_reconstruction_l1_status.insert(acss_msg.rep);
            log::info!("Successfully interpolated shares for l2 public reconstruction for instance id {} and source party {}", instance_id, acss_msg.rep);
            // broadcast these shares
            let prot_msg = ProtMsg::PubRecL2(instance_id, acss_msg.rep, l2_shares);
            self.broadcast(prot_msg).await;
        }
    }

    pub async fn process_pub_rec_l2_msg(&mut self, instance_id: usize, source_party: Replica, shares: Vec<LargeFieldSer>, share_sender: Replica){
        log::info!("Received PubRecL2 message for instance {} of party {}, shares received from party {} with shares.len() {}", instance_id, source_party, share_sender, shares.len());
        if !self.acss_ab_state.contains_key(&instance_id){
            let acss_ab_state = ACSSABState::new();
            self.acss_ab_state.insert(instance_id, acss_ab_state);
        }
        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();

        if acss_ab_state.public_reconstruction_l2_status.contains(&source_party){
            log::info!("Public reconstruction l2 already complete for party {} in instance {}", source_party, instance_id);
            return;
        }
        if !acss_ab_state.public_reconstruction_l2_shares.contains_key(&source_party){
            acss_ab_state.public_reconstruction_l2_shares.insert(source_party, HashMap::default());
        }

        let share_map = acss_ab_state.public_reconstruction_l2_shares.get_mut(&source_party).unwrap();
        let shares_deser: Vec<LargeField> = shares.into_iter().map(|el| LargeField::from_bytes_be(el.as_slice()).unwrap()).collect();
        
        let tot_sharings_len = shares_deser.len();
        share_map.insert(share_sender, shares_deser);

        // TODO: Add Reed-Solomon Error Correction here
        if share_map.len() == self.num_faults+1{
            log::info!("L2 Sharing: t+1 shares received for share polynomials of party {} in instance id {}", source_party, instance_id);
            let mut evaluation_points = Vec::new();
            let mut shares_indexed: Vec<Vec<LargeField>> = Vec::new();
            for _ in 0..tot_sharings_len{
                shares_indexed.push(Vec::new());
            }
            for party in 0..self.num_nodes{
                if share_map.contains_key(&party){
                    evaluation_points.push(LargeField::from((party+1) as u64));
                    let shares_party = share_map.get(&party).unwrap();
                    for (index, share) in shares_party.into_iter().enumerate(){
                        shares_indexed[index].push(share.clone());
                    }
                }
            }

            // Interpolate polynomials
            // Generate vandermonde matrix
            let vandermonde = vandermonde_matrix(evaluation_points.clone());
            let inverse_vandermonde = inverse_vandermonde(vandermonde);

            let secrets : Vec<LargeField> = shares_indexed.into_par_iter().map(|evals|{
                let coefficients = matrix_vector_multiply(&inverse_vandermonde, &evals);
                return Polynomial::new(&coefficients).coefficients;
            }).flatten().collect();

            log::info!("Successfully interpolated secrets after l2 public reconstruction for instance id {} and source party {} with secrets_len: {}", instance_id, source_party, secrets.len());

            acss_ab_state.public_reconstruction_l2_status.insert(source_party);
            let _status = self.out_pub_rec_out.send((instance_id, source_party, secrets)).await;
        }
    }
}