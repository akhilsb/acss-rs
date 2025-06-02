use std::ops::Div;

use crate::{Context, msg::AcssSKEShares};
use crypto::{hash::{do_hash, Hash}, aes_hash::{MerkleTree, Proof}, encrypt};
use lambdaworks_math::{unsigned_integer::element::UnsignedInteger, traits::ByteConversion};
use consensus::{LargeField, LargeFieldSer, generate_evaluation_points_fft, generate_evaluation_points, generate_evaluation_points_opt, sample_polynomials_from_prf, rand_field_element, VACommitment};
use rayon::prelude::{ParallelIterator, IndexedParallelIterator, IntoParallelIterator};
use types::Replica;

use super::ACSSABState;

impl Context{
    pub async fn init_symmetric_key_setup(&mut self){
        if self.symmetric_keys_avid.keys_from_me.is_empty(){
            log::info!("Initializing symmetric keys and sharing them through ASKS in ACSS instance");
            // First sample $n$ symmetric keys
            let mut symm_keys = Vec::new();
            for i in 0..self.num_nodes{
                let key = rand_field_element();
                symm_keys.push(key.clone());
                self.symmetric_keys_avid.keys_from_me.insert(i, key.to_bytes_be().to_vec());
            }
            log::info!("Symmetric keys generated: {:?}", symm_keys);
            // Now share these keys through ASKS
            let _status = self.asks_inp_channel.send((
                1,
                self.num_nodes, 
                false, 
                false, 
                Some(symm_keys), 
                None
            )).await;
            if _status.is_err(){
                log::error!("Failed to send ASKS init request");
                return;
            }
        }
    }

    pub async fn init_symmetric_key_reconstruction(&mut self, party: Replica){
        log::info!("Received ASKS termination for secrets initiated by party {}", party);
        log::info!("Reconstructing symmetric keys in ASKS from party {}", party);
        if !self.symmetric_keys_avid.term_asks_sharing.contains(&party){
            self.symmetric_keys_avid.term_asks_sharing.insert(party);
            // Initiate reconstruction

            let _status = self.asks_inp_channel.send((
                1,
                self.num_nodes, 
                false, 
                true, 
                None, 
                Some(party)
            )).await;
            if _status.is_err(){
                log::error!("Failed to send ASKS termination request for symmetric keys");
                return;
            }
        }
    }

    pub async fn process_symmetric_key_reconstruction(&mut self, party: Replica, secret: Vec<LargeField>){
        log::info!("Received reconstructed symmetric keys from party {} {:?}", party, secret);
        if !self.symmetric_keys_avid.keys_to_me.contains_key(&party){
            let secret = secret[0].clone().to_bytes_be();
            self.symmetric_keys_avid.keys_to_me.insert(party, secret.to_vec());
            // Now that the key is available, we can use it to decrypt the secrets initialized by the party {party}
            self.decrypt_shares_all_instances(party).await;
        } else {
            log::warn!("Reconstructed keys from party {} already exists", party);
        }
    }

    pub fn gen_evaluation_points(&self)-> Vec<LargeField>{
        let evaluation_points;
        if !self.use_fft{
            evaluation_points = (1..self.num_nodes+1).into_iter().map(|x| LargeField::from(x as u64)).collect();
        }
        else{
            evaluation_points = self.roots_of_unity.clone();
        }
        evaluation_points
    }

    pub async fn init_acss_ab(&mut self, secrets: Vec<LargeField>, instance_id: usize){
        // Init ASKS first
        self.init_symmetric_key_setup().await;
        if !self.acss_ab_state.contains_key(&instance_id){
            let acss_ab_state = ACSSABState::new();
            self.acss_ab_state.insert(instance_id, acss_ab_state);
        }
        // Number of secrets must be a multiple of self.num_faults+1
        let mut secrets = secrets;
        if secrets.len() % (self.num_faults + 1) != 0 {
            let rem_secrets = (self.num_faults+1) - (secrets.len()%(self.num_faults+1));
            for _ in 0..rem_secrets {
                secrets.push(rand_field_element());
            }
        }

        let tot_sharings = secrets.len();
        let mut handles = Vec::new();
        let mut _indices;
        let mut evaluations;
        let nonce_evaluations;
        let mut coefficients;
        
        let blinding_poly_evaluations;
        let blinding_poly_coefficients;
        let nonce_blinding_poly_evaluations;
        
        if !self.use_fft{
            // Generate evaluations right here
            let evaluations_prf = sample_polynomials_from_prf(
                secrets, 
                self.symmetric_keys_avid.keys_from_me.clone(), 
                self.num_faults, 
                false, 
                1u8
            );
            let evaluation_prf_chunks: Vec<Vec<Vec<LargeField>>> = evaluations_prf.chunks(evaluations_prf.len()/self.num_threads).map(|el| el.to_vec()).collect();
            for eval_prfs in evaluation_prf_chunks{
                let handle = tokio::spawn(
                    generate_evaluation_points_opt(
                        eval_prfs,
                        self.num_faults,
                        self.num_nodes,
                    )
                );
                handles.push(handle);
            }

            evaluations = Vec::new();
            coefficients = Vec::new();
            _indices = Vec::new();
            for party in 0..self.num_nodes{
                _indices.push(LargeField::new(UnsignedInteger::from((party+1) as u64)));
            }
                    
            for handle in handles{
                let (
                    evaluations_batch, 
                    coefficients_batch) = handle.await.unwrap();
                evaluations.extend(evaluations_batch);
                coefficients.extend(coefficients_batch);
            }
            
            // Generate nonce evaluations
            let nonce_secrets:Vec<LargeField> = (0..self.num_nodes).into_iter().map(|_| rand_field_element()).collect();
            let evaluations_nonce_prf = sample_polynomials_from_prf(
                nonce_secrets,
                self.symmetric_keys_avid.keys_from_me.clone(), 
                self.num_faults, 
                true, 
                1u8
            );
            let (nonce_evaluations_ret,_nonce_coefficients) = generate_evaluation_points(
                evaluations_nonce_prf,
                self.num_faults,
                self.num_nodes
            ).await;
            nonce_evaluations = nonce_evaluations_ret;

            // Generate the DZK proofs and commitments and utilize RBC to broadcast these proofs
            
            // Sample blinding polynomials
            let blinding_secrets: Vec<LargeField> = (0..self.num_nodes).into_iter().map(|_| rand_field_element()).collect();
            let blinding_prf = sample_polynomials_from_prf(
                blinding_secrets, 
                self.symmetric_keys_avid.keys_from_me.clone(), 
                self.num_faults, 
                true, 
                2u8
            );
            let (blinding_poly_evaluations_vec, blinding_poly_coefficients_vec) = generate_evaluation_points(
                blinding_prf,
                self.num_faults,
                self.num_nodes
            ).await;

            blinding_poly_evaluations = blinding_poly_evaluations_vec;
            blinding_poly_coefficients = blinding_poly_coefficients_vec;

            let blinding_nonce_secrets: Vec<LargeField> = (0..self.num_nodes).into_iter().map(|_| rand_field_element()).collect();
            let blinding_nonce_prf = sample_polynomials_from_prf(
                blinding_nonce_secrets, 
                self.symmetric_keys_avid.keys_from_me.clone(), 
                self.num_faults, 
                true, 
                3u8
            );

            let (nonce_blinding_poly_evaluations_vec, _nonce_blinding_poly_coefficients_vec) = generate_evaluation_points(
                blinding_nonce_prf,
                self.num_faults,
                self.num_nodes,
            ).await;
            nonce_blinding_poly_evaluations = nonce_blinding_poly_evaluations_vec;
        }
        else{
            // Parallelize the generation of evaluation points
            let mut secret_shards: Vec<Vec<LargeField>> = secrets.chunks(self.num_threads).map(|el_vec| el_vec.to_vec()).collect();
            for shard in secret_shards.iter_mut(){
                let secrets = shard.clone();
                let handle = tokio::spawn(
                    generate_evaluation_points_fft(
                        secrets,
                        self.num_faults-1,
                        self.num_nodes
                    )
                );
                handles.push(handle);
            }
            evaluations = Vec::new();
            coefficients = Vec::new();
            _indices = self.roots_of_unity.clone();
            for handle in handles{
                let (
                    evaluations_batch, 
                    coefficients_batch) = handle.await.unwrap();
                evaluations.extend(evaluations_batch);
                coefficients.extend(coefficients_batch);
            }

            // Generate nonce evaluations
            let nonce_secrets:Vec<LargeField> = (0..self.num_nodes).into_iter().map(|_| rand_field_element()).collect();
            let (nonce_evaluations_ret,_nonce_coefficients) = generate_evaluation_points_fft(
                nonce_secrets,
                self.num_faults-1,
                self.num_nodes,
            ).await;
            nonce_evaluations = nonce_evaluations_ret;

            // Generate blinding polynomials
            let blinding_secrets:Vec<LargeField> = (0..self.num_nodes).into_iter().map(|_| rand_field_element()).collect();
            let (blinding_poly_evaluations_vec, blinding_poly_coefficients_vec) = generate_evaluation_points_fft(
                blinding_secrets, 
                self.num_faults-1, 
                self.num_nodes
            ).await;
            blinding_poly_evaluations = blinding_poly_evaluations_vec;
            blinding_poly_coefficients = blinding_poly_coefficients_vec;

            // Generate blinding nonce polynomials
            let blinding_nonce_secrets: Vec<LargeField> = (0..self.num_nodes).into_iter().map(|_| rand_field_element()).collect();
            let (nonce_blinding_evaluations_vec, _nonce_coefficients_vec) = generate_evaluation_points_fft(
                blinding_nonce_secrets, 
                self.num_faults-1, 
                self.num_nodes
            ).await;
            nonce_blinding_poly_evaluations = nonce_blinding_evaluations_vec;
        }
        
        let evaluation_points = self.gen_evaluation_points();
        // Group polynomials into groups of t+1
        let grouped_polynomials_dzk_proofs = Self::group_polynomials_for_public_reconstruction(
            coefficients, 
            evaluation_points.clone(), 
            self.num_faults+1,
        );

        // Generate commitments
        let merkle_tree_vector: Vec<MerkleTree> = Self::compute_commitments(
            grouped_polynomials_dzk_proofs.clone(), 
            evaluation_points.clone(), 
            nonce_evaluations.clone(), 
            &self.hash_context
        );

        let roots: Vec<Hash> = merkle_tree_vector.iter().map(|tree| tree.root()).collect();

        let blinding_merkle_trees: Vec<MerkleTree> = blinding_poly_coefficients.clone().into_par_iter().zip(nonce_blinding_poly_evaluations.clone().into_par_iter()).map(|(b_poly, b_nonce_evals)|{
            let b_poly_evaluations: Vec<LargeFieldSer> = evaluation_points.iter().map(|eval_point| 
                b_poly.evaluate(eval_point).clone().to_bytes_be()
            ).collect();
            let b_hashes: Vec<Hash> = b_poly_evaluations.into_iter().zip(b_nonce_evals.into_iter()).map(|(b_poly_eval, b_nonce_eval)|{
                let mut appended_vec = vec![];
                appended_vec.extend(b_poly_eval);
                appended_vec.extend(b_nonce_eval.to_bytes_be());
                return do_hash(appended_vec.as_slice());
            }).collect();
            MerkleTree::new(b_hashes, &self.hash_context)
        }).collect();

        let blinding_roots = blinding_merkle_trees.iter().map(|mt| mt.root()).collect::<Vec<Hash>>();

        let root_comm_fe: Vec<LargeField> = roots.iter().zip(blinding_roots.iter()).map(|(root, b_root)|{
            //let root = mt.root();
            let root_combined = self.hash_context.hash_two(root.clone(), b_root.clone());
            return LargeField::from_bytes_be(root_combined.as_slice()).unwrap();
        }).collect();

        // Aggregated polynomials
        let agg_polys = Self::aggregate_polynomials_for_dzk(
            grouped_polynomials_dzk_proofs, 
            blinding_poly_coefficients, 
            root_comm_fe.clone()
        );

        // Initialize DZK procedure
        let (dzk_proofs, dzk_broadcast_polys, commitment_hashes) = self.compute_dzk_proofs(
            agg_polys, 
            root_comm_fe.clone()
        );

        let va_comm: VACommitment = VACommitment{
            instance_id: instance_id,
            column_roots: roots.clone(),
            blinding_column_roots: blinding_roots.clone(),
            dzk_roots: commitment_hashes,
            polys: dzk_broadcast_polys,
            tot_shares: tot_sharings
        };
        
        // Transform the shares to party wise shares
        let mut shares_party_wise: Vec<Vec<LargeFieldSer>> = Vec::new();
        
        let mut nonce_shares_party_wise: Vec<Vec<LargeFieldSer>>  = Vec::new();
        let mut blinding_shares_party_wise: Vec<Vec<LargeFieldSer>> = Vec::new();
        let mut blinding_nonce_shares_party_wise: Vec<Vec<LargeFieldSer>> = Vec::new();
        
        let mut merkle_proofs_party_wise: Vec<Vec<Proof>> = Vec::new();
        let mut blinding_merkle_proofs_party_wise: Vec<Vec<Proof>> = Vec::new();

        for i in 0..self.num_nodes{
            let mut party_shares = Vec::new();
            for j in 0..evaluations.len(){
                party_shares.push(evaluations[j][i].clone().to_bytes_be());
            }
            let mut party_nonce_shares = Vec::new();
            let mut party_blinding_shares = Vec::new();
            let mut party_blinding_nonce_shares = Vec::new();

            for j in 0..nonce_evaluations.len(){
                party_nonce_shares.push(nonce_evaluations[j][i].clone().to_bytes_be());
                party_blinding_shares.push(blinding_poly_evaluations[j][i].clone().to_bytes_be());
                party_blinding_nonce_shares.push(nonce_blinding_poly_evaluations[j][i].clone().to_bytes_be());
            }

            let mut party_merkle_proofs = Vec::new();
            let mut party_blinding_merkle_proofs = Vec::new();

            for j in 0..merkle_tree_vector.len(){
                party_merkle_proofs.push(merkle_tree_vector[j].gen_proof(i));
                party_blinding_merkle_proofs.push(blinding_merkle_trees[j].gen_proof(i));
            }

            shares_party_wise.push(party_shares);
            nonce_shares_party_wise.push(party_nonce_shares);
            blinding_shares_party_wise.push(party_blinding_shares);
            blinding_nonce_shares_party_wise.push(party_blinding_nonce_shares);

            merkle_proofs_party_wise.push(party_merkle_proofs);
            blinding_merkle_proofs_party_wise.push(party_blinding_merkle_proofs);
        }


        let mut shares: Vec<(Replica,Option<Vec<u8>>)> = Vec::new();
        for rep in 0..self.num_nodes{
            // prepare shares
            // even need to encrypt shares
            
            let shares_party = shares_party_wise[rep].clone();
            let nonce_shares = nonce_shares_party_wise[rep].clone();
            let blinding_shares = blinding_shares_party_wise[rep].clone();
            let nonce_blinding_poly_shares = blinding_nonce_shares_party_wise[rep].clone();

            let merkle_proofs = merkle_proofs_party_wise[rep].clone();
            let blinding_merkle_proofs = blinding_merkle_proofs_party_wise[rep].clone();
            let shares_struct;
            if (self.use_fft) || (!self.use_fft && rep >= self.num_faults){
                shares_struct = AcssSKEShares{
                    evaluations: (shares_party, nonce_shares, merkle_proofs),
                    blinding_evaluations: (blinding_shares, nonce_blinding_poly_shares, blinding_merkle_proofs),
                    dzk_iters: dzk_proofs[rep].clone(),
                    rep: rep
                };   
            }
            else{
                shares_struct = AcssSKEShares{
                    evaluations: (vec![], vec![], merkle_proofs),
                    blinding_evaluations: (vec![], vec![], blinding_merkle_proofs),
                    dzk_iters: dzk_proofs[rep].clone(),
                    rep: rep
                }; 
            }

            let shares_ser = bincode::serialize(&shares_struct).unwrap();
            
            let sec_key = self.symmetric_keys_avid.keys_from_me.get(&rep).unwrap().clone();
            let enc_shares = encrypt(sec_key.as_slice(), shares_ser);
            
            let ser_enc_msg = bincode::serialize(&(instance_id,enc_shares)).unwrap();
            shares.push((rep, Some(ser_enc_msg)));
        }

        let ser_broadcast_vec: Vec<u8> = bincode::serialize(&va_comm).unwrap();
        // Reliably broadcast this vector
        let _rbc_status = self.inp_ctrbc.send(ser_broadcast_vec).await;
        
        // Invoke AVID on vectors of shares
        // Use AVID to send the shares to parties
        let _avid_status = self.inp_avid_channel.send(shares).await;
    }

    pub async fn verify_shares(&mut self, sender: Replica, instance_id: usize){
        if !self.acss_ab_state.contains_key(&instance_id){
            let acss_state = ACSSABState::new();
            self.acss_ab_state.insert(instance_id, acss_state);
        }

        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        if acss_ab_state.verification_status.contains_key(&sender){
            // Already verified status, abandon sharing
            return;
        }

        if !acss_ab_state.commitments.contains_key(&sender) || !acss_ab_state.shares.contains_key(&sender){
            // AVID and CTRBC did not yet terminate
            return;
        }

        // Share verification first
        let shares_full = acss_ab_state.shares.get(&sender).unwrap().clone();
        let va_commitment = acss_ab_state.commitments.get(&sender).unwrap().clone();
        
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
            shares, 
            evaluation_points.clone(), 
            self.num_faults+1
        );

        let root_comm_fe: Vec<LargeField> = roots_from_proofs.iter().zip(blinding_merkle_roots.iter()).map(|(root, b_root)|{
            //let root = mt.root();
            let root_combined = self.hash_context.hash_two(root.clone(), b_root.clone());
            return LargeField::from_bytes_be(root_combined.as_slice()).unwrap();
        }).collect();

        let dzk_aggregated_points = Self::aggregate_points_for_dzk(
            grouped_points, 
            blinding_shares.clone(), 
            root_comm_fe
        );

        for index in 0..self.num_nodes{
            let dzk_proof = shares_full.dzk_iters[index].clone();
            let dzk_roots = va_commitment.dzk_roots[index].clone();
            let dzk_polynomial = va_commitment.polys[index].clone();
            
            let share_merkle_root = va_commitment.column_roots[index].clone();
            let blinding_merkle_root = va_commitment.blinding_column_roots[index].clone();
            let combined_root = self.hash_context.hash_two(share_merkle_root, blinding_merkle_root);
            let root_fe = LargeField::from_bytes_be(combined_root.as_slice()).unwrap();

            let share_point = dzk_aggregated_points[index].clone();
            let blinding_share_point = blinding_shares[index].clone();
            
            //log::info!()
            let status = self.folding_dzk_context.verify_dzk_proof(
                dzk_proof, 
                dzk_roots, 
                dzk_polynomial, 
                combined_root, 
                (share_point-blinding_share_point).div(root_fe), 
                blinding_share_point, 
                self.myid+1
            );

            if !status{
                log::error!("DZK proof verification failed for instance {} from sender {} at index {} with blinding_share_point {}, agg_share_point: {}", instance_id, sender, index, blinding_share_point, share_point);
                return;
            }
        }

        
        log::info!("Share from {} verified", sender);
        acss_ab_state.verification_status.insert(sender,true);
        // Start reliable agreement
        let _status = self.inp_ra_channel.send((sender,1,instance_id)).await;
        self.check_termination(sender, instance_id).await;
    }
}