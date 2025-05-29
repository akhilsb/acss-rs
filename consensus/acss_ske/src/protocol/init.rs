use std::{ops::{Mul, Add, Sub}};

use crate::Context;
use crypto::{hash::{do_hash, Hash}, aes_hash::MerkleTree, encrypt};
use lambdaworks_math::{unsigned_integer::element::UnsignedInteger, polynomial::Polynomial, traits::ByteConversion};
use consensus::{LargeField, LargeFieldSer, generate_evaluation_points_fft, generate_evaluation_points, generate_evaluation_points_opt, sample_polynomials_from_prf, rand_field_element};
use rand::random;
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
        } else {
            log::warn!("Reconstructed keys from party {} already exists", party);
        }
    }

    pub async fn init_acss_ab(&mut self, secrets: Vec<LargeField>, instance_id: usize){
        // Init ASKS first
        self.init_symmetric_key_setup().await;
        if !self.acss_ab_state.contains_key(&instance_id){
            let acss_ab_state = ACSSABState::new();
            self.acss_ab_state.insert(instance_id, acss_ab_state);
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
            let evaluations_nonce_prf = sample_polynomials_from_prf(
                vec![LargeField::new(UnsignedInteger{
                    limbs: random()
                })], 
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
            nonce_evaluations = nonce_evaluations_ret[0].clone();

            // Generate the DZK proofs and commitments and utilize RBC to broadcast these proofs
            // Sample blinding polynomial
            let blinding_prf = sample_polynomials_from_prf(
                vec![LargeField::new(UnsignedInteger{
                    limbs: random()
                })], 
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

            blinding_poly_evaluations = blinding_poly_evaluations_vec[0].clone();
            blinding_poly_coefficients = blinding_poly_coefficients_vec[0].clone();

            let blinding_nonce_prf = sample_polynomials_from_prf(
                vec![LargeField::new(UnsignedInteger{
                    limbs: random()
                })], 
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
            nonce_blinding_poly_evaluations = nonce_blinding_poly_evaluations_vec[0].clone();
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
            let (nonce_evaluations_ret,_nonce_coefficients) = generate_evaluation_points_fft(
                vec![LargeField::new(UnsignedInteger{
                    limbs: random()
                })],
                self.num_faults-1,
                self.num_nodes,
            ).await;
            nonce_evaluations = nonce_evaluations_ret[0].clone();

            let (blinding_poly_evaluations_vec, blinding_poly_coefficients_vec) = generate_evaluation_points_fft(vec![LargeField::new(UnsignedInteger{
                    limbs: random()
                })], 
                self.num_faults-1, 
                self.num_nodes
            ).await;
            blinding_poly_evaluations = blinding_poly_evaluations_vec[0].clone();
            blinding_poly_coefficients = blinding_poly_coefficients_vec[0].clone();

            let (nonce_blinding_evaluations_vec, _nonce_coefficients_vec) = generate_evaluation_points_fft(vec![LargeField::new(UnsignedInteger{
                    limbs: random()
                })]
                , 
                self.num_faults-1, 
                self.num_nodes
            ).await;
            nonce_blinding_poly_evaluations = nonce_blinding_evaluations_vec[0].clone();
        }
        // let poly_status = check_if_all_points_lie_on_degree_x_polynomial(_indices, evaluations.clone(), self.num_faults+1);
        // assert!(poly_status.0);
        // Transform the shares to element wise shares
        let mut party_wise_shares: Vec<Vec<LargeFieldSer>> = Vec::new();
        let mut party_appended_shares: Vec<Vec<u8>> = Vec::new();
        for i in 0..self.num_nodes{
            let mut party_shares = Vec::new();
            let mut appended_share = Vec::new();
            for j in 0..evaluations.len(){
                party_shares.push(evaluations[j][i].clone().to_bytes_be());
                appended_share.extend(evaluations[j][i].clone().to_bytes_be());
            }
            party_wise_shares.push(party_shares);

            // Append nonce shares to shares for generating commitment
            appended_share.extend(nonce_evaluations[i].clone().to_bytes_be());
            party_appended_shares.push(appended_share);
        }

        // Generate Commitments here
        // There should be $n$ commitments overall
        let commitments: Vec<Hash> = party_appended_shares.into_iter().map(|share| {
            do_hash(&share)
        }).collect();

        let merkle_tree = MerkleTree::new(commitments.clone(), &self.hash_context);
        let share_root_comm = merkle_tree.root();

        let mut blinding_commitments = Vec::new();
        for i in 0..self.num_nodes{
            blinding_commitments.push(self.hash_context.hash_two( blinding_poly_evaluations[i].clone().to_bytes_be(), nonce_blinding_poly_evaluations[i].clone().to_bytes_be()));
        }

        let blinding_mt_root = MerkleTree::new(blinding_commitments.clone(), &self.hash_context).root();
        // Generate DZK coefficients
        
        let root_comm = self.hash_context.hash_two(share_root_comm, blinding_mt_root);
        // Convert root commitment to field element
        let root_comm_fe = LargeField::from_bytes_be(&root_comm).unwrap();
        let mut root_comm_fe_mul = root_comm_fe.clone();
        let mut dzk_coeffs = blinding_poly_coefficients.clone();
        for poly in coefficients.into_iter(){
            dzk_coeffs = dzk_coeffs.add(poly.mul(root_comm_fe_mul));
            root_comm_fe_mul = root_comm_fe_mul.mul(root_comm_fe);
        }

        // Serialize shares,commitments, and DZK polynomials
        let ser_dzk_coeffs: Vec<[u8;32]> = dzk_coeffs.coefficients.into_iter().map(|el| el.to_bytes_be()).collect();
        let broadcast_vec = (commitments, blinding_commitments, ser_dzk_coeffs, tot_sharings);
        let serialized_broadcase_vec = (instance_id, broadcast_vec);
        let ser_vec = bincode::serialize(&serialized_broadcase_vec).unwrap();

        let mut shares: Vec<(Replica,Option<Vec<u8>>)> = Vec::new();
        for rep in 0..self.num_nodes{
            // prepare shares
            // even need to encrypt shares
            if (self.use_fft) || (!self.use_fft && rep >= self.num_faults){
                let shares_party = party_wise_shares[rep].clone();
                let nonce_share = nonce_evaluations[rep].clone().to_bytes_be();
                let blinding_nonce_share = nonce_blinding_poly_evaluations[rep].clone().to_bytes_be();
                
                let shares_full = (shares_party, nonce_share, blinding_nonce_share);
                let serialized_shares = (instance_id, shares_full);
                let shares_ser = bincode::serialize(&serialized_shares).unwrap();

                let sec_key = self.symmetric_keys_avid.keys_from_me.get(&rep).unwrap().clone();
                let enc_shares = encrypt(sec_key.as_slice(), shares_ser);
                shares.push((rep, Some(enc_shares)));
            }
        }
        // Reliably broadcast this vector
        let _rbc_status = self.inp_ctrbc.send(ser_vec).await;
        
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

        let shares_full = acss_ab_state.shares.get(&sender).unwrap().clone();
        let shares = shares_full.0;
        let nonce_share = shares_full.1;
        let blinding_nonce_share = shares_full.2;

        let commitments_full = acss_ab_state.commitments.get(&sender).unwrap().clone();
        let share_commitments = commitments_full.0;
        let blinding_commitments = commitments_full.1;
        let dzk_coeffs = commitments_full.2;
        let blinding_comm_sender = blinding_commitments[self.myid].clone();

        // First, verify share commitments
        let mut appended_share = Vec::new();
        for share in shares.clone().into_iter(){
            appended_share.extend(share);
        }
        appended_share.extend(nonce_share);
        let comm_hash = do_hash(appended_share.as_slice());
        if comm_hash != share_commitments[self.myid]{
            // Invalid share commitments
            log::error!("Invalid share commitments from {}", sender);
            acss_ab_state.verification_status.insert(sender, false);
            return;
        }

        // Second, verify DZK proof
        let shares_ff: Vec<LargeField> = shares.into_iter().map(|el| LargeField::from_bytes_be(el.as_slice()).unwrap()).collect();
        let dzk_poly_coeffs: Vec<LargeField> = dzk_coeffs.into_iter().map(|el| LargeField::from_bytes_be(el.as_slice()).unwrap()).collect();
        let dzk_poly = Polynomial::new(dzk_poly_coeffs.as_slice());
        // Change this to be root of unity

        let share_root = MerkleTree::new(share_commitments, &self.hash_context).root();
        let blinding_root = MerkleTree::new(blinding_commitments, &self.hash_context).root();
        let root_comm = self.hash_context.hash_two(share_root, blinding_root);
        let root_comm_fe = LargeField::from_bytes_be(&root_comm).unwrap();

        let verf_status = self.evaluate_dzk_poly(
            root_comm_fe, 
            self.myid, 
            &dzk_poly, 
            &shares_ff, 
            blinding_comm_sender, 
            blinding_nonce_share
        );
        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        if !verf_status{
            // Invalid DZK proof
            log::error!("Invalid DZK proof from {}", sender);
            acss_ab_state.verification_status.insert(sender,false);
            return;
        }
        log::info!("Share from {} verified", sender);
        // If successful, add to verified list
        // Reborrow share
        
        acss_ab_state.verification_status.insert(sender,true);
        // Start reliable agreement
        let _status = self.inp_ra_channel.send((sender,1,instance_id)).await;
        self.check_termination(sender, instance_id).await;
    }

    pub fn evaluate_dzk_poly(
        &self,
        root_comm_fe: LargeField,
        share_sender: Replica,
        dzk_poly: &Polynomial<LargeField>, 
        shares: &Vec<LargeField>, 
        blinding_comm: LargeFieldSer,
        blinding_nonce: LargeFieldSer,
    )-> bool{
        // Change this to be root of unity
        let dzk_point;
        if !self.use_fft{
            dzk_point = dzk_poly.evaluate(&LargeField::new(UnsignedInteger::from((share_sender+1) as u64)));
        }
        else{
            // get point of evaluation
            let eval_point = self.roots_of_unity[share_sender];
            dzk_point = dzk_poly.evaluate(&eval_point);
        }
        let mut agg_shares_point = LargeField::zero();
        let mut root_comm_fe_mul = root_comm_fe.clone();
        for share in shares{
            agg_shares_point = agg_shares_point.add(share.mul(root_comm_fe_mul));
            root_comm_fe_mul = root_comm_fe_mul.mul(root_comm_fe.clone());
        }

        let blinding_poly_share_bytes = dzk_point.sub(agg_shares_point).to_bytes_be();
        let blinding_hash = self.hash_context.hash_two(blinding_poly_share_bytes,blinding_nonce);
        if blinding_hash != blinding_comm{
            // Invalid DZK proof
            return false;
        }
        true
    }
}