use crate::{msg::AcssSKEShares, CommDZKMsg, Context};
use crypto::{encrypt, hash::{do_hash}};
use lambdaworks_math::{unsigned_integer::element::UnsignedInteger, traits::ByteConversion};
use consensus::{LargeField, LargeFieldSer, expand_sharing_to_n_evaluation_points, expand_sharing_to_n_evaluation_points_opt, sample_polynomials_from_prf, rand_field_element};
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

        // Bivariate polynomials
        let tot_sharings = secrets.len();
        let mut handles = Vec::new();
        let mut _indices;
        let mut evaluations;
        let nonce_evaluations;
        let mut coefficients;
        
        let blinding_poly_evaluations;
        let nonce_blinding_poly_evaluations;
        
        // if !self.use_fft{
        // Generate Shamir secret shares using a PRG
        let evaluations_prf = sample_polynomials_from_prf(
            secrets, 
            self.symmetric_keys_avid.keys_from_me.clone(), 
            self.num_faults, 
            false, 
            1u8
        );

        // Expand sampled degree-t univariate polynomials to all n points
        let evaluation_prf_chunks: Vec<Vec<Vec<LargeField>>> = evaluations_prf.chunks(evaluations_prf.len()/self.num_threads).map(|el| el.to_vec()).collect();
        for eval_prfs in evaluation_prf_chunks{
            let handle = tokio::spawn(
                expand_sharing_to_n_evaluation_points_opt(
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
        
        // Generate Shamir secret sharings of Nonce polynomials for Commitment generation
        let nonce_secrets:Vec<LargeField> = (0..self.num_faults).into_iter().map(|_| rand_field_element()).collect();
        let evaluations_nonce_prf = sample_polynomials_from_prf(
            nonce_secrets,
            self.symmetric_keys_avid.keys_from_me.clone(), 
            self.num_faults, 
            true, 
            1u8
        );
        let (nonce_evaluations_ret,_nonce_coefficients) = expand_sharing_to_n_evaluation_points(
            evaluations_nonce_prf,
            self.num_faults,
            self.num_nodes
        ).await;
        nonce_evaluations = nonce_evaluations_ret;

        // Sample blinding polynomials
        let blinding_secrets: Vec<LargeField> = (0..self.num_faults).into_iter().map(|_| rand_field_element()).collect();
        let blinding_prf = sample_polynomials_from_prf(
            blinding_secrets, 
            self.symmetric_keys_avid.keys_from_me.clone(), 
            self.num_faults, 
            true,
            2u8
        );
        let (blinding_poly_evaluations_vec, _blinding_poly_coefficients_vec) = expand_sharing_to_n_evaluation_points(
            blinding_prf,
            self.num_faults,
            self.num_nodes
        ).await;

        blinding_poly_evaluations = blinding_poly_evaluations_vec;

        let blinding_nonce_secrets: Vec<LargeField> = (0..self.num_faults).into_iter().map(|_| rand_field_element()).collect();
        let blinding_nonce_prf = sample_polynomials_from_prf(
            blinding_nonce_secrets, 
            self.symmetric_keys_avid.keys_from_me.clone(), 
            self.num_faults, 
            true,
            3u8
        );

        let (nonce_blinding_poly_evaluations_vec, _nonce_blinding_poly_coefficients_vec) = expand_sharing_to_n_evaluation_points(
            blinding_nonce_prf,
            self.num_faults,
            self.num_nodes,
        ).await;
        nonce_blinding_poly_evaluations = nonce_blinding_poly_evaluations_vec;

        // Group polynomials into bivariate polynomials
        // Also DZK proofs need to be the old one in the Crypto work
        let mut bv_evaluations: Vec<Vec<Vec<LargeField>>> = evaluations.chunks(self.num_faults+1).map(|el|el.to_vec()).collect();
        
        // Create a bivariate polynomial from each group
        let expansion_eval_points: Vec<LargeField> = (self.num_faults+1..self.num_nodes+1).into_iter().map(|i| LargeField::new(UnsignedInteger::from(i as u64))).collect();
        Self::gen_bivariate_polynomials(
            &mut bv_evaluations, 
            self.num_faults,
            expansion_eval_points.clone()
        );

        let mut nonce_poly_evaluations: Vec<Vec<Vec<LargeField>>> = vec![nonce_evaluations];
        Self::gen_bivariate_polynomials(
            &mut nonce_poly_evaluations,
            self.num_faults,
            expansion_eval_points.clone()
        );

        let mut blinding_poly_evaluations: Vec<Vec<Vec<LargeField>>> = vec![blinding_poly_evaluations];
        Self::gen_bivariate_polynomials(
            &mut blinding_poly_evaluations, 
            self.num_faults, 
            expansion_eval_points.clone()
        );

        let mut nonce_blinding_poly_evaluations: Vec<Vec<Vec<LargeField>>> = vec![nonce_blinding_poly_evaluations];
        Self::gen_bivariate_polynomials(
            &mut nonce_blinding_poly_evaluations,
            self.num_faults,
            expansion_eval_points.clone()
        );

        // Now evaluations_grouped contains the bivariate polynomial evaluations
        // Generate commitments

        let commitments = Self::gen_commitments(
            &bv_evaluations,
            &nonce_poly_evaluations[0],
            self.num_nodes
        );

        let blinding_commitments = Self::gen_commitments(
            &blinding_poly_evaluations, 
            &nonce_blinding_poly_evaluations[0], 
            self.num_nodes
        );

        let root_comm = Self::root_commitment(&commitments);
        let blinding_root_comm = Self::root_commitment(&blinding_commitments);

        let fiat_shamir_root_comm = self.hash_context.hash_two(root_comm.clone(), blinding_root_comm.clone());
        let fiat_shamir_root_fe = LargeField::from_bytes_be(fiat_shamir_root_comm.as_slice()).unwrap();

        let dzk_poly = Self::gen_dzk_proof_polynomial(
            &bv_evaluations, 
            &blinding_poly_evaluations[0], 
            fiat_shamir_root_fe
        );
        
        let dzk_poly_ser = dzk_poly.iter().map(|poly|{
            poly.iter().map(|el| el.to_bytes_be()).collect()
        }).collect();

        let comm_msg = CommDZKMsg{
            comm: commitments,
            blinding_comm: blinding_commitments,

            dzk_poly: dzk_poly_ser,
            tot_shares: tot_sharings,
            src: self.myid,
            instance_id: instance_id
        };
        
        let ser_comm_msg = bincode::serialize(&comm_msg).unwrap();
        // Group shares into n batches
        let mut grouped_shares_for_avid: Vec<Vec<Vec<LargeFieldSer>>> = vec![vec![vec![];self.num_nodes];self.num_nodes];
        for bv_polynomial in bv_evaluations.into_iter(){
            for (iter_index,poly_vec) in bv_polynomial.into_iter().enumerate(){
                for (party_index,share) in poly_vec.into_iter().enumerate(){
                    grouped_shares_for_avid[iter_index][party_index].push(share.to_bytes_be());
                }
            }
        }
        
        // Send shares in n batches through n independent AVID instances
        let _rbc_status = self.inp_ctrbc.send(ser_comm_msg).await;
        for batch in 0..self.num_nodes{
            let mut shares: Vec<(Replica,Option<Vec<u8>>)> = Vec::new();
            for rep in 0..self.num_nodes{
                // prepare shares
                // even need to encrypt shares
                
                let shares_party = grouped_shares_for_avid[batch][rep].clone();
                let nonce_share = nonce_poly_evaluations[0][batch][rep].to_bytes_be();
                let blinding_share = blinding_poly_evaluations[0][batch][rep].to_bytes_be();
                let nonce_blinding_share: [u8; 32] = nonce_blinding_poly_evaluations[0][batch][rep].to_bytes_be();

                let shares_struct;
                if (self.use_fft) || (!self.use_fft && rep >= self.num_faults){
                    shares_struct = AcssSKEShares{
                        evaluations: (shares_party, nonce_share),
                        blinding_evaluations: (blinding_share, nonce_blinding_share),
                        rep: rep,
                        batch: batch
                    };   
                }
                else{
                    shares_struct = AcssSKEShares{
                        evaluations: (vec![], [0u8;32]),
                        blinding_evaluations: ([0u8;32], [0u8;32]),
                        rep: rep,
                        batch: batch
                    };
                }

                let shares_ser = bincode::serialize(&shares_struct).unwrap();
                
                let sec_key = self.symmetric_keys_avid.keys_from_me.get(&rep).unwrap().clone();
                let enc_shares = encrypt(sec_key.as_slice(), shares_ser);
                
                let ser_enc_msg = bincode::serialize(&(instance_id,batch,enc_shares)).unwrap();
                shares.push((rep, Some(ser_enc_msg)));
            }
            let _inp_avid_status = self.inp_avid_channel.send(shares).await;
        }
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

        if !acss_ab_state.commitments.contains_key(&sender) || !acss_ab_state.batch_wise_shares.len() < self.num_nodes{
            // AVID and CTRBC did not yet terminate
            return;
        }

        // Share verification first
        let shares_full = acss_ab_state.batch_wise_shares.get(&sender).unwrap().clone();
        let va_commitment = acss_ab_state.commitments.get(&sender).unwrap().clone();
        
        // Verify Commitments for each batch of shares
        for batch in 0..self.num_nodes{
            // Verify batch by batch
            let acss_ske_shares = shares_full.get(&batch).unwrap().clone();
            // Verify commitments
            let mut appended_share: Vec<u8> = Vec::new();
            for share in acss_ske_shares.evaluations.0.clone().into_iter(){
                appended_share.extend(share);
            }
            appended_share.extend(acss_ske_shares.evaluations.1.clone());

            let commitment = do_hash(appended_share.as_slice());
            if commitment != va_commitment.comm[batch][self.myid] {
                log::error!("Share commitment mismatch for instance {} from sender {} in batch {}", instance_id, sender, batch);
                return;
            }

            let mut appended_share: Vec<u8> = Vec::new();
            appended_share.extend(acss_ske_shares.blinding_evaluations.0.clone());
            appended_share.extend(acss_ske_shares.blinding_evaluations.1.clone());

            let blinding_commitment = do_hash(appended_share.as_slice());
            if blinding_commitment != va_commitment.blinding_comm[batch][self.myid] {
                log::error!("Blinding share commitment mismatch for instance {} from sender {} in batch {}", instance_id, sender, batch);
                return;
            }
        }

        // Commitment matching complete, compute DZK proofs and verify
        let root_commitment = Self::root_commitment(&va_commitment.comm);
        let blinding_root_commitment = Self::root_commitment(&va_commitment.blinding_comm);

        let fiat_shamir_root_comm = self.hash_context.hash_two(root_commitment.clone(), blinding_root_commitment.clone());
        let fiat_shamir_root_fe = LargeField::from_bytes_be(fiat_shamir_root_comm.as_slice()).unwrap();

        let mut accepted_shares= Vec::new();
        for batch in 0..self.num_nodes{
            let acss_ske_shares = shares_full.get(&batch).unwrap().clone();
            // Serialized shares
            let shares: Vec<LargeField> = acss_ske_shares.evaluations.0.clone().into_iter().map(|el| LargeField::from_bytes_be(el.as_slice()).unwrap()).collect();
            
            let blinding_share: LargeField = LargeField::from_bytes_be(acss_ske_shares.blinding_evaluations.0.clone().as_slice()).unwrap();
            let mut agg_share = blinding_share.clone();
            let mut mult = fiat_shamir_root_fe.clone();
            for share in shares.iter(){
                agg_share += share*mult;
                mult *= fiat_shamir_root_fe.clone();
            }

            let dzk_share = LargeField::from_bytes_be(va_commitment.dzk_poly[batch][self.myid].as_slice()).unwrap();
            if agg_share != dzk_share {
                log::error!("DZK share verification failed for instance {} from sender {} in batch {}", instance_id, sender, batch);
                return;
            }

            if batch <= self.num_faults{
                accepted_shares.extend(shares.clone());
            }
        }

        acss_ab_state.shares.insert(sender, accepted_shares);
        log::info!("All DZK shares from sender {} in instance_id {} verified successfully", sender, instance_id);
        // Accumulate all shares from batches
        acss_ab_state.verification_status.insert(sender,true);
        // Start reliable agreement
        let _status = self.inp_ra_channel.send((sender,1,instance_id)).await;
        self.check_termination(sender, instance_id).await;
    }
}