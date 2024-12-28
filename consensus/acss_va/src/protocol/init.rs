use std::time::{SystemTime, UNIX_EPOCH};

use crypto::{LargeField, hash::{Hash, do_hash}, aes_hash::{MerkleTree}, encrypt, decrypt, pseudorandom_lf};
use network::{plaintcp::CancelHandler, Acknowledgement};
use num_bigint_dig::RandBigInt;
use types::{WrapperMsg, Replica};
use crate::{Context, msg::{RowPolynomialsBatch, Commitment, RowPolynomialsBatchSer, ProtMsg, PointsBV}, protocol::BatchACSSState};

impl Context{
    pub async fn init_batch_acss_va(self: &mut Context, secrets: Vec<LargeField>, instance_id: usize){

        let tot_batches = 1;
        let zero = LargeField::from(0);
        let field_prime = self.large_field_bv_sss.prime.clone();
        // Sample bivariate polynomials
        // Pack t+1 degree-t sharings in each bivariate polynomial
        let batched_secrets = Self::batch_secrets(secrets, self.num_faults+1);
        
        // Represent each batch of secrets using a degree-(2t,t) bivariate polynomial
        let mut row_coefficients_batch = Vec::new();
        let mut row_evaluations_batch = Vec::new();
        let mut col_evaluations_batch = Vec::new();
        let mut col_dzk_proof_evaluations_batch = Vec::new();


        for (index,batch) in (0..batched_secrets.len()).into_iter().zip(batched_secrets.into_iter()){
            
            // Sample F(x,0) polynomial next
            let eval_point_start: isize = ((self.num_faults+1) as isize) * (-1);
            let eval_point_indices_lf: Vec<LargeField> = (0..eval_point_start).into_iter().map(|index| LargeField::from(index)).collect();
            
            let mut points_f_x0: Vec<LargeField> = batch.clone();
            for _ in 1..self.num_faults+1{
                let rnd_share = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
                points_f_x0.push(rnd_share);
            }

            // Generate coefficients of this polynomial
            let coeffs_f_x0 = self.large_field_bv_sss.polynomial_coefficients_with_precomputed_vandermonde_matrix(&points_f_x0);
            
            let mut prf_seed = Vec::new();
            prf_seed.extend(instance_id.to_be_bytes());
            prf_seed.extend(index.to_be_bytes());

            let (mut row_evaluations,mut col_evaluations, bv_coefficients) 
                        = self.sample_bivariate_polynomial_with_prf(
                Some(coeffs_f_x0), 
                (0..self.num_nodes+1).into_iter().map(|el| LargeField::from(el)).collect(), 
                prf_seed.clone()
            );
            
            // Secrets are no longer needed. Remove the first row and column evaluation. They are not needed because they do not correspond to any node's shares
            row_evaluations.remove(0);
            col_evaluations.remove(0);
            for (row, column) in row_evaluations.iter_mut().zip(col_evaluations.iter_mut()){
                row.remove(0);
                column.remove(0);
            }

            let eval_indices = eval_point_indices_lf.clone();
            let (_, columns_secret) = Self::generate_row_column_evaluations(
                &bv_coefficients, 
                eval_indices, 
                &self.large_field_uv_sss,
                false
            );

            row_coefficients_batch.push(bv_coefficients);
            row_evaluations_batch.push(row_evaluations);
            col_evaluations_batch.push(col_evaluations);
            col_dzk_proof_evaluations_batch.push(columns_secret);
            // Generate commitments on points in rows and columns
            // Generate coefficients of all n row polynomials and column polynomials for transmission
            // Generate dZK proofs on the polynomials generated on indices -t+1..0. 
        }

        let each_batch;
        if row_coefficients_batch.len()%tot_batches != 0{
            each_batch = (row_coefficients_batch.len()/tot_batches)+1;
        }
        else{
            each_batch = row_coefficients_batch.len()/tot_batches;
        }
        let row_coeffs_batches: Vec<Vec<Vec<Vec<LargeField>>>> = row_coefficients_batch.chunks(each_batch).into_iter().map(|el| el.to_vec()).collect();
        let row_poly_evals_batches: Vec<Vec<Vec<Vec<LargeField>>>> = row_evaluations_batch.chunks(each_batch).into_iter().map(|el|el.to_vec()).collect();
        let col_poly_evals_batches: Vec<Vec<Vec<Vec<LargeField>>>> = col_evaluations_batch.chunks(each_batch).map(|el| el.to_vec()).collect();
        let dzk_poly_evals_batches: Vec<Vec<Vec<Vec<LargeField>>>> = col_dzk_proof_evaluations_batch.chunks(each_batch).map(|el| el.to_vec()).collect();

        let mut index: usize = 0;
        
        let mut share_messages_party = Vec::new();
        for _ in 0..self.num_nodes{
            share_messages_party.push(Vec::new());
        }

        let mut merkle_roots_batches = Vec::new();
        let mut blinding_commitments_batches = Vec::new();
        let mut dzk_polynomials = Vec::new();
        for ((row_coeffs_batch, _row_evals_batch),(col_evals_batch, dzk_polys_batch)) in 
                (row_coeffs_batches.into_iter().zip(row_poly_evals_batches.into_iter())).zip(col_poly_evals_batches.into_iter().zip(dzk_poly_evals_batches).into_iter()){

            // Sample nonce polynomial
            let mut prf_seed = Vec::new();
            prf_seed.extend(instance_id.to_be_bytes());
            prf_seed.extend(self.nonce_seed.to_be_bytes());
            prf_seed.extend(index.clone().to_be_bytes());
            
            let evaluation_points = (1..self.num_nodes+1).into_iter().map(|el| LargeField::from(el)).collect();
            let (_nonce_row_evals, nonce_col_evals, nonce_row_coeffs) 
                    = self.sample_bivariate_polynomial_with_prf(None, evaluation_points, prf_seed);
            
            // Generate commitments
            let comms: Vec<Vec<Hash>> = col_evals_batch.clone().into_iter().zip(nonce_col_evals.into_iter()).map(
                |(shares,nonces)|
                Self::generate_commitments(shares, nonces)
            ).collect();

            let merkle_trees: Vec<MerkleTree> = comms.into_iter().map(|el| MerkleTree::new(el,&self.hash_context)).collect();
            let mrs: Vec<Hash> = merkle_trees.iter().map(|mt| mt.root()).collect();
            
            let master_mt = MerkleTree::new(mrs.clone(),&self.hash_context);
            
            let master_root = master_mt.root();

            // A single blinding polynomial for the entire batch
            let blinding_poly_coeffs = self.sample_univariate_polynomial();
            let blinding_nonce_poly_coeffs = self.sample_univariate_polynomial();

            let blinding_eval_points_comm: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|point| self.large_field_uv_sss.mod_evaluate_at(&blinding_poly_coeffs, point)).collect();
            
            let blinding_eval_points_dzk: Vec<LargeField> = (0..self.num_faults+1).into_iter().map(|point| self.large_field_uv_sss.mod_evaluate_at(&blinding_poly_coeffs, point)).collect();
            let blinding_nonce_eval_points: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|point| self.large_field_uv_sss.mod_evaluate_at(&blinding_nonce_poly_coeffs, point)).collect();

            let mut blinding_poly_evals_vec = Vec::new();
            blinding_poly_evals_vec.push(blinding_eval_points_comm.clone());

            let blinding_commitment_vec = Self::generate_commitments(blinding_poly_evals_vec, blinding_nonce_eval_points.clone());
            let blinding_mt = MerkleTree::new(blinding_commitment_vec.clone(), &self.hash_context);
            let blinding_root = blinding_mt.root();

            let master_root_batch = self.hash_context.hash_two(master_root, blinding_root);
            let mut master_root_lf = LargeField::from_signed_bytes_be(master_root_batch.as_slice())%&self.large_field_uv_sss.prime;
            if master_root_lf < zero{
                master_root_lf += &self.large_field_uv_sss.prime;
            }
            
            // Generate Distributed ZK polynomial
            let mut agg_poly = blinding_eval_points_dzk.clone();
            let mut master_root_lf_mul= master_root_lf.clone();
            for bv_eval_polys in dzk_polys_batch.into_iter(){
                for eval_poly in bv_eval_polys{
                    for (index, evaluation) in (0..eval_poly.len()).zip(eval_poly){
                        agg_poly[index] = (&agg_poly[index]+(&master_root_lf_mul*evaluation))%&self.large_field_uv_sss.prime;
                    }
                    master_root_lf_mul = (&master_root_lf_mul*&master_root_lf)%&self.large_field_uv_sss.prime;
                }
            }

            self.large_field_uv_sss.fill_evaluation_at_all_points(&mut agg_poly);

            dzk_polynomials.push(agg_poly.clone().into_iter().map(|el| el.to_signed_bytes_be()).collect());
            //Compose share message
            
            let mut row_coeffs_party = Vec::new();
            let mut nonce_coeffs_party = Vec::new();
            for _ in 0..self.num_nodes{
                row_coeffs_party.push(Vec::new());
                nonce_coeffs_party.push(Vec::new());
            }

            for bv_poly in row_coeffs_batch.into_iter(){
                for (rep, deg_2t_poly) in (0..self.num_nodes).into_iter().zip(bv_poly.into_iter()){
                    row_coeffs_party[rep].push(deg_2t_poly);
                }
            }
            for (rep,nonce_poly) in (0..self.num_nodes).into_iter().zip(nonce_row_coeffs.into_iter()){
                nonce_coeffs_party[rep].extend(nonce_poly);
            }

            for (rep,(rows_party_batch,nonce_party_batch)) in (0..self.num_nodes).into_iter().zip(row_coeffs_party.into_iter().zip(nonce_coeffs_party.into_iter())){
                let mut merkle_proofs_row = Vec::new();

                for mt_column in merkle_trees.iter(){
                    merkle_proofs_row.push(mt_column.gen_proof(rep));
                }

                let row_polys_sec_message;
                if rep < self.num_faults{
                    row_polys_sec_message = RowPolynomialsBatch{
                        coefficients: Vec::new(),
                        blinding_evaluation: blinding_eval_points_comm[rep].clone(),
                        nonce_coefficients: Vec::new(),
                        blinding_nonce_evaluation: blinding_nonce_eval_points[rep].clone(),
                        
                        num_bv_polys: rows_party_batch.len(),
                        proofs: merkle_proofs_row,
    
                        blinding_poly_proof: blinding_mt.gen_proof(rep)
                    };
                }
                else{
                    let num_bv_polys = rows_party_batch.len();
                    row_polys_sec_message = RowPolynomialsBatch{
                        coefficients: rows_party_batch,
                        blinding_evaluation: blinding_eval_points_comm[rep].clone(),
                        nonce_coefficients: nonce_party_batch,
                        blinding_nonce_evaluation: blinding_nonce_eval_points[rep].clone(),
                        
                        num_bv_polys: num_bv_polys,
                        proofs: merkle_proofs_row,
    
                        blinding_poly_proof: blinding_mt.gen_proof(rep)
                    };
                }
                assert!(row_polys_sec_message.verify_commitments(&self.hash_context, 
                    &self.large_field_bv_sss, 
                    (1..self.num_nodes+1).into_iter().collect(), 
                    master_root_batch.clone())
                );
                let eval_point_start: isize = ((self.num_faults+1) as isize) * (-1);
                let eval_point_indices_lf: Vec<LargeField> = (0..eval_point_start).into_iter().map(|index| LargeField::from(index)).collect();
                assert!(row_polys_sec_message.verify_shares_with_dzk(
                    agg_poly[rep+1].clone(), 
                    eval_point_indices_lf, 
                    &self.large_field_uv_sss, 
                    &self.hash_context)
                );
                share_messages_party[rep].push(row_polys_sec_message);
            }
            merkle_roots_batches.push(mrs);
            blinding_commitments_batches.push(blinding_commitment_vec);
            index+=1;
        }

        let commitment = Commitment{
            roots: merkle_roots_batches,
            blinding_roots: blinding_commitments_batches,
            dzk_poly: dzk_polynomials
        };

        for (rep,row_polys) in (0..self.num_nodes).into_iter().zip(share_messages_party.into_iter()){
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();

            let ser_shares: Vec<RowPolynomialsBatchSer> = row_polys.into_iter().map(|row| RowPolynomialsBatchSer::from_deser(row)).collect();
            // encrypt share
            let ser_share_msg = bincode::serialize(&ser_shares).unwrap();
            let enc_share = encrypt(&secret_key, ser_share_msg);

            let init_msg = ProtMsg::Init(enc_share, commitment.clone(), self.myid, instance_id);
            let wrapper_msg = WrapperMsg::new(init_msg,self.myid, secret_key.as_slice());

            let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
        // Broadcast commitments and send shares to everyone
        log::info!("Creation time: {:?}", SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis());
    }

    pub async fn process_batch_acss_init(&mut self, enc_msg: Vec<u8>, commitment: Commitment, sender: Replica, instance_id: usize){
        if !self.acss_state.contains_key(&instance_id){
            let new_state = BatchACSSState::new(sender);
            self.acss_state.insert(instance_id, new_state);
        }

        let acss_state = self.acss_state.get_mut(&instance_id).unwrap();


        let secret_key = self.sec_key_map.get(&sender).clone().unwrap().clone();
        // Decrypt message first
        let dec_msg = decrypt(&secret_key, enc_msg);
        // Deserialize the encrypted message
        let shares_msg: Vec<RowPolynomialsBatchSer> = bincode::deserialize(dec_msg.as_slice()).unwrap();
        
        // Verify shares
        let mut index_batch: usize = 0;

        let mut row_evaluations = Vec::new();
        let mut nonce_evaluations = Vec::new();
        let mut proofs = Vec::new();
        for (shares_batch_ser, (merkle_roots, (blinding_comm,dzk_polynomial))) in shares_msg.into_iter().zip(
            commitment.roots.into_iter().zip(
                commitment.blinding_roots.into_iter().zip(commitment.dzk_poly.into_iter()))){
            let mut shares_batch = shares_batch_ser.to_deser();
            let num_polys = shares_batch.num_bv_polys;
            if self.myid < self.num_faults{
                // Generate share coefficients locally using PRF
                for index in 0..num_polys{
                    let mut sk_coeff = secret_key.clone();
                    let mut prf_seed = Vec::new();
                    prf_seed.extend(instance_id.to_be_bytes());
                    prf_seed.extend(index.to_be_bytes());

                    sk_coeff.extend(prf_seed.clone());
            
                    let sampled_coefficients: Vec<LargeField> = pseudorandom_lf(sk_coeff.as_slice(), 2*self.num_faults+1).into_iter().map(
                        |elem|{
                            let mut mod_elem = elem%&self.large_field_uv_sss.prime;
                            if mod_elem < LargeField::from(0){
                                mod_elem+=&self.large_field_uv_sss.prime;
                            }
                            mod_elem
                        }
                    ).collect();
                    shares_batch.coefficients.push(sampled_coefficients);
                }
                let mut sk_nonce = secret_key.clone();
                let mut prf_seed = Vec::new();
                prf_seed.extend(instance_id.to_be_bytes());
                prf_seed.extend(self.nonce_seed.to_be_bytes());
                prf_seed.extend(index_batch.to_be_bytes());

                sk_nonce.extend(prf_seed);
                // Generate nonce polynomial through PRF
                let sampled_coefficients: Vec<LargeField> = pseudorandom_lf(sk_nonce.as_slice(), 2*self.num_faults+1).into_iter().map(
                    |elem|{
                        let mut mod_elem = elem%&self.large_field_uv_sss.prime;
                        if mod_elem < LargeField::from(0){
                            mod_elem+=&self.large_field_uv_sss.prime;
                        }
                        mod_elem
                    }
                ).collect();
                shares_batch.nonce_coefficients.extend(sampled_coefficients);
                index_batch+=1;
            }
            // generate Merkle tree on commitments
            let shares_mt = MerkleTree::new(merkle_roots.clone(), &self.hash_context);
            let blinding_mt = MerkleTree::new(blinding_comm.clone(), &self.hash_context);

            let master_root = self.hash_context.hash_two(shares_mt.root(), blinding_mt.root());
            // Verify commitments
            if !shares_batch.verify_commitments(
                &self.hash_context, 
                &self.large_field_uv_sss, 
                (1..self.num_nodes+1).into_iter().collect(), 
                master_root
            ){
                log::error!("Commitment verification failed for ACSS instance {}", instance_id);
                return;
            }

            // Verify DZK proof
            let eval_point_start: isize = ((self.num_faults+1) as isize) * (-1);
            let eval_point_indices_lf: Vec<LargeField> = (0..eval_point_start).into_iter().map(|index| LargeField::from(index)).collect();
            let dzk_polynomial: Vec<LargeField> = dzk_polynomial.into_iter().map(|el| LargeField::from_signed_bytes_be(el.as_slice())).collect();
            if !shares_batch.verify_shares_with_dzk(
                dzk_polynomial[self.myid+1].clone(), 
                eval_point_indices_lf, 
                &self.large_field_uv_sss, 
                &self.hash_context){
                log::error!("DZK proof verification failed for ACSS instance {}", instance_id);
                return;
            }
            let row_evaluations_batch: Vec<Vec<LargeField>> = shares_batch.coefficients.clone().into_iter().map(|coeffs| {
                return (1..self.num_nodes+1).into_iter().map(|point| self.large_field_uv_sss.mod_evaluate_at(&coeffs, point)).collect();
            }).collect();

            let nonce_evals_batch: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|point| self.large_field_uv_sss.mod_evaluate_at(&shares_batch.nonce_coefficients , point)).collect();
            
            row_evaluations.push(row_evaluations_batch);
            nonce_evaluations.push(nonce_evals_batch);
            proofs.push(shares_batch.proofs);

            acss_state.row_coefficients.push(shares_batch.coefficients);
            acss_state.nonce_coefficients.push(shares_batch.nonce_coefficients);
            
            acss_state.blinding_commitments.push(blinding_comm);
            acss_state.blinding_row_shares.push(shares_batch.blinding_evaluation);
            acss_state.blinding_nonce_shares.push(shares_batch.blinding_nonce_evaluation);

            acss_state.dzk_polynomials.push(dzk_polynomial);
            acss_state.share_roots.push(merkle_roots);
        }
        log::info!("Successfully verified all shares for ACSS instance ID {}", instance_id);
        acss_state.rows_reconstructed = true;

        // Send ECHOs to all parties
        let mut points_vec = Vec::new();
        for _ in 0..self.num_nodes{
            points_vec.push(PointsBV{
                evaluations: Vec::new(),
                nonce_evaluation: Vec::new(),
                proof: Vec::new()
            })
        }

        // for (row_evals, (nonce_evals, proofs)) in row_evaluations.into_iter().zip(nonce_evaluations.into_iter().zip(proofs.into_iter())){
        //     for row_eval_sp in row_evals{
        //         for (rep, point) in (0..self.num_nodes).into_iter().zip(row_eval_sp.into_iter()){
        //             points_vec[rep].evaluations.push()
        //         }                
        //     }
        // }        
    }

    fn generate_commitments(shares: Vec<Vec<LargeField>>, nonces: Vec<LargeField>)-> Vec<Hash>{
        let mut hashes = Vec::new();
        let mut appended_msgs = Vec::new();
        for _ in 0..nonces.len(){
            appended_msgs.push(Vec::new());
        }
        for shares_poly in shares{
            for (rep,share) in (0..shares_poly.len()).into_iter().zip(shares_poly.into_iter()){
                appended_msgs[rep].extend(share.to_signed_bytes_be());
            }
        }
        for (mut msg,nonce) in appended_msgs.into_iter().zip(nonces.into_iter()){
            let nonce_ser = nonce.to_signed_bytes_be();
            msg.extend(nonce_ser);
            hashes.push(do_hash(msg.as_slice()));
        }
        hashes
    }

    fn batch_secrets(secrets: Vec<LargeField>, batch_size: usize)-> Vec<Vec<LargeField>>{
        let zero = LargeField::from(0);
        let mut bv_secrets_packed = Vec::new();
        let mut packed_secrets = Vec::new();
        let mut count = 0;
        for secret in secrets.into_iter(){
            packed_secrets.push(secret);
            count +=1;
            if count == batch_size{
                bv_secrets_packed.push(packed_secrets.clone());
                packed_secrets = Vec::new();
                count = 0;
            }
        }
        if packed_secrets.len() > 0{
            // Pad the last batch with dummy secrets
            for _ in packed_secrets.len()..batch_size{
                packed_secrets.push(zero.clone());
            }
        }
        bv_secrets_packed.push(packed_secrets);
        bv_secrets_packed
    }
}