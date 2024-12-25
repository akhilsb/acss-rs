use consensus::{LargeFieldSSS, DZKProof};
use crypto::{LargeField, pseudorandom_lf, hash::{Hash, do_hash}, aes_hash::{MerkleTree, Proof}, LargeFieldSer};
use num_bigint_dig::RandBigInt;
use types::Replica;
use crate::{Context, msg::RowPolynomialsBatch};

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
        let mut col_dzk_proof_coefficients_batch = Vec::new();

        for (index,batch) in (0..batched_secrets.len()).into_iter().zip(batched_secrets.into_iter()){
            
            // Sample F(x,0) polynomial next
            let eval_point_start: isize = (self.num_faults as isize) * (-1);
            let eval_point_indices_lf: Vec<LargeField> = (eval_point_start..1).into_iter().map(|index| LargeField::from(index)).collect();
            let mut points_f_x0: Vec<(LargeField,LargeField)> = eval_point_indices_lf.clone().into_iter().zip(batch.clone().into_iter()).collect();
            for index in 1..self.num_faults+1{
                let rnd_share = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
                points_f_x0.push((LargeField::from(index), rnd_share));
            }

            // Generate coefficients of this polynomial
            let coeffs_f_x0 = self.large_field_bv_sss.polynomial_coefficients(&points_f_x0);
            
            let mut prf_seed = Vec::new();
            prf_seed.extend(instance_id.to_be_bytes());
            prf_seed.extend(index.to_be_bytes());

            let (mut row_evaluations,mut col_evaluations, bv_coefficients) 
                        = self.sample_bivariate_polynomial_with_prf(
                Some(coeffs_f_x0), 
                (0..self.num_nodes+1).into_iter().map(|el| LargeField::from(el)).collect(), 
                prf_seed.clone()
            );

            // remove the first row and column evaluation. They are not needed because they do not correspond to any node's shares
            row_evaluations.remove(0);
            col_evaluations.remove(0);

            let eval_indices = eval_point_indices_lf.clone();
            let (_, columns_secret) = Self::generate_row_column_evaluations(
                &bv_coefficients, 
                eval_indices, 
                &self.large_field_uv_sss
            );

            // Interpolate coefficients of share polynomials
            let mut coefficients_columns = Vec::new();
            for col_poly in columns_secret.into_iter(){
                let eval_points_for_interpolation: Vec<(LargeField,LargeField)> = (0..self.num_faults+1).into_iter().zip(col_poly.into_iter()).map(
                    |elem|
                    (LargeField::from(elem.0), elem.1)
                ).collect();
                coefficients_columns.push(self.large_field_uv_sss.polynomial_coefficients(&eval_points_for_interpolation));
            }

            row_coefficients_batch.push(bv_coefficients);
            row_evaluations_batch.push(row_evaluations);
            col_evaluations_batch.push(col_evaluations);
            col_dzk_proof_coefficients_batch.push(coefficients_columns);
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
        let dzk_poly_coeffs_batches: Vec<Vec<Vec<Vec<LargeField>>>> = col_dzk_proof_coefficients_batch.chunks(each_batch).map(|el| el.to_vec()).collect();

        let mut index: usize = 0;

        // Distributed Zero Knowledge Proof context
        let mut dzk_hashes = Vec::new();
        let mut dzk_broadcast_polys = Vec::new();
        
        let mut share_messages_party = Vec::new();
        for _ in 0..self.num_nodes{
            share_messages_party.push(Vec::new());
        }
        for ((row_coeffs_batch, _row_evals_batch),(col_evals_batch, dzk_polys_batch)) in 
                (row_coeffs_batches.into_iter().zip(row_poly_evals_batches.into_iter())).zip(col_poly_evals_batches.into_iter().zip(dzk_poly_coeffs_batches).into_iter()){

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
            let master_mt_proofs: Vec<Proof> = (0..self.num_nodes).into_iter().map(|el| master_mt.gen_proof(el)).collect();

            let master_root = master_mt.root();

            // A single blinding polynomial for the entire batch
            let blinding_poly_coeffs = self.sample_univariate_polynomial();
            let blinding_nonce_poly_coeffs = self.sample_univariate_polynomial();

            let blinding_eval_points: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|point| self.large_field_uv_sss.mod_evaluate_at(&blinding_poly_coeffs, point)).collect();
            let blinding_nonce_eval_points: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|point| self.large_field_uv_sss.mod_evaluate_at(&blinding_nonce_poly_coeffs, point)).collect();

            let mut blinding_poly_evals_vec = Vec::new();
            blinding_poly_evals_vec.push(blinding_eval_points.clone());

            let blinding_commitment_vec = Self::generate_commitments(blinding_poly_evals_vec, blinding_nonce_eval_points.clone());
            let blinding_mt = MerkleTree::new(blinding_commitment_vec, &self.hash_context);
            let blinding_root = blinding_mt.root();

            let master_root_batch = self.hash_context.hash_two(master_root, blinding_root);
            let mut master_root_lf = LargeField::from_signed_bytes_be(master_root_batch.as_slice())%&self.large_field_uv_sss.prime;
            if master_root_lf < zero{
                master_root_lf += &self.large_field_uv_sss.prime;
            }
            
            // Generate Distributed ZK polynomial
            let mut agg_poly = blinding_poly_coeffs.clone();
            let mut master_root_lf_mul= master_root_lf.clone();
            for bv_coeff_polys in dzk_polys_batch.into_iter(){
                for coeff_poly in bv_coeff_polys{
                    for (index, coeff) in (0..coeff_poly.len()).zip(coeff_poly){
                        agg_poly[index] = (&agg_poly[index]+(&master_root_lf_mul*coeff))%&self.large_field_uv_sss.prime;
                    }
                    master_root_lf_mul = (&master_root_lf_mul*&master_root_lf)%&self.large_field_uv_sss.prime;
                }
            }

            // Generate distributed ZK proof for this polynomial
            let mut merkle_roots_dzk = Vec::new();
            let mut eval_points_dzk = Vec::new();
            
            let mut trees_dzk: Vec<MerkleTree> = Vec::new();
            
            let coefficients = agg_poly.clone();
            let iteration = 1;

            let const_size_poly: Vec<LargeFieldSer> = self.folding_dzk_context.gen_dzk_proof(
                &mut eval_points_dzk, 
                &mut trees_dzk, 
                coefficients, 
                iteration, 
                master_root
            ).into_iter().map(|x| x.to_signed_bytes_be()).collect();
            
            for tree in trees_dzk.iter(){
                merkle_roots_dzk.push(tree.root());
            }
            dzk_broadcast_polys.push(const_size_poly);

            let mut dzk_proofs_all_nodes = Vec::new();
            for _ in 0..self.num_nodes{
                dzk_proofs_all_nodes.push(DZKProof{
                    g_0_x: Vec::new(),
                    g_1_x: Vec::new(),
                    proof: Vec::new(),
                });
            }
            
            for (g_0_g_1_shares,mt) in eval_points_dzk.into_iter().zip(trees_dzk.into_iter()){                
                //log::info!("Eval points iteration: {:?} rep: {}",g_0_g_1_shares ,rep);
                for (rep,g) in (0..self.num_nodes).into_iter().zip(g_0_g_1_shares.into_iter()){
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().g_0_x.push(g.0.to_signed_bytes_be());
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().g_1_x.push(g.1.to_signed_bytes_be());
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().proof.push(mt.gen_proof(rep));
                }
            }

            dzk_hashes.push(merkle_roots_dzk);

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
                let row_polys_sec_message = RowPolynomialsBatch{
                    coefficients: rows_party_batch,
                    blinding_evaluation: blinding_eval_points[rep].clone(),
                    nonce_coefficients: nonce_party_batch,
                    blinding_nonce_evaluation: blinding_nonce_eval_points[rep].clone(),
                    
                    proofs: merkle_proofs_row,
                    dzk_proof: dzk_proofs_all_nodes[rep].clone(),
                    root_proofs: master_mt_proofs.clone(),

                    blinding_poly_proof: blinding_mt.gen_proof(rep)
                };
                share_messages_party[rep].push(row_polys_sec_message);
            }
            index+=1;
        }
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

    fn sample_univariate_polynomial(&self) -> Vec<LargeField>{
        let mut coeffs = Vec::new();
        for _ in 0..self.num_faults+1{
            coeffs.push(rand::thread_rng().gen_bigint_range(&LargeField::from(0), &self.large_field_bv_sss.prime));
        }
        coeffs
    }

    // This method samples a random degree-(2t,t) bivariate polynomial given a set of secrets to encode within it. 
    // Returns (a,b,c) - a is the set of evaluations on row polynomials on the given evaluation points, 
    // b is the set of evaluations on the column polynomials on the given evaluation points
    // c is the set of coefficients of row polynomials. 
    // instance_id acts the prf seed for generating shares randomly
    fn sample_bivariate_polynomial_with_prf(&self, 
        secret_poly_coeffs: Option<Vec<LargeField>>, 
        evaluation_pts: Vec<LargeField>, 
        prf_seed: Vec<u8>
    )->(Vec<Vec<LargeField>>, Vec<Vec<LargeField>>,Vec<Vec<LargeField>>){
        let mut row_coefficients = Vec::new();
        let secret_encoded = secret_poly_coeffs.is_some();
        if secret_encoded{
            row_coefficients.push(secret_poly_coeffs.unwrap());
        }
        for rep in 0..self.num_faults{
            let mut sec_key = self.sec_key_map.get(&rep).unwrap().clone();
            sec_key.extend(prf_seed.clone());
            // Use a different seed when there is no secret to be encoded. 
            if !secret_encoded{
                sec_key.extend(self.nonce_seed.to_be_bytes());
            }
            
            let sampled_coefficients: Vec<LargeField> = pseudorandom_lf(sec_key.as_slice(), 2*self.num_faults+1).into_iter().map(
                |elem|{
                    let mut mod_elem = elem%&self.large_field_uv_sss.prime;
                    if mod_elem < LargeField::from(0){
                        mod_elem+=&self.large_field_uv_sss.prime;
                    }
                    mod_elem
                }
            ).collect();
            row_coefficients.push(sampled_coefficients);
        }
        if !secret_encoded{
            // First polynomial must be randomly sampled
            let mut first_poly = Vec::new();
            for _ in 0..2*self.num_faults+1{
                first_poly.push(rand::thread_rng().gen_bigint_range(&LargeField::from(0), &self.large_field_uv_sss.prime));
            }
            row_coefficients.push(first_poly);
        }
        //let eval_points = (1..self.num_nodes+1).into_iter().map(|el| LargeField::from(el)).collect();
        let (mut row_evals,col_evals) = Self::generate_row_column_evaluations(
            &row_coefficients, 
            evaluation_pts,
            &self.large_field_uv_sss 
        );
        // Fill remaining row polynomials
        for point in self.num_faults+1..self.num_nodes+1{
            let mut row_poly_evaluations = Vec::new();
            for index in 0..self.num_nodes{
                row_poly_evaluations.push(col_evals[index][point].clone());
            }
            row_evals.push(row_poly_evaluations);
        }
        (row_evals,col_evals, row_coefficients)
    }

    fn generate_row_column_evaluations(coefficients: &Vec<Vec<LargeField>>, 
            eval_points: Vec<LargeField>, 
            large_field_shamir_context: &LargeFieldSSS
        )->(Vec<Vec<LargeField>>,Vec<Vec<LargeField>>){
        let mut row_evaluations = Vec::new();
        let mut column_evaluations = Vec::new();
        for _ in 0..coefficients.len(){
            row_evaluations.push(Vec::new());
        }
        for _ in 0..eval_points.len(){
            column_evaluations.push(Vec::new());
        }
        for (index,coefficient_vec) in (0..coefficients.len()).into_iter().zip(coefficients.into_iter()){
            for (index_p,point) in (0..eval_points.len()).zip(eval_points.clone().into_iter()){
                let evaluation = large_field_shamir_context.mod_evaluate_at_lf(&coefficient_vec.as_slice(), point);
                row_evaluations[index].push(evaluation.clone());
                column_evaluations[index_p].push(evaluation);
            }
        }
        for index in 0..column_evaluations.len(){
            large_field_shamir_context.fill_evaluation_at_all_points(&mut column_evaluations[index]);
            assert!(large_field_shamir_context.verify_degree(&mut column_evaluations[index]));
        }
        return (row_evaluations,column_evaluations);
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