use std::collections::{HashSet, HashMap};

use consensus::{ShamirSecretSharing, LargeField};
use crypto::hash::Hash;
use crypto::pseudorandom_lw;
use lambdaworks_math::polynomial::Polynomial;
use types::Replica;

use crate::{Context, msg::{Commitment, PointsBV}};

use lambdaworks_math::traits::ByteConversion;

impl Context{
    // This method samples a random degree-(2t,t) bivariate polynomial given a set of secrets to encode within it. 
    // Returns (a,b,c) - a is the set of evaluations on row polynomials on the given evaluation points, 
    // b is the set of evaluations on the column polynomials on the given evaluation points
    // c is the set of coefficients of row polynomials. 
    // instance_id acts the prf seed for generating shares randomly
    pub fn sample_bivariate_polynomial_with_prf(
        num_faults: usize,
        num_nodes:usize, 
        sec_key_map: HashMap<Replica, Vec<u8>>,
        large_field_uv_sss: ShamirSecretSharing,
        secret_poly_coeffs: Option<Vec<LargeField>>, 
        evaluation_pts: Vec<LargeField>, 
        prf_seed: Vec<u8>
    )->(Vec<Vec<LargeField>>, Vec<Vec<LargeField>>,Vec<Vec<LargeField>>){
        let eval_pts_len = evaluation_pts.len();
        let mut row_coefficients = Vec::new();
        // Is it a fully random polynomial or should some secrets be encoded in the polynomial?
        let secret_encoded = secret_poly_coeffs.is_some();
        if secret_encoded{
            row_coefficients.push(secret_poly_coeffs.unwrap());
        }
        for rep in 0..num_faults{
            let mut sec_key = sec_key_map.get(&rep).unwrap().clone();
            sec_key.extend(prf_seed.clone());
            
            let sampled_coefficients: Vec<LargeField> = pseudorandom_lw(sec_key.as_slice(), 2*num_faults+1);
            row_coefficients.push(sampled_coefficients);
        }
        if !secret_encoded{
            // First polynomial must be randomly sampled
            let mut first_poly = Vec::new();
            for _ in 0..2*num_faults+1{
                first_poly.push(ShamirSecretSharing::rand_field_element());
            }
            row_coefficients.push(first_poly);
        }
        //let eval_points = (1..self.num_nodes+1).into_iter().map(|el| LargeField::from(el)).collect();
        let (mut row_evals,col_evals) = Self::generate_row_column_evaluations(
            &row_coefficients, 
            evaluation_pts,
            &large_field_uv_sss,
            true 
        );
        // Fill remaining row polynomials
        for point in num_faults+1..num_nodes+1{
            let mut row_poly_evaluations = Vec::new();
            for index in 0..eval_pts_len{
                row_poly_evaluations.push(col_evals[index][point].clone());
            }
            row_evals.push(row_poly_evaluations);
        }
        (row_evals,col_evals, row_coefficients)
    }

    pub fn generate_row_column_evaluations(coefficients: &Vec<Vec<LargeField>>, 
            eval_points: Vec<LargeField>, 
            large_field_shamir_context: &ShamirSecretSharing,
            fill_columns: bool
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
                let evaluation = large_field_shamir_context.evaluate_at_lf(&Polynomial::new(&coefficient_vec.as_slice()), point);
                row_evaluations[index].push(evaluation.clone());
                column_evaluations[index_p].push(evaluation);
            }
        }
        if fill_columns{
            for index in 0..column_evaluations.len(){
                large_field_shamir_context.fill_evaluation_at_all_points(&mut column_evaluations[index]);
                assert!(large_field_shamir_context.verify_degree(&mut column_evaluations[index]));
            }
        }
        return (row_evaluations,column_evaluations);
    }
    
    pub fn sample_univariate_polynomial(&self) -> Vec<LargeField>{
        let mut coeffs = Vec::new();
        for _ in 0..self.num_faults+1{
            coeffs.push(ShamirSecretSharing::rand_field_element());
        }
        coeffs
    }

    pub fn interpolate_points_on_share_poly(&self, 
        comm: Commitment, 
        points: HashMap<Replica,PointsBV>,
        col:bool,
        evaluation_points: Vec<LargeField>)-> Option<Vec<(Vec<Vec<LargeField>>, Vec<LargeField>)>>{
        
        let threshold;
        if col{
            threshold = self.num_faults+1;
        }
        else {
            threshold = 2*self.num_faults+1;
        }
        let mut verified_points: Vec<Vec<Vec<LargeField>>> = Vec::new();
        let mut indices_verified_points: HashSet<Replica> = HashSet::default();
        let mut nonce_points: Vec<Vec<LargeField>> = Vec::new();
        for _ in 0..comm.roots.len(){
            let mut verified_points_bv = Vec::new();
            for _ in 0..comm.batch_count{
                verified_points_bv.push(Vec::new());
            }
            verified_points.push(verified_points_bv);
            nonce_points.push(Vec::new());
        }
        let mut total_points = 0;
        for rep in 0..self.num_nodes{
            if !points.contains_key(&(rep+1)){
                continue;
            }
            let col_points = points.get(&(rep+1)).unwrap();
            let roots_vec: Vec<Hash>;
            if col{
                roots_vec = comm.roots.iter().map(|batch_root_vec| batch_root_vec[self.myid].clone()).collect();
            }
            else {
                roots_vec = comm.roots.iter().map(|batch_root_vec| batch_root_vec[rep].clone()).collect();
            }
            let verf_status = col_points.verify_points(roots_vec, &self.hash_context);
            if verf_status.is_some(){
                // Add this point to the set of points to reconstruct
                // Commitments of points
                for (index,(eval_points,nonce_point)) in (0..comm.roots.len()).into_iter().zip(col_points.evaluations.iter().zip(col_points.nonce_evaluation.iter())){
                    for (iindex, eval_point) in (0..comm.batch_count).into_iter().zip(eval_points.into_iter()){
                        verified_points[index][iindex].push(eval_point.clone());
                    }
                    nonce_points[index].push(nonce_point.clone());
                }
                indices_verified_points.insert(rep+1);
                total_points +=1;
                if total_points >= threshold{
                    break;
                }
            }
            else {
                log::error!("Error verifying Merkle proofs of point on column sent by {}",rep);
            }
        }
        if total_points < threshold{
            log::error!("Not enough points received for polynomial interpolation, waiting for more shares");
            return None;
        }

        // Construct Vandermonde inverse matrix for the given set of indices
        let mut indices_vec: Vec<usize> = indices_verified_points.iter().map(|el| el.clone()).collect();
        indices_vec.sort();
        let mut indices_lf: Vec<LargeField> = indices_verified_points.iter().map(|el| LargeField::from(*el as u64)).collect();
        indices_lf.sort();
        let vandermonde_matrix = self.large_field_uv_sss.vandermonde_matrix(&indices_lf);
        let inverse_vandermonde = self.large_field_uv_sss.inverse_vandermonde(vandermonde_matrix);

        // Shares and nonces of each replica
        let mut share_map: Vec<(Vec<Vec<LargeField>>, Vec<LargeField>)> = Vec::new();
        
        for _ in evaluation_points.iter(){
            let mut shares_batch = Vec::new();
            let num_batches = comm.roots.len();
            for _ in 0..num_batches{
                shares_batch.push(Vec::new());
            }
            share_map.push((shares_batch,Vec::new()));
        }

        // Reconstruct column polynomials and construct commitments
        let mut batch_index = 0;
        for (eval_points_batch_wise, nonce_points_batch_wise) in verified_points.into_iter().zip(nonce_points.into_iter()){
            let nonce_interpolated_batch_coeffs = self.large_field_uv_sss.polynomial_coefficients_with_vandermonde_matrix(&inverse_vandermonde, &nonce_points_batch_wise);
            
            for (index, eval_index) in (0..evaluation_points.len()).zip(evaluation_points.clone().into_iter()){
                let eval_point = self.large_field_uv_sss.evaluate_at_lf(&nonce_interpolated_batch_coeffs, eval_index);
                share_map[index].1.push(eval_point);
            }

            for eval_points_single_bv in eval_points_batch_wise.into_iter(){
                let single_bv_coefficients = self.large_field_uv_sss.polynomial_coefficients_with_vandermonde_matrix(&inverse_vandermonde, &eval_points_single_bv);

                for (index,eval_index) in (0..evaluation_points.len()).zip(evaluation_points.clone().into_iter()){
                    let eval_point = self.large_field_uv_sss.evaluate_at_lf(&single_bv_coefficients, eval_index);
                    share_map[index].0[batch_index].push(eval_point);
                }
            }
            batch_index +=1;
        }
        Some(share_map)
    }
}