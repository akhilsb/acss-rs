use consensus::LargeFieldSSS;
use crypto::{LargeField, pseudorandom_lf};
use num_bigint_dig::RandBigInt;

use crate::Context;

impl Context{
    // This method samples a random degree-(2t,t) bivariate polynomial given a set of secrets to encode within it. 
    // Returns (a,b,c) - a is the set of evaluations on row polynomials on the given evaluation points, 
    // b is the set of evaluations on the column polynomials on the given evaluation points
    // c is the set of coefficients of row polynomials. 
    // instance_id acts the prf seed for generating shares randomly
    pub fn sample_bivariate_polynomial_with_prf(&self, 
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
        for rep in 0..self.num_faults{
            let mut sec_key = self.sec_key_map.get(&rep).unwrap().clone();
            sec_key.extend(prf_seed.clone());
            
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
            &self.large_field_uv_sss,
            true 
        );
        // Fill remaining row polynomials
        for point in self.num_faults+1..self.num_nodes+1{
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
            large_field_shamir_context: &LargeFieldSSS,
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
                let evaluation = large_field_shamir_context.mod_evaluate_at_lf(&coefficient_vec.as_slice(), point);
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
            coeffs.push(rand::thread_rng().gen_bigint_range(&LargeField::from(0), &self.large_field_bv_sss.prime));
        }
        coeffs
    }
}