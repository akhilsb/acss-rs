use std::collections::HashMap;

use crypto::{aes_hash::{MerkleTree, Proof, HashState}, LargeField, hash::{Hash, do_hash}, LargeFieldSer};
use lambdaworks_math::{traits::ByteConversion, unsigned_integer::element::UnsignedInteger};
use types::Replica;

use crate::{LargeFieldSSS, DZKProof, PointBV};


pub struct FoldingDZKContext{
    pub large_field_uv_sss: LargeFieldSSS,
    pub hash_context: HashState,
    pub poly_split_evaluation_map: HashMap<isize,isize>,
    pub evaluation_points: Vec<usize>,
    pub recon_threshold: usize,
    pub end_degree_threshold: usize,
}

impl FoldingDZKContext{
    // Distributed Zero Knowledge Proofs follow a recursive structure. 
    pub fn gen_dzk_proof(&self, 
        eval_points: &mut Vec<Vec<(LargeField,LargeField)>>, 
        trees: &mut Vec<MerkleTree>, 
        coefficients: Vec<LargeField>, 
        iteration: usize, 
        root: Hash
    ) -> Vec<LargeField>{
        if coefficients.len()-1 <= self.end_degree_threshold{
            return coefficients;
        }
        
        // 1. Create a Merkle Tree if the polynomial is big enough
        let evaluations: Vec<LargeField> = self.evaluation_points.clone().into_iter().map(|x| self.large_field_uv_sss.mod_evaluate_at(&coefficients, x)).collect();
        let hashes: Vec<Hash> = evaluations.iter().map(|x| do_hash(x.to_bytes_be().as_slice())).collect();
        let merkle_tree = MerkleTree::new(hashes, &self.hash_context);
        let next_root = merkle_tree.root();
        let aggregated_root_hash = self.hash_context.hash_two(root, merkle_tree.root().clone());
        trees.push(merkle_tree);

        // 2. Split polynomial in half
        let mut first_half_coeff = coefficients.clone();
        let degree = coefficients.len()-1;
        let split_point;
        if degree % 2 == 0{
            split_point = degree/2;
        }
        else{
            split_point = (degree+1)/2;
        }
        let second_half_coeff = first_half_coeff.split_off(split_point);
        
        // 3. Calculate evaluation points on both split polynomials
        let g_vals: Vec<(LargeField,LargeField)> = self.evaluation_points.clone().into_iter().map(|rep| 
            (self.large_field_uv_sss.mod_evaluate_at(&first_half_coeff, rep),
            self.large_field_uv_sss.mod_evaluate_at(&second_half_coeff, rep))
        ).collect();
        eval_points.push(g_vals.clone());
        
        // 4. Compute coefficients for next iteration
        
        // 4.a. Compute updated Merkle root
        let next_root = self.hash_context.hash_two(root, next_root);
        let root_bint = LargeField::from_bytes_be(next_root.as_slice()).unwrap();
        
        let mut poly_folded:Vec<LargeField> = second_half_coeff.into_iter().map(|coeff| (coeff*&root_bint)).collect();
        for (index, coeff) in (0..first_half_coeff.len()).into_iter().zip(first_half_coeff.into_iter()){
            poly_folded[index] += coeff;
        }
        

        // Fifth and Finally, recurse until degree reaches a constant
        return self.gen_dzk_proof(eval_points, trees, poly_folded, iteration+1, aggregated_root_hash);
    }

    pub fn verify_dzk_proofs_column(&self, 
        dzk_roots: Vec<Hash>, 
        dzk_poly: Vec<LargeFieldSer>, 
        bv_ready_points: HashMap<Replica,PointBV>,
        instance_id: usize,
    )-> Option<(Vec<Vec<LargeField>>, Vec<LargeField>, Vec<LargeField>, Vec<LargeField>)>{
        let mut column_evaluation_points = Vec::new();
        let mut nonce_evaluation_points = Vec::new();

        let mut blinding_evaluation_points = Vec::new();
        let mut blinding_nonce_points = Vec::new();

        //let bv_echo_points = acss_va_state.bv_echo_points.clone();
        //let dzk_roots = comm.dzk_roots[self.myid].clone();
        //let dzk_poly = comm.polys[self.myid].clone();
        let mut valid_indices = Vec::new();
        for rep in self.evaluation_points.clone().into_iter(){
            if bv_ready_points.contains_key(&rep){
                let (column_share,bcolumn_share, dzk_iter) = bv_ready_points.get(&rep).unwrap();
                // Combine column and blinding column roots
                let combined_root = self.hash_context.hash_two(column_share.2.root(), bcolumn_share.2.root());
                
                let deser_points: Vec<LargeField> = column_share.0.clone().into_iter().map(|el| LargeField::from_bytes_be(el.as_slice()).unwrap()).collect();
                let agg_point = self.gen_agg_poly_dzk(deser_points.clone(), combined_root.clone());

                let nonce = LargeField::from_bytes_be(column_share.1.as_slice()).unwrap();

                let blinding_point = LargeField::from_bytes_be(bcolumn_share.0.as_slice()).unwrap(); 
                let blinding_nonce = LargeField::from_bytes_be(bcolumn_share.1.as_slice()).unwrap();

                if self.verify_dzk_proof(dzk_iter.clone() , 
                                        dzk_roots.clone(), 
                                        dzk_poly.clone(), 
                                        combined_root, 
                                        agg_point.clone(), 
                                        blinding_point.clone(), 
                                        rep){
                    valid_indices.push(LargeField::from(rep as u64));
                    column_evaluation_points.push(deser_points);
                    nonce_evaluation_points.push(nonce);

                    blinding_evaluation_points.push(blinding_point.clone());
                    blinding_nonce_points.push( blinding_nonce);
                }
                
                if column_evaluation_points.len() == self.recon_threshold{
                    break;
                }
            }
        }

        if column_evaluation_points.len() < self.recon_threshold {
            log::error!("Did not receive enough valid points from other parties, abandoning ACSS {}", instance_id);
            return None;
        }
        log::info!("Successfully verified commitments and dZK proofs for column polynomial of ACSS instance {}",instance_id);
        // Re borrow here
        //let acss_va_state = self.acss_state.get_mut(&instance_id).unwrap();

        // Interpolate column
        // Compute Vandermonde matrix here once. No other choice but to compute. If we have to interpolate the entire column, then it must cost O(n^3) operations
        let vandermonde_matrix_lt =  LargeFieldSSS::vandermonde_matrix(valid_indices);
        let inverse_vandermonde = LargeFieldSSS::inverse_vandermonde(vandermonde_matrix_lt);

        let poly_coeffs: Vec<Vec<LargeField>> = column_evaluation_points.into_iter().map(|poly| self.large_field_uv_sss.polynomial_coefficients_with_vandermonde_matrix(&inverse_vandermonde, &poly)).collect();
        //let poly_coeffs = self.large_field_uv_sss.polynomial_coefficients_with_precomputed_vandermonde_matrix(&column_evaluation_points);
        let nonce_coeffs = self.large_field_uv_sss.polynomial_coefficients_with_vandermonde_matrix(&inverse_vandermonde,&nonce_evaluation_points);

        let bpoly_coeffs = self.large_field_uv_sss.polynomial_coefficients_with_precomputed_vandermonde_matrix(&blinding_evaluation_points);
        let bnonce_coeffs = self.large_field_uv_sss.polynomial_coefficients_with_precomputed_vandermonde_matrix(&blinding_nonce_points);

        return Some((poly_coeffs,nonce_coeffs,bpoly_coeffs,bnonce_coeffs));
    }

    pub fn verify_dzk_proof_alt(&self,
        dzk_proof: DZKProof, 
        dzk_roots: Vec<Hash>, 
        dzk_poly: Vec<LargeFieldSer>, 
        column_root: Hash, 
        row_share: LargeField,
        evaluation_point: usize
    ) -> bool{
        // Verify dzk proof finally
        // Start from the lowest level
        // Calculate aggregated roots first
        let mut rev_agg_roots: Vec<Hash> = Vec::new();
        let mut rev_roots: Vec<Hash> = Vec::new();

        let dzk_share = row_share;
        
        // First root comes from the share and blinding polynomials
        let mut agg_root = column_root;
        let mut aggregated_roots = Vec::new();
        for index in 0..dzk_roots.len(){
            agg_root = self.hash_context.hash_two(agg_root , dzk_roots[index]);
            aggregated_roots.push(agg_root.clone());
        }
        rev_agg_roots.extend(aggregated_roots.into_iter().rev());
        rev_roots.extend(dzk_roots.into_iter().rev());
        
        let first_poly: Vec<LargeField> = dzk_poly.into_iter().map(|x| LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
        let mut degree_poly = first_poly.len()-1;

        // Evaluate points according to this polynomial
        let mut point = self.large_field_uv_sss.mod_evaluate_at(first_poly.as_slice(), evaluation_point);

        let g_0_pts: Vec<LargeField> = dzk_proof.g_0_x.into_iter().rev().map(|x | LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
        let g_1_pts: Vec<LargeField> = dzk_proof.g_1_x.into_iter().rev().map(|x| LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
        let proofs: Vec<Proof> = dzk_proof.proof.into_iter().rev().collect();
        
        for (index, (g_0, g_1)) in (0..g_0_pts.len()).into_iter().zip(g_0_pts.into_iter().zip(g_1_pts.into_iter())){
            
            
            // First, Compute Fiat-Shamir Heuristic point
            // log::info!("Aggregated Root Hash: {:?}, g_0: {:?}, g_1: {:?}, poly_folded: {:?}", rev_agg_root_vec[index], g_0, g_1, first_poly);
            let root = LargeField::from_bytes_be(rev_agg_roots[index].as_slice()).unwrap();
            
            let fiat_shamir_hs_point = &g_0 + &root*&g_1;
            if point != fiat_shamir_hs_point{
                log::error!("DZK Proof verification failed at verifying equality of Fiat-Shamir heuristic at iteration {}",index);
                return false;
            }

            // Second, modify point to reflect the value before folding
            // Where was the polynomial split?
            let split_point = *self.poly_split_evaluation_map.get(&(degree_poly as isize)).unwrap() as usize;

            let pt_bigint = LargeField::from(evaluation_point as u64);
            let pow_bigint = pt_bigint.pow(UnsignedInteger::<4>::from(split_point as u64));
            //let pow_bigint = LargeFieldSSS::mod_pow(&pt_bigint,&LargeField::from(split_point), &self.large_field_uv_sss.prime);
            let agg_point = &g_0 + &pow_bigint*&g_1;
            point = agg_point;
            // update degree of the current polynomial
            degree_poly = degree_poly + split_point;

            // Third, check Merkle Proof of point
            let merkle_proof = &proofs[index];
            if !merkle_proof.validate(
                &self.hash_context) || 
                    do_hash(point.to_bytes_be().as_slice()) !=  merkle_proof.item()|| 
                    rev_roots[index] != merkle_proof.root(){
                log::error!("DZK Proof verification failed while verifying Merkle Proof validity at iteration {}", index);
                log::error!("Merkle root matching: computed: {:?}  given: {:?}",rev_roots[index].clone(),merkle_proof.root());
                log::error!("Items: {:?}  given: {:?}",merkle_proof.item(),do_hash(point.to_bytes_be().as_slice()));
                return false; 
            }
        }
        // Verify final point's equality with the original accumulated point
        if point != dzk_share{
            log::error!("DZK Point does not match the first level point {:?} {:?} for {}'s column", point, dzk_share, evaluation_point);
            return false;
        }
        true
    }


    pub fn verify_dzk_proof(&self,
        dzk_proof: DZKProof, 
        dzk_roots: Vec<Hash>, 
        dzk_poly: Vec<LargeFieldSer>, 
        column_root: Hash, 
        row_share: LargeField, 
        blinding_row_share: LargeField, 
        evaluation_point: usize
    ) -> bool{
        // Verify dzk proof finally
        // Start from the lowest level
        // Calculate aggregated roots first
        let mut rev_agg_roots: Vec<Hash> = Vec::new();
        let mut rev_roots: Vec<Hash> = Vec::new();

        let root_bint = LargeField::from_bytes_be(column_root.as_slice()).unwrap();
        let dzk_share = blinding_row_share + root_bint*row_share;
        
        // First root comes from the share and blinding polynomials
        let mut agg_root = column_root;
        let mut aggregated_roots = Vec::new();
        for index in 0..dzk_roots.len(){
            agg_root = self.hash_context.hash_two(agg_root , dzk_roots[index]);
            aggregated_roots.push(agg_root.clone());
        }
        rev_agg_roots.extend(aggregated_roots.into_iter().rev());
        rev_roots.extend(dzk_roots.into_iter().rev());
        
        let first_poly: Vec<LargeField> = dzk_poly.into_iter().map(|x| LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
        let mut degree_poly = first_poly.len()-1;

        // Evaluate points according to this polynomial
        let mut point = self.large_field_uv_sss.mod_evaluate_at(first_poly.as_slice(), evaluation_point);

        let g_0_pts: Vec<LargeField> = dzk_proof.g_0_x.into_iter().rev().map(|x | LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
        let g_1_pts: Vec<LargeField> = dzk_proof.g_1_x.into_iter().rev().map(|x| LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
        let proofs: Vec<Proof> = dzk_proof.proof.into_iter().rev().collect();
        
        for (index, (g_0, g_1)) in (0..g_0_pts.len()).into_iter().zip(g_0_pts.into_iter().zip(g_1_pts.into_iter())){
            
            
            // First, Compute Fiat-Shamir Heuristic point
            // log::info!("Aggregated Root Hash: {:?}, g_0: {:?}, g_1: {:?}, poly_folded: {:?}", rev_agg_root_vec[index], g_0, g_1, first_poly);
            let root = LargeField::from_bytes_be(rev_agg_roots[index].as_slice()).unwrap();
            
            let fiat_shamir_hs_point = &g_0 + &root*&g_1;
            if point != fiat_shamir_hs_point{
                log::error!("DZK Proof verification failed at verifying equality of Fiat-Shamir heuristic at iteration {}",index);
                return false;
            }

            // Second, modify point to reflect the value before folding
            // Where was the polynomial split?
            let split_point = *self.poly_split_evaluation_map.get(&(degree_poly as isize)).unwrap() as usize;

            let pt_bigint = LargeField::from(evaluation_point as u64);
            let pow_bigint = pt_bigint.pow(UnsignedInteger::<4>::from(split_point as u64));
            //let pow_bigint = LargeFieldSSS::mod_pow(&pt_bigint,&LargeField::from(split_point), &self.large_field_uv_sss.prime);
            let agg_point = &g_0 + &pow_bigint*&g_1;
            point = agg_point;
            // update degree of the current polynomial
            degree_poly = degree_poly + split_point;

            // Third, check Merkle Proof of point
            let merkle_proof = &proofs[index];
            if !merkle_proof.validate(
                &self.hash_context) || 
                    do_hash(point.to_bytes_be().as_slice()) !=  merkle_proof.item()|| 
                    rev_roots[index] != merkle_proof.root(){
                log::error!("DZK Proof verification failed while verifying Merkle Proof validity at iteration {}", index);
                log::error!("Merkle root matching: computed: {:?}  given: {:?}",rev_roots[index].clone(),merkle_proof.root());
                log::error!("Items: {:?}  given: {:?}",merkle_proof.item(),do_hash(point.to_bytes_be().as_slice()));
                return false; 
            }
        }
        // Verify final point's equality with the original accumulated point
        if point != dzk_share{
            log::error!("DZK Point does not match the first level point {:?} {:?} for {}'s column", point, dzk_share, evaluation_point);
            return false;
        }
        true
    }

    pub fn verify_dzk_proof_row(&self, 
                        dzk_proofs: Vec<DZKProof>, 
                        dzk_roots: Vec<Vec<Hash>>,
                        dzk_polys: Vec<Vec<LargeFieldSer>>, 
                        column_roots: Vec<Hash>, 
                        row_shares: Vec<LargeField>, 
                        blinding_row_shares: Vec<LargeField>,
                        evaluation_point: usize
                    )-> bool{
        // Verify dzk proof finally
        // Start from the lowest level
        let roots = dzk_roots.clone();
        // Calculate aggregated roots first
        let mut rev_agg_roots: Vec<Vec<Hash>> = Vec::new();
        let mut rev_roots: Vec<Vec<Hash>> = Vec::new();

        let mut dzk_shares = Vec::new();
        for ((ind_roots,first_root),(share,blinding)) in 
                (roots.into_iter().zip(column_roots.into_iter())).zip(
                    row_shares.into_iter().zip(blinding_row_shares.into_iter())
            ){
            let root_bint = LargeField::from_bytes_be(first_root.as_slice()).unwrap();
            let dzk_share = blinding + root_bint*share;
            
            dzk_shares.push(dzk_share);
            // First root comes from the share and blinding polynomials
            let mut agg_root = first_root;
            let mut aggregated_roots = Vec::new();
            for index in 0..ind_roots.len(){
                agg_root = self.hash_context.hash_two(agg_root , ind_roots[index]);
                aggregated_roots.push(agg_root.clone());
            }
            rev_agg_roots.push(aggregated_roots.into_iter().rev().collect());
            rev_roots.push(ind_roots.into_iter().rev().collect());
        }
        let mut _rep = 0;
        for ((dzk_proof, first_poly),((rev_agg_root_vec,rev_root_vec),dzk_share)) in 
                    (dzk_proofs.into_iter().zip(dzk_polys.into_iter())).zip(
                        (rev_agg_roots.into_iter().zip(rev_roots.into_iter())).zip(dzk_shares.into_iter())
                    ){
            // These are the coefficients of the polynomial
            //log::info!("DZK verification Hashes {:?} for rep {}", rev_agg_root_vec, rep);
            let first_poly: Vec<LargeField> = first_poly.into_iter().map(|x| LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
            let mut degree_poly = first_poly.len()-1;
            // Evaluate points according to this polynomial
            let mut point = self.large_field_uv_sss.mod_evaluate_at(first_poly.as_slice(), evaluation_point);

            let g_0_pts: Vec<LargeField> = dzk_proof.g_0_x.into_iter().rev().map(|x | LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
            let g_1_pts: Vec<LargeField> = dzk_proof.g_1_x.into_iter().rev().map(|x| LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
            let proofs: Vec<Proof> = dzk_proof.proof.into_iter().rev().collect();
            
            for (index, (g_0, g_1)) in (0..g_0_pts.len()).into_iter().zip(g_0_pts.into_iter().zip(g_1_pts.into_iter())){
                
                
                // First, Compute Fiat-Shamir Heuristic point
                // log::info!("Aggregated Root Hash: {:?}, g_0: {:?}, g_1: {:?}, poly_folded: {:?}", rev_agg_root_vec[index], g_0, g_1, first_poly);
                let root = LargeField::from_bytes_be(rev_agg_root_vec[index].as_slice()).unwrap();
                
                let fiat_shamir_hs_point = &g_0 + &root*&g_1;
                if point != fiat_shamir_hs_point{
                    log::error!("DZK Proof verification failed at verifying equality of Fiat-Shamir heuristic at iteration {}",index);
                    return false;
                }

                // Second, modify point to reflect the value before folding
                // Where was the polynomial split?
                let split_point = *self.poly_split_evaluation_map.get(&(degree_poly as isize)).unwrap() as usize;

                let pt_bigint = LargeField::from(evaluation_point as u64);
                let pow_bigint = pt_bigint.pow(UnsignedInteger::<4>::from(split_point as u64));
                let agg_point = &g_0 + &pow_bigint*&g_1;
                
                point = agg_point;
                // update degree of the current polynomial
                degree_poly = degree_poly + split_point;

                // Third, check Merkle Proof of point
                let merkle_proof = &proofs[index];
                if !merkle_proof.validate(
                    &self.hash_context) || 
                        do_hash(point.to_bytes_be().as_slice()) !=  merkle_proof.item()|| 
                        rev_root_vec[index] != merkle_proof.root(){
                    log::error!("DZK Proof verification failed while verifying Merkle Proof validity at iteration {}", index);
                    log::error!("Merkle root matching: computed: {:?}  given: {:?}",rev_root_vec[index].clone(),merkle_proof.root());
                    log::error!("Items: {:?}  given: {:?}",merkle_proof.item(),do_hash(point.to_bytes_be().as_slice()));
                    return false; 
                }
            }
            // Verify final point's equality with the original accumulated point
            if point != dzk_share{
                log::error!("DZK Point does not match the first level point {:?} {:?} for {}'s column", point, dzk_share, _rep);
                return false;
            }
            _rep+=1;
        }
        true
    }
    
    pub fn gen_agg_poly_dzk(&self, evaluations: Vec<LargeField>, root: Hash)-> LargeField{

        let mut root_mul_lf: LargeField = LargeField::from_bytes_be(root.as_slice()).unwrap();
        let root_original = root_mul_lf.clone();
        let mut aggregated_val = LargeField::from(0);

        root_mul_lf = LargeField::from(1);
        for share in evaluations{
            aggregated_val += &root_mul_lf*share;
            
            root_mul_lf = &root_mul_lf*&root_original;
        }
        aggregated_val
    }
}