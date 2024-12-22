use crypto::{aes_hash::{MerkleTree, Proof}, LargeField, hash::{Hash, do_hash}, LargeFieldSer};
use num_bigint_dig::BigInt;
use types::Replica;

use crate::{Context, VACommitment, LargeFieldSSS, DZKProof};


impl Context{
    // Distributed Zero Knowledge Proofs follow a recursive structure. 
    pub fn gen_dzk_proof(&self, eval_points: &mut Vec<Vec<(BigInt,BigInt)>>, trees: &mut Vec<MerkleTree>, coefficients: Vec<BigInt>, iteration: usize, root: Hash) -> Vec<LargeField>{
        if coefficients.len()-1 <= self.end_degree{
            return coefficients;
        }
        // 1. Create a Merkle Tree if the polynomial is big enough
        let evaluations: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|x| self.large_field_uv_sss.mod_evaluate_at(&coefficients, x)).collect();
        let hashes: Vec<Hash> = evaluations.iter().map(|x| do_hash(x.to_signed_bytes_be().as_slice())).collect();
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
        let g_vals: Vec<(LargeField,LargeField)> = (1..self.num_nodes+1).into_iter().map(|rep| 
            (self.large_field_uv_sss.mod_evaluate_at(&first_half_coeff, rep),
            self.large_field_uv_sss.mod_evaluate_at(&second_half_coeff, rep))
        ).collect();
        eval_points.push(g_vals.clone());
        
        // 4. Compute coefficients for next iteration
        
        // 4.a. Compute updated Merkle root
        let next_root = self.hash_context.hash_two(root, next_root);
        let root_bint = BigInt::from_signed_bytes_be(next_root.as_slice()) % &self.large_field_uv_sss.prime;
        
        let mut poly_folded:Vec<BigInt> = second_half_coeff.into_iter().map(|coeff| (coeff*&root_bint)%&self.large_field_uv_sss.prime).collect();
        for (index, coeff) in (0..first_half_coeff.len()).into_iter().zip(first_half_coeff.into_iter()){
            poly_folded[index] += coeff;
            poly_folded[index] = &poly_folded[index] % &self.large_field_uv_sss.prime;
            if poly_folded[index] < BigInt::from(0){
                poly_folded[index] += &self.large_field_uv_sss.prime;
            }
        }
        

        // Fifth and Finally, recurse until degree reaches a constant
        return self.gen_dzk_proof(eval_points, trees, poly_folded, iteration+1, aggregated_root_hash);
    }

    pub fn verify_dzk_proof(&self, 
        dzk_proof: DZKProof, 
        dzk_roots: Vec<Hash>, 
        dzk_poly: Vec<LargeFieldSer>, 
        column_root: Hash, 
        row_share: BigInt, 
        blinding_row_share: BigInt, 
        rep: Replica
    ) -> bool{

        let zero = BigInt::from(0);

        // Verify dzk proof finally
        // Start from the lowest level
        // Calculate aggregated roots first
        let mut rev_agg_roots: Vec<Hash> = Vec::new();
        let mut rev_roots: Vec<Hash> = Vec::new();

        let root_bint = BigInt::from_signed_bytes_be(column_root.as_slice());
        let mut dzk_share = (blinding_row_share + root_bint*row_share) % &self.large_field_uv_sss.prime;
        
        if dzk_share < BigInt::from(0){
            dzk_share += &self.large_field_uv_sss.prime;
        }
        
        // First root comes from the share and blinding polynomials
        let mut agg_root = column_root;
        let mut aggregated_roots = Vec::new();
        for index in 0..dzk_roots.len(){
            agg_root = self.hash_context.hash_two(agg_root , dzk_roots[index]);
            aggregated_roots.push(agg_root.clone());
        }
        rev_agg_roots.extend(aggregated_roots.into_iter().rev());
        rev_roots.extend(dzk_roots.into_iter().rev());
        
        let first_poly: Vec<BigInt> = dzk_poly.into_iter().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
        let mut degree_poly = first_poly.len()-1;

        // Evaluate points according to this polynomial
        let mut point = self.large_field_uv_sss.mod_evaluate_at(first_poly.as_slice(), rep+1);

        let g_0_pts: Vec<BigInt> = dzk_proof.g_0_x.into_iter().rev().map(|x | BigInt::from_signed_bytes_be(x.as_slice())).collect();
        let g_1_pts: Vec<BigInt> = dzk_proof.g_1_x.into_iter().rev().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
        let proofs: Vec<Proof> = dzk_proof.proof.into_iter().rev().collect();
        
        for (index, (g_0, g_1)) in (0..g_0_pts.len()).into_iter().zip(g_0_pts.into_iter().zip(g_1_pts.into_iter())){
            
            
            // First, Compute Fiat-Shamir Heuristic point
            // log::info!("Aggregated Root Hash: {:?}, g_0: {:?}, g_1: {:?}, poly_folded: {:?}", rev_agg_root_vec[index], g_0, g_1, first_poly);
            let root = BigInt::from_signed_bytes_be(rev_agg_roots[index].as_slice())% &self.large_field_uv_sss.prime;
            
            let mut fiat_shamir_hs_point = (&g_0 + &root*&g_1)%&self.large_field_uv_sss.prime;
            if fiat_shamir_hs_point < zero{
                fiat_shamir_hs_point += &self.large_field_uv_sss.prime;
            }
            if point != fiat_shamir_hs_point{
                log::error!("DZK Proof verification failed at verifying equality of Fiat-Shamir heuristic at iteration {}",index);
                return false;
            }

            // Second, modify point to reflect the value before folding
            // Where was the polynomial split?
            let split_point = *self.poly_length_split_points_map.get(&(degree_poly as isize)).unwrap() as usize;

            let pt_bigint = BigInt::from(rep+1);
            let pow_bigint = LargeFieldSSS::mod_pow(&pt_bigint,&BigInt::from(split_point), &self.large_field_uv_sss.prime);
            let mut agg_point = (&g_0 + &pow_bigint*&g_1)%&self.large_field_uv_sss.prime;
            if agg_point < zero{
                agg_point += &self.large_field_uv_sss.prime;
            }
            point = agg_point;
            // update degree of the current polynomial
            degree_poly = degree_poly + split_point;

            // Third, check Merkle Proof of point
            let merkle_proof = &proofs[index];
            if !merkle_proof.validate(
                &self.hash_context) || 
                    do_hash(point.to_signed_bytes_be().as_slice()) !=  merkle_proof.item()|| 
                    rev_roots[index] != merkle_proof.root(){
                log::error!("DZK Proof verification failed while verifying Merkle Proof validity at iteration {}", index);
                log::error!("Merkle root matching: computed: {:?}  given: {:?}",rev_roots[index].clone(),merkle_proof.root());
                log::error!("Items: {:?}  given: {:?}",merkle_proof.item(),do_hash(point.to_signed_bytes_be().as_slice()));
                return false; 
            }
        }
        // Verify final point's equality with the original accumulated point
        if point != dzk_share{
            log::error!("DZK Point does not match the first level point {:?} {:?} for {}'s column", point, dzk_share, rep);
            return false;
        }
        true
    }

    pub fn verify_dzk_proof_batch(&self, dzk_proofs: Vec<DZKProof>, comm: VACommitment, column_roots: Vec<Hash>, row_shares: Vec<BigInt>, blinding_row_shares: Vec<BigInt>)-> bool{
        
        let zero = BigInt::from(0);

        // Verify dzk proof finally
        // Start from the lowest level
        let roots = comm.dzk_roots.clone();
        // Calculate aggregated roots first
        let mut rev_agg_roots: Vec<Vec<Hash>> = Vec::new();
        let mut rev_roots: Vec<Vec<Hash>> = Vec::new();

        let mut dzk_shares = Vec::new();
        for ((ind_roots,first_root),(share,blinding)) in 
                (roots.into_iter().zip(column_roots.into_iter())).zip(
                    row_shares.into_iter().zip(blinding_row_shares.into_iter())
            ){
            let root_bint = BigInt::from_signed_bytes_be(first_root.as_slice());
            let mut dzk_share = (blinding + root_bint*share) % &self.large_field_uv_sss.prime;
            
            if dzk_share < BigInt::from(0){
                dzk_share += &self.large_field_uv_sss.prime;
            }
            
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
                    (dzk_proofs.into_iter().zip(comm.polys.into_iter())).zip(
                        (rev_agg_roots.into_iter().zip(rev_roots.into_iter())).zip(dzk_shares.into_iter())
                    ){
            // These are the coefficients of the polynomial
            //log::info!("DZK verification Hashes {:?} for rep {}", rev_agg_root_vec, rep);
            let first_poly: Vec<BigInt> = first_poly.into_iter().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let mut degree_poly = first_poly.len()-1;
            // Evaluate points according to this polynomial
            let mut point = self.large_field_uv_sss.mod_evaluate_at(first_poly.as_slice(), self.myid+1);

            let g_0_pts: Vec<BigInt> = dzk_proof.g_0_x.into_iter().rev().map(|x | BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let g_1_pts: Vec<BigInt> = dzk_proof.g_1_x.into_iter().rev().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let proofs: Vec<Proof> = dzk_proof.proof.into_iter().rev().collect();
            
            for (index, (g_0, g_1)) in (0..g_0_pts.len()).into_iter().zip(g_0_pts.into_iter().zip(g_1_pts.into_iter())){
                
                
                // First, Compute Fiat-Shamir Heuristic point
                // log::info!("Aggregated Root Hash: {:?}, g_0: {:?}, g_1: {:?}, poly_folded: {:?}", rev_agg_root_vec[index], g_0, g_1, first_poly);
                let root = BigInt::from_signed_bytes_be(rev_agg_root_vec[index].as_slice())% &self.large_field_uv_sss.prime;
                
                let mut fiat_shamir_hs_point = (&g_0 + &root*&g_1)%&self.large_field_uv_sss.prime;
                if fiat_shamir_hs_point < zero{
                    fiat_shamir_hs_point += &self.large_field_uv_sss.prime;
                }
                if point != fiat_shamir_hs_point{
                    log::error!("DZK Proof verification failed at verifying equality of Fiat-Shamir heuristic at iteration {}",index);
                    return false;
                }

                // Second, modify point to reflect the value before folding
                // Where was the polynomial split?
                let split_point = *self.poly_length_split_points_map.get(&(degree_poly as isize)).unwrap() as usize;

                let pt_bigint = BigInt::from(self.myid+1);
                let pow_bigint = LargeFieldSSS::mod_pow(&pt_bigint,&BigInt::from(split_point), &self.large_field_uv_sss.prime);
                let mut agg_point = (&g_0 + &pow_bigint*&g_1)%&self.large_field_uv_sss.prime;
                if agg_point < zero{
                    agg_point += &self.large_field_uv_sss.prime;
                }
                point = agg_point;
                // update degree of the current polynomial
                degree_poly = degree_poly + split_point;

                // Third, check Merkle Proof of point
                let merkle_proof = &proofs[index];
                if !merkle_proof.validate(
                    &self.hash_context) || 
                        do_hash(point.to_signed_bytes_be().as_slice()) !=  merkle_proof.item()|| 
                        rev_root_vec[index] != merkle_proof.root(){
                    log::error!("DZK Proof verification failed while verifying Merkle Proof validity at iteration {}", index);
                    log::error!("Merkle root matching: computed: {:?}  given: {:?}",rev_root_vec[index].clone(),merkle_proof.root());
                    log::error!("Items: {:?}  given: {:?}",merkle_proof.item(),do_hash(point.to_signed_bytes_be().as_slice()));
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
}