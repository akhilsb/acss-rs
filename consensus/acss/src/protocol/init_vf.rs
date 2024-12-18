use crypto::aes_hash::MerkleTree;
use crypto::hash::do_hash;
use crypto::{LargeField};
use num_bigint_dig::RandBigInt;
use num_bigint_dig::BigInt;

use crate::Context;

impl Context{
    /**
     * ACSS protocol layout.
     * 
     * 1. Shamir secret sharing. Split secrets into shares. 
     * 2. Sample random blinding (b(x)), nonce (y(x)), and blinding nonce polynomials(y_0(x))
     * 3. Generate commitments to shares and the blinding polynomial. 
     * 4. Compute succinct commitment
     * 5. Generate distributed ZK polynomial
     * 6. Encrypt shares and broadcast commitments.  
    */
    pub async fn init_verifiable_abort(self: &mut Context, secret: LargeField, _instance_id: usize, _threshold: usize){
        
        let field_prime = self.large_field_bv_sss.prime.clone();
        let zero = BigInt::from(0);
        
        // Sample bivariate polynomial
        // degree-2t row polynomial and degree-t column polynomial

        // Sample degree-t polynomial
        let mut secret_poly_y_deg_t = Vec::new();
        secret_poly_y_deg_t.push(secret.clone());
        
        for _rep in 0..self.num_faults{
            let share = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
            // let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            // // Add ID to seed
            // secret_key.extend(instance_id.to_be_bytes());
            // // Sample random value
            // let field_elem = pseudorandom_lf(secret_key.as_slice(), 1);
            // let share = field_elem[0]%&field_prime;
            // if share < zero{
            //     share += &field_prime;
            // }
            secret_poly_y_deg_t.push(share);
        }
        // Extend polynomial to all n values
        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut secret_poly_y_deg_t);
        
        // Fill polynomial on x-axis as well
        let mut secret_poly_x_deg_2t = Vec::new();
        secret_poly_x_deg_2t.push(secret);
        
        for _rep in 0..2*self.num_faults+1{
            // Sample random values
            let rand_bint = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
            secret_poly_x_deg_2t.push(rand_bint);
        }

        self.large_field_bv_sss.fill_evaluation_at_all_points(&mut secret_poly_x_deg_2t);
        
        // polys_x_deg_2t and polys_y_deg_t have structure (n+1*n) points.
        // Sample t degree-2t bivariate polynomials
        let mut polys_x_deg_2t = Vec::new();
        for rep in 0..self.num_nodes{
            let share = secret_poly_y_deg_t[rep+1].clone();
            let mut poly_x_deg_2t = Vec::new();
            poly_x_deg_2t.push(share);
            polys_x_deg_2t.push(poly_x_deg_2t);
        }

        // Keep track of corresponding column polynomials
        let mut polys_y_deg_t = Vec::new();
        for rep in 0..self.num_nodes{
            let share = secret_poly_x_deg_2t[rep+1].clone();
            let mut poly_y_deg_t = Vec::new();
            poly_y_deg_t.push(share);
            polys_y_deg_t.push(poly_y_deg_t);
        }

        for rep in 0..self.num_faults{
            // Sample 2t points then
            for _ in 0..2*self.num_faults{
                polys_x_deg_2t[rep].push(rand::thread_rng().gen_bigint_range(&zero, &field_prime));
            }
            self.large_field_bv_sss.fill_evaluation_at_all_points(&mut polys_x_deg_2t[rep]);
            for index in 0..self.num_nodes{
                polys_y_deg_t[index].push(polys_x_deg_2t[rep][index+1].clone());
            }
        }

        // Extend all degree-t polynomials to n points
        // Generate Coefficients of these polynomials
        let mut coefficients_y_deg_t = Vec::new();
        for rep in 0..self.num_nodes{
            let poly_eval_pts:Vec<(BigInt,BigInt)> = (0..self.num_faults+1).into_iter().map(|x| BigInt::from(x)).zip(polys_y_deg_t[rep].clone().into_iter()).collect();
            let coeffs = self.large_field_uv_sss.polynomial_coefficients(&poly_eval_pts);
            coefficients_y_deg_t.push(coeffs.clone());
            self.large_field_uv_sss.fill_evaluation_at_all_points(&mut polys_y_deg_t[rep]);
        }
        // Fill all remaining degree-2t polynomials
        for rep in self.num_faults .. self.num_nodes{
            for index in 0..self.num_nodes{
                polys_x_deg_2t[rep].push(polys_y_deg_t[index][rep+1].clone());
            }
        }

        // 2. Generate commitments: Sample Nonce Polynomials
        let mut nonce_polys = Vec::new();
        for _ in 0..self.num_nodes{
            let mut nonce_poly_y_deg_t  = Vec::new();
            let secret = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
            let shares:Vec<BigInt> = self.large_field_uv_sss.split(secret.clone()).into_iter().map(|x| x.1).collect();
            nonce_poly_y_deg_t.push(secret);
            nonce_poly_y_deg_t.extend(shares); 
            nonce_polys.push(nonce_poly_y_deg_t);
        }
        // Generate commitments
        let mut commitments = Vec::new();
        for (share_y_deg_t,nonce_y_deg_t) in polys_y_deg_t.iter().zip(nonce_polys.iter()){
            let mut comm_y_deg_t = Vec::new();
            for rep in 0..self.num_nodes{
                let mut appended = Vec::new();
                appended.extend(share_y_deg_t[rep+1].clone().to_signed_bytes_be());
                appended.extend(nonce_y_deg_t[rep+1].clone().to_signed_bytes_be());
                comm_y_deg_t.push(do_hash(appended.as_slice()));
            }
            commitments.push(comm_y_deg_t);
        }
        // Generate Merkle Trees
        let mut mts = Vec::new();
        for comm_vector in commitments.clone().into_iter(){
            mts.push(MerkleTree::new(comm_vector, &self.hash_context));
        }
        // A vector of n Merkle Trees

        // 3. Generate Distributed Zero Knowledge Proofs
    }

    // Distributed Zero Knowledge Proofs follow a recursive structure. 
    pub fn gen_dzk_proof(eval_points: Vec<Vec<(BigInt,BigInt)>>, proofs: Vec<MerkleTree>, coefficients: Vec<BigInt>){
        
    }

}