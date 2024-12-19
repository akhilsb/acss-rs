use crypto::aes_hash::{MerkleTree, Proof};
use crypto::hash::{do_hash, Hash};
use crypto::{LargeField, LargeFieldSer, encrypt};
use network::Acknowledgement;
use network::plaintcp::CancelHandler;
use num_bigint_dig::RandBigInt;
use num_bigint_dig::BigInt;
use types::{Replica, WrapperMsg};

use crate::{Context, VAShare, VACommitment, ProtMsg, DZKProof, LargeFieldSSS};

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
    pub async fn init_verifiable_abort(self: &mut Context, secret: LargeField, instance_id: usize, _threshold: usize){
        
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
        let mut hashes = Vec::new();
        let mut dzk_broadcast_polys = Vec::new();
        // (Replica, (g_0 values), (g_1 values), (Vector of Merkle Proofs for each g_0,g_1 value))
        let mut shares_proofs_dzk: Vec<(Replica, Vec<DZKProof>)> = Vec::new();
        for rep in 0..self.num_nodes{
            shares_proofs_dzk.push((rep, Vec::new()));
        }
        for coefficient_vec in coefficients_y_deg_t.into_iter(){
            let mut eval_points = Vec::new();
            
            let mut trees: Vec<MerkleTree> = Vec::new();
            //trees.push(mts[rep].clone());
            
            let coefficients = coefficient_vec.clone();
            
            let iteration = 1;
            let root = trees[0].root();
            hashes.push(root.clone());

            // Reliably broadcast these coefficients
            let coeffs_const_size: Vec<Vec<u8>> = self.gen_dzk_proof(&mut eval_points, &mut trees, coefficients, iteration, root).into_iter().map(|x| x.to_signed_bytes_be()).collect();
            
            for tree in trees.iter(){
                hashes.push(tree.root());
            }
            dzk_broadcast_polys.push(coeffs_const_size);

            let mut dzk_proofs_all_nodes = Vec::new();
            for _ in 0..self.num_nodes{
                dzk_proofs_all_nodes.push(DZKProof{
                    g_0_x: Vec::new(),
                    g_1_x: Vec::new(),
                    proof: Vec::new(),
                });
            }

            for (g_0_g_1_shares,mt) in eval_points.into_iter().zip(trees.into_iter()){                
                for (rep,g) in (0..self.num_nodes).into_iter().zip(g_0_g_1_shares.into_iter()){
                    dzk_proofs_all_nodes[rep].g_0_x.push(g.0.to_signed_bytes_be());
                    dzk_proofs_all_nodes[rep].g_1_x.push(g.1.to_signed_bytes_be());
                    dzk_proofs_all_nodes[rep].proof.push(mt.gen_proof(rep));
                }
            }

            for (rep,proof) in (0..self.num_nodes).into_iter().zip(dzk_proofs_all_nodes.into_iter()){
                shares_proofs_dzk[rep].1.push(proof);
            }
        }
        
        let va_comm: VACommitment = VACommitment { 
            roots: hashes, 
            polys: dzk_broadcast_polys 
        };
        

        // 4. Distribute shares through messages
        for (rep, dzk_proofs) in shares_proofs_dzk.into_iter(){
            
            // Craft VAShare message
            polys_x_deg_2t[rep].drain(..0);
            nonce_polys[rep].drain(..0);

            polys_y_deg_t[rep].truncate(self.num_faults+1);

            let row_poly: Vec<(LargeFieldSer,LargeFieldSer, Proof)> = (0..self.num_faults).into_iter().zip(polys_x_deg_2t[rep].iter()).map(|(index, x)| 
                (x.to_signed_bytes_be(),
                nonce_polys[index][rep].clone().to_signed_bytes_be(),
                mts[index].gen_proof(rep))
            ).collect();
            let column_poly: Vec<(LargeFieldSer,LargeFieldSer)> = polys_y_deg_t[rep].iter().zip(nonce_polys[rep].iter()).map(|(share,nonce)| 
                (share.to_signed_bytes_be(),nonce.to_signed_bytes_be())
            ).collect();
            let msg = VAShare{
                row_poly: row_poly,
                column_poly: column_poly,
                dzk_iters: dzk_proofs,
                rep: rep,
            };
            // Encrypt and send message
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            let ser_msg = bincode::serialize(&msg).unwrap();
            let encrypted_msg = encrypt(secret_key.as_slice(), ser_msg);

            let prot_msg_va = ProtMsg::Init(
                encrypted_msg, 
                va_comm.clone(), 
                self.myid,
                instance_id
            );

            let wrapper_msg = WrapperMsg::new(prot_msg_va, self.myid, &secret_key);
            let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }

    // Distributed Zero Knowledge Proofs follow a recursive structure. 
    pub fn gen_dzk_proof(&self, eval_points: &mut Vec<Vec<(BigInt,BigInt)>>, trees: &mut Vec<MerkleTree>, coefficients: Vec<BigInt>, iteration: usize, root: Hash) -> Vec<LargeField>{
        if coefficients.len() < self.end_degree{
            return coefficients;
        }
        // First create a Merkle Tree and the Merkle root
        let evaluations:Vec<LargeField> = (0..self.num_nodes).into_iter().map(|x| self.large_field_uv_sss.mod_evaluate_at(&coefficients, x)).collect();
        let hashes: Vec<Hash> = evaluations.iter().map(|x| do_hash(x.to_signed_bytes_be().as_slice())).collect();
        let merkle_tree = MerkleTree::new(hashes, &self.hash_context);
        
        let aggregated_root_hash = self.hash_context.hash_two(root, merkle_tree.root().clone());
        let mut root = BigInt::from_signed_bytes_be(aggregated_root_hash.as_slice()) % &self.large_field_uv_sss.prime;
        if root < BigInt::from(0){
            root += &self.large_field_uv_sss.prime;
        }
        trees.push(merkle_tree);

        // Second, split polynomial in half
        let mut first_half_coeff = coefficients.clone();
        let degree = coefficients.len()-1;
        let next_degree;
        if degree % 2 == 0{
            next_degree = degree/2;
        }
        else{
            next_degree = (degree+1)/2;
        }
        let second_half_coeff = first_half_coeff.split_off(next_degree);
        let shamir_context = self.dzk_ss.get(&next_degree).unwrap();

        // Third, calculate evaluation points on both split polynomials
        let g_vals: Vec<(LargeField,LargeField)> = (1..self.num_nodes+1).into_iter().map(|rep| 
            (shamir_context.mod_evaluate_at(&first_half_coeff, rep),
            shamir_context.mod_evaluate_at(&second_half_coeff, rep))
        ).collect();
        eval_points.push(g_vals);

        // Fourth, compute coefficients for next iteration
        let mut poly_folded:Vec<BigInt> = second_half_coeff.into_iter().map(|coeff| (coeff*&root)%&shamir_context.prime).collect();
        for (index, coeff) in (0..first_half_coeff.len()).into_iter().zip(first_half_coeff.into_iter()){
            poly_folded[index] += coeff;
            poly_folded[index] = &poly_folded[index] % &shamir_context.prime;
            if poly_folded[index] < BigInt::from(0){
                poly_folded[index] += &shamir_context.prime;
            }
        }

        // Fifth and Finally, recurse until degree reaches a constant
        return self.gen_dzk_proof(eval_points, trees, poly_folded, iteration+1, aggregated_root_hash);
    }

    pub fn verify_dzk_proof(&self, share: VAShare, comm: VACommitment)-> bool{
        
        let zero = BigInt::from(0);

        // Verify Row Commitments
        let mut row_shares = Vec::new();
        for (share, nonce, proof) in share.row_poly.into_iter(){
            let mut app_val = Vec::new();
            app_val.extend(share.clone());
            app_val.extend(nonce);

            let commitment = do_hash(app_val.as_slice());
            if !proof.validate(&self.hash_context) || proof.item() != commitment{
                log::error!("Commitment verification failed");
                return false;
            }
            let share_val = BigInt::from_signed_bytes_be(share.as_slice());
            row_shares.push(share_val);
        }

        // Verify Column commitments next
        let mut column_shares = Vec::new();
        let mut column_nonces = Vec::new();
        for (share, nonce) in share.column_poly.into_iter(){
            column_shares.push(BigInt::from_signed_bytes_be(share.as_slice()));
            column_nonces.push(BigInt::from_signed_bytes_be(nonce.as_slice()));
        }
        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut column_shares);
        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut column_nonces);
        let mut commitments = Vec::new();
        for rep in 0..self.num_nodes{
            let mut app_share = Vec::new();
            app_share.extend(column_shares[rep+1].clone().to_signed_bytes_be());
            app_share.extend(column_nonces[rep+1].clone().to_signed_bytes_be());
            commitments.push(do_hash(app_share.as_slice()));
        }
        // Construct Merkle Tree
        let mt = MerkleTree::new(commitments, &self.hash_context);
        if mt.root() != comm.roots[0]{
            log::error!("Error verifying column polynomial root");
            return false;
        }

        // Verify dzk proof finally
        // Start from the lowest level
        let roots = comm.roots.clone();
        let mut agg_root = roots[0];
        let mut aggregated_roots = Vec::new();
        aggregated_roots.push(agg_root.clone());
        for index in 1..roots.len(){
            agg_root = self.hash_context.hash_two(agg_root , roots[index]);
            aggregated_roots.push(agg_root.clone());
        }
        let rev_agg_roots: Vec<Hash> = aggregated_roots.into_iter().rev().collect();
        let rev_roots: Vec<Hash> = roots.into_iter().rev().collect();
        
        
        for (dzk_proof, first_poly) in share.dzk_iters.into_iter().zip(comm.polys.into_iter()){
            // These are the coefficients of the polynomial
            let first_poly: Vec<BigInt> = first_poly.into_iter().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let degree_poly = first_poly.len();
            let shamir_ss = self.dzk_ss.get(&degree_poly).unwrap();
            // Evaluate points according to this polynomial
            let mut point = shamir_ss.mod_evaluate_at(first_poly.as_slice(), self.myid);

            // First, this point must be equal to the combination of g_0 and g_1
            let g_0_pts: Vec<BigInt> = dzk_proof.g_0_x.into_iter().rev().map(|x | BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let g_1_pts: Vec<BigInt> = dzk_proof.g_1_x.into_iter().rev().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let proofs: Vec<Proof> = dzk_proof.proof.into_iter().rev().collect();

            for (index, (g_0, g_1)) in (0..g_0_pts.len()).into_iter().zip(g_0_pts.into_iter().zip(g_1_pts.into_iter())){
                
                // First, Compute Fiat-Shamir Heuristic point
                let root = BigInt::from_signed_bytes_be(rev_agg_roots[index].as_slice())% &shamir_ss.prime;
                
                let mut fiat_shamir_hs_point = (&g_0 + &root*&g_1)%&shamir_ss.prime;
                if fiat_shamir_hs_point < zero{
                    fiat_shamir_hs_point += &shamir_ss.prime;
                }
                if point != fiat_shamir_hs_point{
                    log::error!("DZK Proof verification failed at verifying equality of Fiat-Shamir heuristic at iteration {}",index);
                    return false;
                }

                // Second, modify point to reflect the value before folding

                let pt_bigint = BigInt::from(self.myid);
                let pow_bigint = LargeFieldSSS::mod_pow(&pt_bigint,&BigInt::from(degree_poly), &shamir_ss.prime);
                let mut agg_point = (&g_0 + &pow_bigint*&g_1)%&shamir_ss.prime;
                if agg_point < zero{
                    agg_point += &shamir_ss.prime;
                }
                point = agg_point;
                // Third, check Merkle Proof of point
                
                let merkle_proof = &proofs[index];
                if !merkle_proof.validate(
                    &self.hash_context) || 
                        merkle_proof.item() != point.to_signed_bytes_be().as_slice() || 
                        rev_roots[index] != merkle_proof.root(){
                    log::error!("DZK Proof verification failed while verifying Merkle Proof validity at iteration {}", index);
                    log::error!("Merkle root matching: computed: {:?}  given: {:?}",rev_roots[index].clone(),merkle_proof.root());
                    return false; 
                }
            }
        }
        true
    }
}