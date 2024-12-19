use crypto::aes_hash::{MerkleTree, Proof};
use crypto::hash::{do_hash, Hash};
use crypto::{LargeField, LargeFieldSer, encrypt, decrypt};
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
        assert!(self.large_field_uv_sss.verify_degree(&mut secret_poly_y_deg_t));
        // Fill polynomial on x-axis as well
        let mut secret_poly_x_deg_2t = Vec::new();
        secret_poly_x_deg_2t.push(secret);
        
        for _rep in 0..2*self.num_faults{
            // Sample random values
            let rand_bint = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
            secret_poly_x_deg_2t.push(rand_bint);
        }

        self.large_field_bv_sss.fill_evaluation_at_all_points(&mut secret_poly_x_deg_2t);
        assert!(self.large_field_bv_sss.verify_degree(&mut secret_poly_x_deg_2t));
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
            assert!(self.large_field_bv_sss.verify_degree(&mut polys_x_deg_2t[rep]));
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
            assert!(self.large_field_uv_sss.verify_degree(&mut polys_y_deg_t[rep]));
        }

        // Fill all remaining degree-2t polynomials
        for rep in self.num_faults .. self.num_nodes{
            for index in 0..self.num_nodes{
                polys_x_deg_2t[rep].push(polys_y_deg_t[index][rep+1].clone());
            }
            assert!(self.large_field_bv_sss.verify_degree(&mut polys_x_deg_2t[rep]));
        }

        // 2. Generate commitments: Sample Nonce Polynomials
        let mut nonce_polys = Vec::new();
        for _ in 0..self.num_nodes{
            let mut nonce_poly_y_deg_t  = Vec::new();
            let secret = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
            let shares:Vec<BigInt> = self.large_field_uv_sss.split(secret.clone()).into_iter().map(|x| x.1).collect();
            nonce_poly_y_deg_t.push(secret);
            nonce_poly_y_deg_t.extend(shares);
            assert!(self.large_field_uv_sss.verify_degree(&mut nonce_poly_y_deg_t));
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

        // 3. Generate Blinding Polynomials

        // 4. Generate Distributed Zero Knowledge Proofs
        let mut hashes = Vec::new();
        let mut dzk_broadcast_polys = Vec::new();
        // (Replica, (g_0 values), (g_1 values), (Vector of Merkle Proofs for each g_0,g_1 value))
        let mut shares_proofs_dzk: Vec<(Replica, Vec<DZKProof>)> = Vec::new();
        for rep in 0..self.num_nodes{
            shares_proofs_dzk.push((rep, Vec::new()));
        }
        for (rep,coefficient_vec) in (0..self.num_nodes).into_iter().zip(coefficients_y_deg_t.into_iter()){
            let mut merkle_roots = Vec::new();
            let mut eval_points = Vec::new();
            
            let mut trees: Vec<MerkleTree> = Vec::new();
            trees.push(mts[rep].clone());
            
            let coefficients = coefficient_vec.clone();
            
            let iteration = 1;
            let root = mts[rep].root();
            //merkle_roots.push(root.clone());

            // Reliably broadcast these coefficients
            let coeffs_const_size: Vec<Vec<u8>> = self.gen_dzk_proof(&mut eval_points, &mut trees, coefficients, iteration, root).into_iter().map(|x| x.to_signed_bytes_be()).collect();
            
            for tree in trees.iter(){
                merkle_roots.push(tree.root());
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
                //log::info!("Eval points iteration: {:?} rep: {}",g_0_g_1_shares ,rep);
                for (rep,g) in (0..self.num_nodes).into_iter().zip(g_0_g_1_shares.into_iter()){
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().g_0_x.push(g.0.to_signed_bytes_be());
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().g_1_x.push(g.1.to_signed_bytes_be());
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().proof.push(mt.gen_proof(rep));
                }
            }
            log::info!("G_0pts {:?}, G_1pts: {:?} iteration: {} rep: {}", dzk_proofs_all_nodes[rep].g_0_x.clone(),dzk_proofs_all_nodes[rep].g_1_x.clone(),iteration,rep);


            for (rep,proof) in (0..self.num_nodes).into_iter().zip(dzk_proofs_all_nodes.into_iter()){
                shares_proofs_dzk[rep].1.push(proof);
            }
            hashes.push(merkle_roots);
        }
        
        let va_comm: VACommitment = VACommitment { 
            roots: hashes, 
            polys: dzk_broadcast_polys 
        };
        

        // 4. Distribute shares through messages
        for (rep, dzk_proofs) in shares_proofs_dzk.into_iter(){
            
            // Craft VAShare message
            // polys_x_deg_2t[rep].pop(..0);
            // nonce_polys[rep].drain(..0);
            polys_x_deg_2t[rep] = polys_x_deg_2t[rep].split_off(1);
            polys_y_deg_t[rep].truncate(self.num_faults+1);

            let row_poly: Vec<(LargeFieldSer,LargeFieldSer, Proof)> = (0..self.num_nodes).into_iter().zip(polys_x_deg_2t[rep].iter()).map(|(index, x)| 
                (x.to_signed_bytes_be(),
                nonce_polys[index][rep+1].clone().to_signed_bytes_be(),
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
        
        let mut root_bint = BigInt::from_signed_bytes_be(root.as_slice()) % &self.large_field_uv_sss.prime;
        if root_bint < BigInt::from(0){
            root_bint += &self.large_field_uv_sss.prime;
        }

        // Second, split polynomial in half
        let mut first_half_coeff = coefficients.clone();
        let degree = coefficients.len()-1;
        let split_point;
        let next_degree;
        if degree % 2 == 0{
            split_point = degree/2;
            next_degree = split_point;
        }
        else{
            split_point = (degree+1)/2;
            next_degree = split_point - 1;
        }
        let second_half_coeff = first_half_coeff.split_off(split_point);
        let shamir_context = self.dzk_ss.get(&next_degree).unwrap();
        log::info!("Degrees of first half and second half: {} {} in iteration {} and shamir degree: {}", first_half_coeff.len(),second_half_coeff.len(),iteration, shamir_context.threshold);
        
        // Third, calculate evaluation points on both split polynomials
        let g_vals: Vec<(LargeField,LargeField)> = (1..self.num_nodes+1).into_iter().map(|rep| 
            (shamir_context.mod_evaluate_at(&first_half_coeff, rep),
            shamir_context.mod_evaluate_at(&second_half_coeff, rep))
        ).collect();
        eval_points.push(g_vals.clone());
        
        // Fourth, compute coefficients for next iteration
        let mut poly_folded:Vec<BigInt> = second_half_coeff.into_iter().map(|coeff| (coeff*&root_bint)%&shamir_context.prime).collect();
        for (index, coeff) in (0..first_half_coeff.len()).into_iter().zip(first_half_coeff.into_iter()){
            poly_folded[index] += coeff;
            poly_folded[index] = &poly_folded[index] % &shamir_context.prime;
            if poly_folded[index] < BigInt::from(0){
                poly_folded[index] += &shamir_context.prime;
            }
        }
        //log::info!("Aggregated Root Hash: {:?}, g: {:?}, poly_folded: {:?} iteration {}", root, g_vals, poly_folded, iteration);
        if poly_folded.len()-1 <= self.end_degree{
            return poly_folded;
        }
        // Only create a Merkle Tree if the polynomial is big enough
        let evaluations: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|x| self.large_field_uv_sss.mod_evaluate_at(&poly_folded, x)).collect();
        let hashes: Vec<Hash> = evaluations.iter().map(|x| do_hash(x.to_signed_bytes_be().as_slice())).collect();
        let merkle_tree = MerkleTree::new(hashes, &self.hash_context);
        let aggregated_root_hash = self.hash_context.hash_two(root, merkle_tree.root().clone());
        trees.push(merkle_tree);

        // Fifth and Finally, recurse until degree reaches a constant
        return self.gen_dzk_proof(eval_points, trees, poly_folded, iteration+1, aggregated_root_hash);
    }

    pub async fn process_acss_init_vf(self: &mut Context, enc_shares: Vec<u8>, comm: VACommitment, dealer: Replica, instance_id: usize){
        let secret_key = self.sec_key_map.get(&dealer).unwrap();
        
        let dec_shares = decrypt(secret_key.as_slice(), enc_shares);
        let shares: VAShare = bincode::deserialize(&dec_shares).unwrap();

        let verf_check = self.verify_dzk_proof(shares, comm);
        if verf_check{
            log::info!("Successfully verified shares for instance_id {}", instance_id);
        }
    }

    pub fn verify_dzk_proof(&self, share: VAShare, comm: VACommitment)-> bool{
        
        let zero = BigInt::from(0);

        // Verify Row Commitments
        let mut row_shares = Vec::new();
        for (rep, (share, nonce, proof)) in (0..self.num_nodes).into_iter().zip(share.row_poly.clone().into_iter()){
            let mut app_val = Vec::new();
            app_val.extend(share.clone());
            app_val.extend(nonce);

            let commitment = do_hash(app_val.as_slice());
            if !proof.validate(&self.hash_context) || 
                proof.item() != commitment || 
                proof.root() != comm.roots[rep][0]{
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
        if mt.root() != comm.roots[self.myid][0]{
            log::error!("Error verifying column polynomial root");
            return false;
        }

        // Verify dzk proof finally
        // Start from the lowest level
        let roots = comm.roots.clone();
        let mut rev_agg_roots: Vec<Vec<Hash>> = Vec::new();
        let mut rev_roots: Vec<Vec<Hash>> = Vec::new();
        for ind_roots in roots.into_iter(){
            let mut agg_root = ind_roots[0];
            let mut aggregated_roots = Vec::new();
            aggregated_roots.push(agg_root.clone());
            for index in 1..ind_roots.len(){
                agg_root = self.hash_context.hash_two(agg_root , ind_roots[index]);
                aggregated_roots.push(agg_root.clone());
            }
            rev_agg_roots.push(aggregated_roots.into_iter().rev().collect());
            rev_roots.push(ind_roots.into_iter().rev().collect());
        }
        let mut rep = 0;
        for ((dzk_proof, first_poly),(rev_agg_root_vec,rev_root_vec)) in (share.dzk_iters.into_iter().zip(comm.polys.into_iter())).zip(rev_agg_roots.into_iter().zip(rev_roots.into_iter())){
            // These are the coefficients of the polynomial
            log::info!("DZK verification Hashes {:?} for rep {}", rev_agg_root_vec, rep);
            let first_poly: Vec<BigInt> = first_poly.into_iter().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let degree_poly = first_poly.len()-1;
            let shamir_ss = self.dzk_ss.get(&degree_poly).unwrap();
            // Evaluate points according to this polynomial
            let mut point = shamir_ss.mod_evaluate_at(first_poly.as_slice(), self.myid+1);

            let g_0_pts: Vec<BigInt> = dzk_proof.g_0_x.into_iter().rev().map(|x | BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let g_1_pts: Vec<BigInt> = dzk_proof.g_1_x.into_iter().rev().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let proofs: Vec<Proof> = dzk_proof.proof.into_iter().rev().collect();
            
            for (index, (g_0, g_1)) in (0..g_0_pts.len()).into_iter().zip(g_0_pts.into_iter().zip(g_1_pts.into_iter())){
                
                // First, Compute Fiat-Shamir Heuristic point
                log::info!("Aggregated Root Hash: {:?}, g_0: {:?}, g_1: {:?}, poly_folded: {:?}", rev_agg_root_vec[index], g_0, g_1, first_poly);
                let root = BigInt::from_signed_bytes_be(rev_agg_root_vec[index].as_slice())% &shamir_ss.prime;
                
                let mut fiat_shamir_hs_point = (&g_0 + &root*&g_1)%&shamir_ss.prime;
                if fiat_shamir_hs_point < zero{
                    fiat_shamir_hs_point += &shamir_ss.prime;
                }
                if point != fiat_shamir_hs_point{
                    log::error!("DZK Proof verification failed at verifying equality of Fiat-Shamir heuristic at iteration {}",index);
                    return false;
                }

                // Second, modify point to reflect the value before folding

                let pt_bigint = BigInt::from(self.myid+1);
                let pow_bigint = LargeFieldSSS::mod_pow(&pt_bigint,&BigInt::from(degree_poly+1), &shamir_ss.prime);
                let mut agg_point = (&g_0 + &pow_bigint*&g_1)%&shamir_ss.prime;
                if agg_point < zero{
                    agg_point += &shamir_ss.prime;
                }
                point = agg_point;
                // Third, check Merkle Proof of point
                
                let merkle_proof = &proofs[index];
                if !merkle_proof.validate(
                    &self.hash_context) || 
                        point.to_signed_bytes_be().as_slice() != share.row_poly[rep].0 || 
                        rev_root_vec[index] != merkle_proof.root(){
                    log::error!("DZK Proof verification failed while verifying Merkle Proof validity at iteration {}", index);
                    log::error!("Merkle root matching: computed: {:?}  given: {:?}",rev_root_vec[index].clone(),merkle_proof.root());
                    log::error!("Items: {:?}  given: {:?}",merkle_proof.item(),do_hash(point.to_signed_bytes_be().as_slice()));
                    return false; 
                }
            }
            rep+=1;
        }
        true
    }
}