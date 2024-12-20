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
        let mut secret_poly_y_deg_t: Vec<BigInt> = Vec::new();
        secret_poly_y_deg_t.push(secret.clone());
        secret_poly_y_deg_t.extend(self.large_field_uv_sss.split(secret.clone()).into_iter().map(|tup| tup.1));
        assert!(self.large_field_uv_sss.verify_degree(&mut secret_poly_y_deg_t));


        // Fill polynomial on x-axis as well
        let mut secret_poly_x_deg_2t = Vec::new();
        secret_poly_x_deg_2t.push(secret.clone());
        secret_poly_x_deg_2t.extend(self.large_field_bv_sss.split(secret).into_iter().map(|tup| tup.1));
        assert!(self.large_field_bv_sss.verify_degree(&mut secret_poly_x_deg_2t));


        // polys_x_deg_2t and polys_y_deg_t have structure (n+1*n) points.
        // Sample t degree-2t bivariate polynomials
        let mut polys_x_deg_2t = Vec::new();
        for rep in 0..self.num_nodes{
            let share = secret_poly_y_deg_t[rep+1].clone();
            let mut poly_x_deg_2t = Vec::new();
            poly_x_deg_2t.push(share.clone());
            if rep <= self.num_faults-1{
                poly_x_deg_2t.extend(self.large_field_bv_sss.split(share).into_iter().map(|tup| tup.1));
            }
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
            assert!(self.large_field_bv_sss.verify_degree(&mut polys_x_deg_2t[rep]));
            for index in 0..self.num_nodes{
                polys_y_deg_t[index].push(polys_x_deg_2t[rep][index+1].clone());
            }
        }

        // Extend all degree-t polynomials to n points
        // Generate Coefficients of these polynomials
        let mut coefficients_y_deg_t = Vec::new();
        for rep in 0..self.num_nodes{
            // Coefficients
            let poly_eval_pts:Vec<(BigInt,BigInt)> = (0..self.num_faults+1).into_iter().map(|x| BigInt::from(x)).zip(polys_y_deg_t[rep].clone().into_iter()).collect();
            let coeffs = self.large_field_uv_sss.polynomial_coefficients(&poly_eval_pts);
            coefficients_y_deg_t.push(coeffs.clone());
            
            // Evaluations
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

        // 2. Generate blinding polynomials
        let mut blinding_y_deg_t = Vec::new();
        let mut blinding_coeffs_y_deg_t = Vec::new();
        for _rep in 0..self.num_nodes{
            let mut bpoly_y_deg_t = Vec::new();
            let secret = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
            bpoly_y_deg_t.push(secret.clone());
            
            // Shares
            let shares: Vec<BigInt> = self.large_field_uv_sss.split(secret.clone()).into_iter().map(|tup| tup.1).collect();
            bpoly_y_deg_t.extend(shares);
            
            // Coefficients
            let bpoly_eval_pts:Vec<(BigInt,BigInt)> = (0..self.num_faults+1).into_iter().map(|x| BigInt::from(x)).zip(bpoly_y_deg_t.clone().into_iter()).collect();
            let bpoly_coeffs = self.large_field_uv_sss.polynomial_coefficients(&bpoly_eval_pts);
            blinding_coeffs_y_deg_t.push(bpoly_coeffs.clone());
            
            blinding_y_deg_t.push(bpoly_y_deg_t);
        }

        // 3.a. Generate commitments: Sample Nonce Polynomials
        let mut nonce_polys = Vec::new();
        let mut blinding_nonce_polys = Vec::new();
        for _ in 0..self.num_nodes{
            let mut nonce_poly_y_deg_t  = Vec::new();
            let mut bnonce_poly_y_deg_t = Vec::new();

            // Secret sampling
            let secret = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
            let bsecret = rand::thread_rng().gen_bigint_range(&zero, &field_prime);
            
            // Share filling
            let shares:Vec<BigInt> = self.large_field_uv_sss.split(secret.clone()).into_iter().map(
                |x|
                {
                    if x.1 < zero{
                        return x.1 + &field_prime;
                    } 
                    x.1
                }
            )
            .collect();
            let bshares: Vec<BigInt> = self.large_field_uv_sss.split(bsecret.clone()).into_iter().map(
                |x| 
                {
                    if x.1 < zero{
                        return x.1 + &field_prime;
                    } 
                    x.1
                }
            ).collect();
            
            // Polynomial filling
            nonce_poly_y_deg_t.push(secret);
            nonce_poly_y_deg_t.extend(shares);
            bnonce_poly_y_deg_t.push(bsecret);
            bnonce_poly_y_deg_t.extend(bshares);


            assert!(self.large_field_uv_sss.verify_degree(&mut nonce_poly_y_deg_t));
            assert!(self.large_field_uv_sss.verify_degree(&mut bnonce_poly_y_deg_t));
            
            nonce_polys.push(nonce_poly_y_deg_t);
            blinding_nonce_polys.push(bnonce_poly_y_deg_t);
        }


        // 3.b. Generate commitments
        let mut commitments = Vec::new();
        let mut blinding_commitments = Vec::new();
        for ((share_y_deg_t,nonce_y_deg_t),(blinding_y_deg_t, bnonce_y_deg_t)) in 
                    (polys_y_deg_t.iter().zip(nonce_polys.iter())).zip(blinding_y_deg_t.iter().zip(blinding_nonce_polys.iter())){
            
            let mut comm_y_deg_t = Vec::new();
            let mut bcomm_y_deg_t = Vec::new();
            for rep in 0..self.num_nodes{
                let mut appended = Vec::new();
                appended.extend(share_y_deg_t[rep+1].clone().to_signed_bytes_be());
                appended.extend(nonce_y_deg_t[rep+1].clone().to_signed_bytes_be());
                comm_y_deg_t.push(do_hash(appended.as_slice()));

                let mut appended = Vec::new();
                appended.extend(blinding_y_deg_t[rep+1].clone().to_signed_bytes_be());
                appended.extend(bnonce_y_deg_t[rep+1].clone().to_signed_bytes_be());
                bcomm_y_deg_t.push(do_hash(appended.as_slice()));
            }
            commitments.push(comm_y_deg_t);
            blinding_commitments.push(bcomm_y_deg_t);
        }


        // 3.c. Generate Merkle Trees over commitments
        let mut mts = Vec::new();
        let mut blinding_mts = Vec::new();
        for (comm_vector,bcomm_vector) in commitments.clone().into_iter().zip(blinding_commitments.clone().into_iter()){
            mts.push(MerkleTree::new(comm_vector, &self.hash_context));
            blinding_mts.push(MerkleTree::new(bcomm_vector, &self.hash_context));
        }

        let mut column_share_roots = Vec::new();
        let mut column_blinding_roots = Vec::new();
        let column_wise_roots: Vec<Hash> = mts.iter().zip(blinding_mts.iter()).map(
            |(mt,bmt)|{
                column_share_roots.push(mt.root());
                column_blinding_roots.push(bmt.root());
                return self.hash_context.hash_two(mt.root(), bmt.root());
            }
        ).collect();
        // 4. Generate Distributed Zero Knowledge Proofs
        let mut hashes = Vec::new();
        let mut dzk_broadcast_polys = Vec::new();

        let mut dzk_share_polynomials = Vec::new();
        // 4.a. Create DZK Share polynomials
        let mut rep = 0;
        for ((coefficient_vec, blinding_coefficient_vec), column_mr) in (coefficients_y_deg_t.into_iter().zip(blinding_coeffs_y_deg_t.into_iter())).zip(column_wise_roots.clone().into_iter()){
            let column_root_bint = BigInt::from_signed_bytes_be(column_mr.clone().as_slice());
            
            let dzk_poly: Vec<BigInt> = coefficient_vec.into_iter().zip(blinding_coefficient_vec.into_iter()).map(
                |(f_i,b_i)| {
                    let mut added_coeff = (b_i + &column_root_bint*f_i)%&field_prime;
                    if added_coeff < zero{
                        added_coeff += &field_prime;
                    }
                    return added_coeff;
                }
            ).collect();
            dzk_share_polynomials.push(dzk_poly.clone());
            let mut vec_pts = Vec::new();
            for i in 1..self.num_nodes+1{
                let pt = self.large_field_uv_sss.mod_evaluate_at(&dzk_poly, i);
                assert!(polys_x_deg_2t[i-1][rep+1] == polys_y_deg_t[rep][i]);
                let mut sub_eval = (blinding_y_deg_t[rep][i].clone() + &column_root_bint*polys_x_deg_2t[i-1][rep+1].clone())%&field_prime;
                if sub_eval < zero{
                    sub_eval += &field_prime;
                }
                assert!(pt == sub_eval);
                vec_pts.push((i,pt));
            }
            rep +=1;
        }
        // (Replica, (g_0 values), (g_1 values), (Vector of Merkle Proofs for each g_0,g_1 value))
        let mut shares_proofs_dzk: Vec<(Replica, Vec<DZKProof>)> = Vec::new();
        for rep in 0..self.num_nodes{
            shares_proofs_dzk.push((rep, Vec::new()));
        }
        for (dzk_poly,column_root) in dzk_share_polynomials.into_iter().zip(column_wise_roots.into_iter()){
            
            let mut merkle_roots = Vec::new();
            let mut eval_points = Vec::new();
            
            let mut trees: Vec<MerkleTree> = Vec::new();
            //trees.push(mts[rep].clone());
            
            let coefficients = dzk_poly.clone();
            
            let iteration = 1;
            let root = column_root;
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

            for (rep,proof) in (0..self.num_nodes).into_iter().zip(dzk_proofs_all_nodes.into_iter()){
                shares_proofs_dzk[rep].1.push(proof);
            }
            hashes.push(merkle_roots);
        }
        
        let va_comm: VACommitment = VACommitment {
            column_roots: column_share_roots,
            blinding_column_roots: column_blinding_roots,
            dzk_roots: hashes, 
            polys: dzk_broadcast_polys 
        };
        

        // 4. Distribute shares through messages
        for (rep, dzk_proofs) in shares_proofs_dzk.into_iter(){
            
            // Craft VAShare message
            // polys_x_deg_2t[rep].pop(..0);
            // nonce_polys[rep].drain(..0);
            //polys_x_deg_2t[rep] = polys_x_deg_2t[rep].split_off(1);
            polys_y_deg_t[rep].truncate(self.num_faults+1);
            //blinding_y_deg_t[rep].truncate(self.num_faults+1);

            let row_poly: Vec<(LargeFieldSer,LargeFieldSer, Proof)> = (0..self.num_nodes).into_iter().map(|index| {
                (polys_x_deg_2t[rep][index+1].to_signed_bytes_be(),
                    nonce_polys[index][rep+1].clone().to_signed_bytes_be(),
                    mts[index].gen_proof(rep))
            }).collect();
            let column_poly: Vec<(LargeFieldSer,LargeFieldSer)> = polys_y_deg_t[rep].iter().zip(nonce_polys[rep].iter()).map(|(share,nonce)| 
                (share.to_signed_bytes_be(),nonce.to_signed_bytes_be())
            ).collect();
            
            let blinding_row_poly: Vec<(LargeFieldSer,LargeFieldSer, Proof)> = (0..self.num_nodes).into_iter().map(
                |index| 
                (blinding_y_deg_t[index][rep+1].clone().to_signed_bytes_be(),
                    blinding_nonce_polys[index][rep+1].clone().to_signed_bytes_be(),
                    blinding_mts[index].gen_proof(rep))
            ).collect();
            let blinding_column_poly: Vec<(LargeFieldSer,LargeFieldSer)> = blinding_y_deg_t[rep].iter().zip(blinding_nonce_polys[rep].iter()).map(
                |(share,nonce)|
                (share.to_signed_bytes_be(),nonce.to_signed_bytes_be())
            ).collect();


            let msg = VAShare{
                row_poly: row_poly,
                column_poly: column_poly,
                dzk_iters: dzk_proofs,
                rep: rep,
                blinding_row_poly: blinding_row_poly,
                blinding_column_poly: blinding_column_poly,
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

    pub async fn process_acss_init_vf(self: &mut Context, enc_shares: Vec<u8>, comm: VACommitment, dealer: Replica, instance_id: usize){
        let secret_key = self.sec_key_map.get(&dealer).unwrap();
        
        let dec_shares = decrypt(secret_key.as_slice(), enc_shares);
        let shares: VAShare = bincode::deserialize(&dec_shares).unwrap();

        let verf_check = self.verify_dzk_proof(shares, comm);
        if verf_check{
            log::info!("Successfully verified shares for instance_id {}", instance_id);
        }
    }

    fn verify_row_commitments(self: &Context,shares: Vec<(LargeFieldSer, LargeFieldSer, Proof)>, roots: Vec<Hash>) -> bool{
        for ((share, nonce, proof), root) in shares.into_iter().zip(roots.into_iter()){
            let mut app_val = Vec::new();
            app_val.extend(share.clone());
            app_val.extend(nonce);

            let commitment = do_hash(app_val.as_slice());
            if !proof.validate(&self.hash_context) || 
                proof.item() != commitment || 
                proof.root() != root{
                log::error!("Commitment verification failed");
                log::error!("Proof validation: {}", proof.validate(&self.hash_context));
                log::error!("Proof item and commitment: {:?} {:?}", proof.item(), commitment);
                log::error!("Root and proof root: {:?} {:?}",root, proof.root());
                return false;
            }
        }
        true
    }

    fn verify_column_commitments(self: &Context, shares: Vec<BigInt>, nonces: Vec<BigInt>, root: Hash)-> bool{
        let mut commitments = Vec::new();
        for rep in 0..self.num_nodes{
            let mut app_share = Vec::new();
            app_share.extend(shares[rep+1].clone().to_signed_bytes_be());
            app_share.extend(nonces[rep+1].clone().to_signed_bytes_be());
            commitments.push(do_hash(app_share.as_slice()));
        }
        // Construct Merkle Tree
        let mt = MerkleTree::new(commitments, &self.hash_context);
        if mt.root() != root{
            log::error!("Error verifying column polynomial root");
            return false;
        }
        true
    }

    pub fn verify_dzk_proof(&self, share: VAShare, comm: VACommitment)-> bool{
        
        let zero = BigInt::from(0);

        // Verify Row Commitments
        let row_shares:Vec<BigInt>  = share.row_poly.iter().map(
            |x| 
            BigInt::from_signed_bytes_be(x.0.clone().as_slice())
        ).collect();

        let blinding_row_shares: Vec<BigInt> = share.blinding_row_poly.iter().map(
            |x|
            BigInt::from_signed_bytes_be(x.0.clone().as_slice())
        ).collect();

        if !self.verify_row_commitments(share.blinding_row_poly, comm.blinding_column_roots.clone())
        || !self.verify_row_commitments(share.row_poly, comm.column_roots.clone()) 
        
        {
            log::error!("Row Commitment verification failed");
            return false;
        }

        // Verify Column commitments next
        let mut column_shares = Vec::new();
        let mut column_nonces = Vec::new();

        let mut blinding_shares = Vec::new();
        let mut blinding_nonces = Vec::new();
        for ((share,nonce), (bshare,bnonce)) in share.column_poly.into_iter().zip(share.blinding_column_poly.into_iter()){
            column_shares.push(BigInt::from_signed_bytes_be(share.as_slice()));
            column_nonces.push(BigInt::from_signed_bytes_be(nonce.as_slice()));

            blinding_shares.push(BigInt::from_signed_bytes_be(bshare.as_slice()));
            blinding_nonces.push(BigInt::from_signed_bytes_be(bnonce.as_slice()));
        }

        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut column_shares);
        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut column_nonces);

        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut blinding_shares);
        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut blinding_nonces);

        if !self.verify_column_commitments(column_shares, column_nonces, comm.column_roots[self.myid]) || 
        !self.verify_column_commitments(blinding_shares, blinding_nonces, comm.blinding_column_roots[self.myid]){
            log::error!("Row Commitment verification failed");
            return false;
        }

        let column_combined_roots: Vec<Hash> = comm.column_roots.into_iter().zip(comm.blinding_column_roots.into_iter()).map(
            |(root1,root2)|
            self.hash_context.hash_two(root1, root2)
        ).collect();
        // Verify dzk proof finally
        // Start from the lowest level
        let roots = comm.dzk_roots.clone();
        // Calculate aggregated roots first
        let mut rev_agg_roots: Vec<Vec<Hash>> = Vec::new();
        let mut rev_roots: Vec<Vec<Hash>> = Vec::new();

        let mut dzk_shares = Vec::new();
        for ((ind_roots,first_root),(share,blinding)) in 
                (roots.into_iter().zip(column_combined_roots.into_iter())).zip(
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
                    (share.dzk_iters.into_iter().zip(comm.polys.into_iter())).zip(
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