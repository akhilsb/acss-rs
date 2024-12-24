use consensus::get_shards;
use crypto::aes_hash::{MerkleTree, Proof};
use crypto::hash::{do_hash, Hash};
use crypto::{LargeField, LargeFieldSer, encrypt, decrypt};
use ctrbc::CTRBCMsg;
use network::Acknowledgement;
use network::plaintcp::CancelHandler;
use num_bigint_dig::RandBigInt;
use num_bigint_dig::BigInt;
use types::{Replica, WrapperMsg};

use crate::{Context, VAShare, VACommitment, ProtMsg, ACSSVAState};
use consensus::{DZKProof, PointBV};

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
            let coeffs_const_size: Vec<Vec<u8>> = self.folding_dzk_context.gen_dzk_proof(
                &mut eval_points, 
                &mut trees, 
                coefficients, 
                iteration, 
                root
            ).into_iter().map(|x| x.to_signed_bytes_be()).collect();
            
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

    pub async fn process_acss_init_vf(self: &mut Context, enc_shares: Vec<u8>, comm: VACommitment, dealer: Replica, instance_id: usize){
        
        // Decrypt message first
        let secret_key = self.sec_key_map.get(&dealer).unwrap().clone();
        
        let dec_shares = decrypt(secret_key.as_slice(), enc_shares);
        let shares: VAShare = bincode::deserialize(&dec_shares).unwrap();

        // Verify Row Commitments
        let row_shares:Vec<BigInt>  = shares.row_poly.iter().map(
            |x| 
            BigInt::from_signed_bytes_be(x.0.clone().as_slice())
        ).collect();

        let blinding_row_shares: Vec<BigInt> = shares.blinding_row_poly.iter().map(
            |x|
            BigInt::from_signed_bytes_be(x.0.clone().as_slice())
        ).collect();

        // Verify commitments
        if !self.verify_row_commitments(shares.blinding_row_poly.clone(), comm.blinding_column_roots.clone())
        || !self.verify_row_commitments(shares.row_poly.clone(), comm.column_roots.clone()) 
        
        {
            log::error!("Row Commitment verification failed for instance id: {}, abandoning ACSS", instance_id);
            return;
        }

        // Verify Column commitments next
        let mut column_shares = Vec::new();
        let mut column_nonces = Vec::new();

        let mut blinding_shares = Vec::new();
        let mut blinding_nonces = Vec::new();
        for ((share,nonce), (bshare,bnonce)) in shares.column_poly.into_iter().zip(shares.blinding_column_poly.into_iter()){
            column_shares.push(BigInt::from_signed_bytes_be(share.as_slice()));
            column_nonces.push(BigInt::from_signed_bytes_be(nonce.as_slice()));

            blinding_shares.push(BigInt::from_signed_bytes_be(bshare.as_slice()));
            blinding_nonces.push(BigInt::from_signed_bytes_be(bnonce.as_slice()));
        }

        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut column_shares);
        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut column_nonces);

        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut blinding_shares);
        self.large_field_uv_sss.fill_evaluation_at_all_points(&mut blinding_nonces);

        if !self.verify_column_commitments(&column_shares, &column_nonces, comm.column_roots[self.myid]) || 
        !self.verify_column_commitments(&blinding_shares, &blinding_nonces, comm.blinding_column_roots[self.myid]){
            log::error!("Column Commitment verification failed");
            return ;
        }

        let column_combined_roots: Vec<Hash> = comm.column_roots.clone().into_iter().zip(comm.blinding_column_roots.clone().into_iter()).map(
            |(root1,root2)|
            self.hash_context.hash_two(root1, root2)
        ).collect();

        let verf_check = self.folding_dzk_context.verify_dzk_proof_row(
            shares.dzk_iters.clone(), 
            comm.dzk_roots.clone(),
            comm.polys.clone(), 
            column_combined_roots, 
            row_shares.clone(), 
            blinding_row_shares.clone(),
            self.myid+1
        );
        if verf_check{
            log::info!("Successfully verified shares for instance_id {}", instance_id);
        }
        else {
            log::info!("Failed to verify dzk proofs of ACSS instance ID {}", instance_id);
            return;
        }
        // Instantiate ACSS state
        if !self.acss_state.contains_key(&instance_id){
            let acss_va_state = ACSSVAState::new(
                dealer,
            );
            self.acss_state.insert(instance_id, acss_va_state);
        }

        let acss_va_state = self.acss_state.get_mut(&instance_id).unwrap(); 

        acss_va_state.row_shares.extend(row_shares.clone());
        acss_va_state.blinding_row_shares.extend(blinding_row_shares.clone());
        let secret_share = column_shares[0].clone();

        for (rep,((share,bshare),(nonce,bnonce))) in (0..self.num_nodes+1).into_iter().zip(
            (column_shares.into_iter().zip(blinding_shares.into_iter())).zip(column_nonces.into_iter().zip(blinding_nonces.into_iter()))){
            acss_va_state.column_shares.insert(rep, (share,nonce));
            acss_va_state.bcolumn_shares.insert(rep, (bshare,bnonce));
        }

        acss_va_state.column_roots.extend(comm.column_roots.clone());
        acss_va_state.blinding_column_roots.extend(comm.blinding_column_roots.clone());
        acss_va_state.dzk_polynomial_roots.extend(comm.dzk_roots.clone());
        acss_va_state.dzk_polynomials.extend(comm.polys.clone());

        acss_va_state.secret = Some(secret_share);
        // Initiate ECHO process
        // Serialize commitment
        let comm_ser = bincode::serialize(&comm).unwrap();

        // Use erasure codes to split tree

        let shards = get_shards(comm_ser, self.num_faults+1, 2*self.num_faults);
        let shard_hashes: Vec<Hash> = shards.iter().map(|shard| do_hash(shard.as_slice())).collect();
        let merkle_tree = MerkleTree::new(shard_hashes, &self.hash_context);

        // Track the root hash to ensure speedy termination and redundant ECHO checks
        acss_va_state.verified_hash = Some(merkle_tree.root());

        let mut encrypted_share_vec = Vec::new();
        for (rep, (row_share, (brow_share, dzk_iter))) in 
        (0..self.num_nodes).into_iter().zip(
            shares.row_poly.into_iter().zip(
                shares.blinding_row_poly.into_iter().zip(
                    shares.dzk_iters.into_iter())))
        {
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            let point_bv: PointBV = (row_share, brow_share, dzk_iter);
            
            let point_bv_ser = bincode::serialize(&point_bv).unwrap();
            let encrypted_shares = encrypt(secret_key.as_slice(), point_bv_ser.clone());

            encrypted_share_vec.push((rep,encrypted_shares));
        }

        acss_va_state.encrypted_shares.extend(encrypted_share_vec.clone());
        for (rep,enc_share) in encrypted_share_vec.into_iter(){
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            let rbc_msg = CTRBCMsg{
                shard: shards[self.myid].clone(),
                mp: merkle_tree.gen_proof(self.myid),
                origin: dealer
            };
            let echo_msg = ProtMsg::Echo(rbc_msg, enc_share, instance_id);
            let wrapper_msg = WrapperMsg::new(echo_msg, self.myid, secret_key.as_slice());
            let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }
}