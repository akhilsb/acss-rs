use std::time::{SystemTime, UNIX_EPOCH};

use consensus::{get_shards, ShamirSecretSharing};
use crypto::aes_hash::{MerkleTree, Proof};
use crypto::hash::{do_hash, Hash};
use crypto::{decrypt, encrypt, LargeFieldSer};
use ctrbc::CTRBCMsg;
use network::plaintcp::CancelHandler;
use network::Acknowledgement;
use types::{Replica, WrapperMsg};

use crate::{ACSSVAState, Context, ProtMsg, VACommitment, VAShare};
use consensus::LargeField;
use consensus::{DZKProof, PointBV};
use lambdaworks_math::polynomial::Polynomial;
use lambdaworks_math::traits::ByteConversion;
impl Context {
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
    pub async fn init_verifiable_abort(
        self: &mut Context,
        secrets: Vec<LargeField>,
        instance_id: usize,
        _threshold: usize,
    ) {
        // let field_prime = self.large_field_bv_sss.prime.clone();
        // let zero = BigInt::from(0);

        let mut row_polynomials = Vec::new();
        let mut col_polynomials = Vec::new();
        // specify Vec<Vec<Polynomial<LargeField>>>
        let mut coeff_polynomials_y: Vec<Vec<Polynomial<LargeField>>> = Vec::new();

        let _lt_indices: Vec<LargeField> = (0..self.num_faults + 1)
            .into_iter()
            .map(|el| LargeField::from(el as u64))
            .collect();
        //let vandermonde_matrix_lt = self.large_field_uv_sss.vandermonde_matrix(&lt_indices);
        // let inverse_vandermonde =self
        //     .large_field_uv_sss
        //     .inverse_vandermonde(vandermonde_matrix_lt);

        let num_cores = 4;
        let chunk_size = secrets.len() / num_cores;
        // Break down secrets into batches
        let secret_batches: Vec<Vec<LargeField>> = secrets
            .chunks(chunk_size)
            .into_iter()
            .map(|el| el.to_vec())
            .collect();
        let mut handles = Vec::new();
        for secret_batch in secret_batches {
            // Parallelizing the share generation
            handles.push(tokio::spawn(Self::generate_shares(
                self.large_field_uv_sss.clone(),
                self.large_field_bv_sss.clone(),
                secret_batch,
                self.num_nodes,
                self.num_faults,
                //inverse_vandermonde.clone(),
            )));
        }

        for handle in handles {
            let (row_evals, col_evals, col_coeffs) = handle.await.unwrap();
            row_polynomials.extend(row_evals);
            col_polynomials.extend(col_evals);
            coeff_polynomials_y.extend(col_coeffs);
        }
        // 2. Generate blinding polynomials
        let mut blinding_y_deg_t = Vec::new();
        let mut blinding_coeffs_y_deg_t = Vec::new();
        for _rep in 0..self.num_nodes {
            let mut bpoly_y_deg_t = Vec::new();
            let secret = ShamirSecretSharing::rand_field_element();
            bpoly_y_deg_t.push(secret.clone());

            // Shares
            let shares: Vec<LargeField> = self.large_field_uv_sss.split(secret.clone());
            bpoly_y_deg_t.extend(shares);

            // Coefficients
            let bpoly_eval_pts: Vec<u64> = (0..self.num_faults + 1)
                .into_iter()
                .map(|x| x as u64)
                .collect();
            let bpoly_coeffs = self
                .large_field_uv_sss
                .reconstructing(&bpoly_eval_pts, &bpoly_y_deg_t);
            blinding_coeffs_y_deg_t.push(bpoly_coeffs.clone());

            blinding_y_deg_t.push(bpoly_y_deg_t);
        }

        // 3.a. Generate commitments: Sample Nonce Polynomials
        let mut nonce_polys = Vec::new();
        let mut blinding_nonce_polys = Vec::new();
        for _ in 0..self.num_nodes {
            let mut nonce_poly_y_deg_t = Vec::new();
            let mut bnonce_poly_y_deg_t = Vec::new();

            // Secret sampling
            let secret = ShamirSecretSharing::rand_field_element();
            let bsecret = ShamirSecretSharing::rand_field_element();

            // Share filling
            let shares: Vec<LargeField> = self.large_field_uv_sss.split(secret.clone());
            let bshares: Vec<LargeField> = self.large_field_uv_sss.split(bsecret.clone());

            // Polynomial filling
            nonce_poly_y_deg_t.push(secret);
            nonce_poly_y_deg_t.extend(shares);
            bnonce_poly_y_deg_t.push(bsecret);
            bnonce_poly_y_deg_t.extend(bshares);

            //assert!(self.large_field_uv_sss.verify_degree(&mut nonce_poly_y_deg_t));
            //assert!(self.large_field_uv_sss.verify_degree(&mut bnonce_poly_y_deg_t));

            nonce_polys.push(nonce_poly_y_deg_t);
            blinding_nonce_polys.push(bnonce_poly_y_deg_t);
        }

        // 3.b. Generate commitments
        let mut commitments = Vec::new();
        let mut blinding_commitments = Vec::new();

        let mut appended_shares = Vec::new();
        for _ in 0..self.num_nodes {
            let mut shares_app = Vec::new();
            for _ in 0..self.num_nodes + 1 {
                shares_app.push(Vec::new());
            }
            appended_shares.push(shares_app);
        }

        for shares_y_deg_t in col_polynomials.clone() {
            for (index, share_poly) in (0..self.num_nodes).zip(shares_y_deg_t.into_iter()) {
                for (l2_index, share) in (0..self.num_nodes + 1).zip(share_poly.into_iter()) {
                    appended_shares[index][l2_index].extend(share.to_bytes_be());
                }
            }
        }

        for ((share_y_deg_t, nonce_y_deg_t), (blinding_y_deg_t, bnonce_y_deg_t)) in
            (appended_shares.iter().zip(nonce_polys.iter()))
                .zip(blinding_y_deg_t.iter().zip(blinding_nonce_polys.iter()))
        {
            let mut comm_y_deg_t = Vec::new();
            let mut bcomm_y_deg_t = Vec::new();
            for (rep, share_eval_val) in (0..self.num_nodes + 1)
                .into_iter()
                .zip(share_y_deg_t.into_iter())
            {
                let mut appended = Vec::new();
                appended.extend(share_eval_val);
                appended.extend(nonce_y_deg_t[rep].clone().to_bytes_be().to_vec());
                comm_y_deg_t.push(do_hash(appended.as_slice()));

                let mut appended = Vec::new();
                appended.extend(blinding_y_deg_t[rep].clone().to_bytes_be().to_vec());
                appended.extend(bnonce_y_deg_t[rep].clone().to_bytes_be().to_vec());
                bcomm_y_deg_t.push(do_hash(appended.as_slice()));
            }
            comm_y_deg_t.remove(0);
            bcomm_y_deg_t.remove(0);

            commitments.push(comm_y_deg_t);
            blinding_commitments.push(bcomm_y_deg_t);
        }

        // 3.c. Generate Merkle Trees over commitments
        let mut mts = Vec::new();
        let mut blinding_mts = Vec::new();
        for (comm_vector, bcomm_vector) in commitments
            .clone()
            .into_iter()
            .zip(blinding_commitments.clone().into_iter())
        {
            mts.push(MerkleTree::new(comm_vector, &self.hash_context));
            blinding_mts.push(MerkleTree::new(bcomm_vector, &self.hash_context));
        }

        let mut column_share_roots = Vec::new();
        let mut column_blinding_roots = Vec::new();
        let column_wise_roots: Vec<Hash> = mts
            .iter()
            .zip(blinding_mts.iter())
            .map(|(mt, bmt)| {
                column_share_roots.push(mt.root());
                column_blinding_roots.push(bmt.root());
                return self.hash_context.hash_two(mt.root(), bmt.root());
            })
            .collect();
        // 4. Generate Distributed Zero Knowledge Proofs
        let mut hashes = Vec::new();
        let mut dzk_broadcast_polys = Vec::new();

        let mut dzk_share_polynomials = Vec::new();

        // 4.a. Aggregate All share polynomials
        let aggregated_coefficients =
            self.agg_share_poly_dzk_batch(coeff_polynomials_y, column_wise_roots.clone());

        // // 4.b. Create DZK Share polynomials
        // let mut _rep = 0;
        // for ((coefficient_vec, blinding_coefficient_vec), column_mr) in (aggregated_coefficients
        //     .into_iter()
        //     .zip(blinding_coeffs_y_deg_t.into_iter()))
        // .zip(column_wise_roots.clone().into_iter())
        // {
        //     let column_root_bint = BigInt::from_signed_bytes_be(column_mr.clone().as_slice());

        //     // Polynomial addition
        //     let dzk_poly: Vec<BigInt> = coefficient_vec
        //         .into_iter()
        //         .zip(blinding_coefficient_vec.into_iter())
        //         .map(|(f_i, b_i)| {
        //             let mut added_coeff = (b_i + &column_root_bint * f_i) % &field_prime;
        //             if added_coeff < zero {
        //                 added_coeff += &field_prime;
        //             }
        //             return added_coeff;
        //         })
        //         .collect();
        //     dzk_share_polynomials.push(dzk_poly.clone());
        //     let mut vec_pts = Vec::new();
        //     for i in 1..self.num_nodes + 1 {
        //         let pt = self.large_field_uv_sss.mod_evaluate_at(&dzk_poly, i);
        //         //assert!(polys_x_deg_2t[i-1][rep+1] == polys_y_deg_t[rep][i]);

        //         //assert!(pt == sub_eval);
        //         vec_pts.push((i, pt));
        //     }
        //     _rep += 1;
        // }

        // 4.b. Create DZK share polynomials
        let mut _rep = 0;
        for ((coefficient_vec, blinding_coefficient_vec), column_mr) in aggregated_coefficients
            .into_iter()
            .zip(blinding_coeffs_y_deg_t.into_iter())
            .zip(column_wise_roots.clone().into_iter())
        {
            let column_root = LargeField::from_bytes_be(column_mr.as_slice()).unwrap();

            // dzk_poly = coefficient_vec + column_root * blinding_coefficient_vec
            let scaled_blinding_poly = ShamirSecretSharing::multiply_polynomials(
                &Polynomial::new(&[column_root]),
                &blinding_coefficient_vec,
            );
            let dzk_poly =
                ShamirSecretSharing::add_polynomials(&coefficient_vec, &scaled_blinding_poly);

            dzk_share_polynomials.push(dzk_poly.clone());

            let mut vec_pts = Vec::new();
            for i in 1..=self.num_nodes {
                let pt = dzk_poly.evaluate(&LargeField::from(i as u64));
                vec_pts.push((i, pt));
            }
            _rep += 1;
        }

        // (Replica, (g_0 values), (g_1 values), (Vector of Merkle Proofs for each g_0,g_1 value))
        let mut shares_proofs_dzk: Vec<(Replica, Vec<DZKProof>)> = Vec::new();
        for rep in 0..self.num_nodes {
            shares_proofs_dzk.push((rep, Vec::new()));
        }
        for (dzk_poly, column_root) in dzk_share_polynomials
            .into_iter()
            .zip(column_wise_roots.into_iter())
        {
            let mut merkle_roots = Vec::new();
            let mut eval_points = Vec::new();

            let mut trees: Vec<MerkleTree> = Vec::new();
            //trees.push(mts[rep].clone());

            let coefficients = dzk_poly.clone();

            let iteration = 1;
            let root = column_root;
            //merkle_roots.push(root.clone());

            // Reliably broadcast these coefficients
            let coeffs_const_size: Vec<Vec<u8>> = self
                .folding_dzk_context
                .gen_dzk_proof(
                    &mut eval_points,
                    &mut trees,
                    coefficients.coefficients,
                    iteration,
                    root,
                )
                .into_iter()
                .map(|x| x.to_bytes_be().to_vec())
                .collect();

            for tree in trees.iter() {
                merkle_roots.push(tree.root());
            }
            dzk_broadcast_polys.push(coeffs_const_size);

            let mut dzk_proofs_all_nodes = Vec::new();
            for _ in 0..self.num_nodes {
                dzk_proofs_all_nodes.push(DZKProof {
                    g_0_x: Vec::new(),
                    g_1_x: Vec::new(),
                    proof: Vec::new(),
                });
            }

            for (g_0_g_1_shares, mt) in eval_points.into_iter().zip(trees.into_iter()) {
                for (rep, g) in (0..self.num_nodes)
                    .into_iter()
                    .zip(g_0_g_1_shares.into_iter())
                {
                    dzk_proofs_all_nodes
                        .get_mut(rep)
                        .unwrap()
                        .g_0_x
                        .push(g.0.to_bytes_be().to_vec());
                    dzk_proofs_all_nodes
                        .get_mut(rep)
                        .unwrap()
                        .g_1_x
                        .push(g.1.to_bytes_be().to_vec());
                    dzk_proofs_all_nodes
                        .get_mut(rep)
                        .unwrap()
                        .proof
                        .push(mt.gen_proof(rep));
                }
            }

            for (rep, proof) in (0..self.num_nodes)
                .into_iter()
                .zip(dzk_proofs_all_nodes.into_iter())
            {
                shares_proofs_dzk[rep].1.push(proof);
            }
            hashes.push(merkle_roots);
        }

        let va_comm: VACommitment = VACommitment {
            column_roots: column_share_roots,
            blinding_column_roots: column_blinding_roots,
            dzk_roots: hashes,
            polys: dzk_broadcast_polys,
        };

        log::info!(
            "Share Creation time: {:?}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        // 4. Distribute shares through messages
        for (rep, dzk_proofs) in shares_proofs_dzk.into_iter() {
            // Craft VAShare message
            // polys_x_deg_2t[rep].pop(..0);
            // nonce_polys[rep].drain(..0);
            //polys_x_deg_2t[rep] = polys_x_deg_2t[rep].split_off(1);
            let mut col_polys_party = Vec::new();
            let mut row_polys_party = Vec::new();
            for index in 0..col_polynomials.len() {
                let bv_poly = &col_polynomials[index];
                let bv_row_poly = &row_polynomials[index];

                let mut col_poly_party = bv_poly[rep].clone();
                let mut row_poly_party = Vec::new();
                for l2_index in 1..self.num_nodes + 1 {
                    row_poly_party.push(bv_row_poly[rep][l2_index].clone());
                }

                col_poly_party.truncate(self.num_faults + 1);
                col_polys_party.push(
                    col_poly_party
                        .into_iter()
                        .map(|el| el.to_bytes_be().to_vec())
                        .collect(),
                );
                row_polys_party.push(
                    row_poly_party
                        .into_iter()
                        .map(|el| el.to_bytes_be().to_vec())
                        .collect(),
                );
            }

            let mut nonce_row_poly = Vec::new();
            let mut proofs_row_poly = Vec::new();

            for index in 0..self.num_nodes {
                nonce_row_poly.push(nonce_polys[index][rep + 1].clone().to_bytes_be().to_vec());
                proofs_row_poly.push(mts[index].gen_proof(rep))
            }
            // polys_y_deg_t[rep].truncate(self.num_faults+1);
            //blinding_y_deg_t[rep].truncate(self.num_faults+1);

            let row_poly: (Vec<Vec<LargeFieldSer>>, Vec<LargeFieldSer>, Vec<Proof>) =
                (row_polys_party, nonce_row_poly, proofs_row_poly);
            let column_poly: (Vec<Vec<LargeFieldSer>>, Vec<LargeFieldSer>) = (
                col_polys_party,
                nonce_polys[rep]
                    .iter()
                    .map(|el| el.to_bytes_be().to_vec())
                    .collect(),
            );

            let blinding_row_poly: Vec<(LargeFieldSer, LargeFieldSer, Proof)> = (0..self.num_nodes)
                .into_iter()
                .map(|index| {
                    (
                        blinding_y_deg_t[index][rep + 1]
                            .clone()
                            .to_bytes_be()
                            .to_vec(),
                        blinding_nonce_polys[index][rep + 1]
                            .clone()
                            .to_bytes_be()
                            .to_vec(),
                        blinding_mts[index].gen_proof(rep),
                    )
                })
                .collect();
            let blinding_column_poly: Vec<(LargeFieldSer, LargeFieldSer)> = blinding_y_deg_t[rep]
                .iter()
                .zip(blinding_nonce_polys[rep].iter())
                .map(|(share, nonce)| (share.to_bytes_be().to_vec(), nonce.to_bytes_be().to_vec()))
                .collect();

            let msg = VAShare {
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

            let prot_msg_va = ProtMsg::Init(encrypted_msg, va_comm.clone(), self.myid, instance_id);

            let wrapper_msg = WrapperMsg::new(prot_msg_va, self.myid, &secret_key);
            let cancel_handler: CancelHandler<Acknowledgement> =
                self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }

    async fn generate_shares(
        large_field_uv_sss: ShamirSecretSharing,
        large_field_bv_sss: ShamirSecretSharing,
        secrets: Vec<LargeField>,
        num_nodes: usize,
        num_faults: usize,
        //inverse_vandermonde: Vec<Vec<LargeField>>,
    ) -> (
        Vec<Vec<Vec<LargeField>>>,
        Vec<Vec<Vec<LargeField>>>,
        Vec<Vec<Polynomial<LargeField>>>,
    ) {
        let mut row_polynomials = Vec::new();
        let mut col_polynomials = Vec::new();
        let mut coeff_polynomials_y = Vec::new();
        for secret in secrets {
            // Sample bivariate polynomial
            // degree-2t row polynomial and degree-t column polynomial
            // Sample degree-t polynomial
            // Sample secret polynomial
            let mut secret_poly_y_deg_t: Vec<LargeField> = Vec::new();
            secret_poly_y_deg_t.push(secret.clone());
            secret_poly_y_deg_t.extend(large_field_uv_sss.split(secret.clone()));
            //assert!(self.large_field_uv_sss.verify_degree(&mut secret_poly_y_deg_t));

            // Fill polynomial on x-axis as well
            let mut secret_poly_x_deg_2t = Vec::new();
            secret_poly_x_deg_2t.push(secret.clone());
            secret_poly_x_deg_2t.extend(large_field_bv_sss.split(secret));
            //assert!(self.large_field_bv_sss.verify_degree(&mut secret_poly_x_deg_2t));

            // polys_x_deg_2t and polys_y_deg_t have structure (n+1*n) points.
            // Sample t degree-2t bivariate polynomials
            let mut polys_x_deg_2t = Vec::new();
            for rep in 0..num_nodes {
                //
                let share = secret_poly_y_deg_t[rep + 1].clone();
                let mut poly_x_deg_2t = Vec::new();
                poly_x_deg_2t.push(share.clone());
                if rep <= num_faults - 1 {
                    poly_x_deg_2t.extend(large_field_bv_sss.split(share));
                }
                polys_x_deg_2t.push(poly_x_deg_2t);
            }

            // Keep track of corresponding column polynomials
            let mut polys_y_deg_t = Vec::new();
            for rep in 0..num_nodes {
                let share = secret_poly_x_deg_2t[rep + 1].clone();
                let mut poly_y_deg_t = Vec::new();
                poly_y_deg_t.push(share);
                polys_y_deg_t.push(poly_y_deg_t);
            }

            for rep in 0..num_faults {
                //assert!(self.large_field_bv_sss.verify_degree(&mut polys_x_deg_2t[rep]));
                for index in 0..num_nodes {
                    polys_y_deg_t[index].push(polys_x_deg_2t[rep][index + 1].clone());
                }
            }

            // Extend all degree-t polynomials to n points
            // Generate Coefficients of these polynomials
            let mut coefficients_y_deg_t = Vec::new();
            for rep in 0..num_nodes {
                // Coefficients
                let poly_eval_pts: Vec<LargeField> =
                    polys_y_deg_t[rep].clone().into_iter().collect();
                let coeffs = large_field_uv_sss.polynomial_coefficients_with_vandermonde_matrix(
                    //&inverse_vandermonde,
                    &poly_eval_pts,
                );
                coefficients_y_deg_t.push(coeffs.clone());

                // Evaluations
                large_field_uv_sss.fill_evaluation_at_all_points(&mut polys_y_deg_t[rep]);
                //assert!(self.large_field_uv_sss.verify_degree(&mut polys_y_deg_t[rep]));
            }

            // Fill all remaining degree-2t polynomials
            for rep in num_faults..num_nodes {
                for index in 0..num_nodes {
                    polys_x_deg_2t[rep].push(polys_y_deg_t[index][rep + 1].clone());
                }
                //assert!(self.large_field_bv_sss.verify_degree(&mut polys_x_deg_2t[rep]));
            }
            coeff_polynomials_y.push(coefficients_y_deg_t);
            row_polynomials.push(polys_x_deg_2t);
            col_polynomials.push(polys_y_deg_t);
        }
        (row_polynomials, col_polynomials, coeff_polynomials_y)
    }

    pub async fn process_acss_init_vf(
        self: &mut Context,
        enc_shares: Vec<u8>,
        comm: VACommitment,
        dealer: Replica,
        instance_id: usize,
    ) {
        // Decrypt message first
        let secret_key = self.sec_key_map.get(&dealer).unwrap().clone();

        let dec_shares = decrypt(secret_key.as_slice(), enc_shares);
        let shares: VAShare = bincode::deserialize(&dec_shares).unwrap();

        let row_shares: Vec<Vec<LargeField>> = shares
            .row_poly
            .0
            .iter()
            .map(|x| {
                x.iter()
                    .filter_map(|el| LargeField::from_bytes_be(el.as_slice()).ok())
                    .collect()
            })
            .collect();

        let blinding_row_shares: Vec<LargeField> = shares
            .blinding_row_poly
            .iter()
            .filter_map(|x| LargeField::from_bytes_be(x.0.as_slice()).ok())
            .collect();

        // Appended
        // Verify commitments
        if !self.verify_blinding_row_commitments(
            shares.blinding_row_poly.clone(),
            comm.blinding_column_roots.clone(),
        ) || !self.verify_commitments_rows(shares.row_poly.clone(), comm.column_roots.clone())
        {
            log::error!(
                "Row Commitment verification failed for instance id: {}, abandoning ACSS",
                instance_id
            );
            return;
        }

        // Verify Column commitments next
        let mut columns = Vec::new();
        for share_poly in shares.column_poly.0 {
            let mut col_shares = share_poly
                .into_iter()
                .map(|el| LargeField::from_bytes_be(el.as_slice()).unwrap())
                .collect();
            self.large_field_uv_sss
                .fill_evaluation_at_all_points(&mut col_shares);
            columns.push(col_shares);
        }

        let mut column_nonces = Vec::new();

        let mut blinding_shares = Vec::new();
        let mut blinding_nonces = Vec::new();

        for (nonce, (bshare, bnonce)) in shares
            .column_poly
            .1
            .into_iter()
            .zip(shares.blinding_column_poly.into_iter())
        {
            column_nonces.push(LargeField::from_bytes_be(nonce.as_slice()).unwrap());

            blinding_shares.push(LargeField::from_bytes_be(bshare.as_slice()).unwrap());
            blinding_nonces.push(LargeField::from_bytes_be(bnonce.as_slice()).unwrap());
        }

        self.large_field_uv_sss
            .fill_evaluation_at_all_points(&mut column_nonces);

        self.large_field_uv_sss
            .fill_evaluation_at_all_points(&mut blinding_shares);
        self.large_field_uv_sss
            .fill_evaluation_at_all_points(&mut blinding_nonces);

        if !self.verify_column_share_commitments(
            &columns,
            &column_nonces,
            comm.column_roots[self.myid],
        ) || !self.verify_blinding_column_commitments(
            &blinding_shares,
            &blinding_nonces,
            comm.blinding_column_roots[self.myid],
        ) {
            log::error!("Column Commitment verification failed");
            return;
        }

        let column_combined_roots: Vec<Hash> = comm
            .column_roots
            .clone()
            .into_iter()
            .zip(comm.blinding_column_roots.clone().into_iter())
            .map(|(root1, root2)| self.hash_context.hash_two(root1, root2))
            .collect();

        let mut party_wise_row_shares = Vec::new();
        for _ in 0..self.num_nodes {
            party_wise_row_shares.push(Vec::new());
        }

        for row in row_shares.clone().into_iter() {
            for (rep, evaluation) in (0..self.num_nodes).into_iter().zip(row.into_iter()) {
                party_wise_row_shares[rep].push(evaluation);
            }
        }

        let dzk_aggregated_points: Vec<LargeField> = party_wise_row_shares
            .clone()
            .into_iter()
            .zip(column_combined_roots.clone().into_iter())
            .map(|(shares, root)| self.folding_dzk_context.gen_agg_poly_dzk(shares, root))
            .collect();

        let verf_check = self.folding_dzk_context.verify_dzk_proof_row(
            shares.dzk_iters.clone(),
            comm.dzk_roots.clone(),
            comm.polys.clone(),
            column_combined_roots,
            dzk_aggregated_points.clone(),
            blinding_row_shares.clone(),
            self.myid + 1,
        );
        if verf_check {
            log::info!(
                "Successfully verified shares for instance_id {}",
                instance_id
            );
        } else {
            log::error!(
                "Failed to verify dzk proofs of ACSS instance ID {}",
                instance_id
            );
            return;
        }
        // Instantiate ACSS state
        if !self.acss_state.contains_key(&instance_id) {
            let acss_va_state = ACSSVAState::new(dealer);
            self.acss_state.insert(instance_id, acss_va_state);
        }

        let acss_va_state = self.acss_state.get_mut(&instance_id).unwrap();

        acss_va_state.row_shares.extend(row_shares.clone());
        acss_va_state
            .blinding_row_shares
            .extend(blinding_row_shares.clone());
        // Row secrets computation
        let mut row_secret_shares = Vec::new();
        for row in row_shares {
            let mut poly = Vec::new();
            let mut xs = Vec::new();
            for (rep, share) in (1..2 * self.num_faults + 2)
                .into_iter()
                .zip(row.into_iter())
            {
                poly.push(share);
                xs.push(rep as u64);
            }
            row_secret_shares.push({
                let recon_poly = self.large_field_bv_sss.reconstructing(&xs, &poly);
                self.large_field_bv_sss.recover(&recon_poly)
            });
        }
        let secret_shares = columns.iter().map(|col| col[0].clone()).collect();

        for (rep, ((share, bshare), (nonce, bnonce))) in (0..self.num_nodes + 1).into_iter().zip(
            (columns.into_iter().zip(blinding_shares.into_iter()))
                .zip(column_nonces.into_iter().zip(blinding_nonces.into_iter())),
        ) {
            acss_va_state.column_shares.insert(rep, (share, nonce));
            acss_va_state.bcolumn_shares.insert(rep, (bshare, bnonce));
        }

        acss_va_state.column_roots.extend(comm.column_roots.clone());
        acss_va_state
            .blinding_column_roots
            .extend(comm.blinding_column_roots.clone());
        acss_va_state
            .dzk_polynomial_roots
            .extend(comm.dzk_roots.clone());
        acss_va_state.dzk_polynomials.extend(comm.polys.clone());

        acss_va_state.secret_shares = Some(secret_shares);
        acss_va_state.row_secret_shares = Some(row_secret_shares);
        // Initiate ECHO process
        // Serialize commitment
        let comm_ser = bincode::serialize(&comm).unwrap();

        // Use erasure codes to split tree

        let shards = get_shards(comm_ser, self.num_faults + 1, 2 * self.num_faults);
        let shard_hashes: Vec<Hash> = shards
            .iter()
            .map(|shard| do_hash(shard.as_slice()))
            .collect();
        let merkle_tree = MerkleTree::new(shard_hashes, &self.hash_context);

        // Track the root hash to ensure speedy termination and redundant ECHO checks
        acss_va_state.verified_hash = Some(merkle_tree.root());

        let mut encrypted_share_vec = Vec::new();
        for (rep, (row_share, (brow_share, dzk_iter))) in (0..self.num_nodes).into_iter().zip(
            party_wise_row_shares.into_iter().zip(
                shares
                    .blinding_row_poly
                    .into_iter()
                    .zip(shares.dzk_iters.into_iter()),
            ),
        ) {
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            let point_bv: PointBV = (
                (
                    row_share
                        .into_iter()
                        .map(|el| el.to_bytes_be().to_vec())
                        .collect(),
                    shares.row_poly.1[rep].clone(),
                    shares.row_poly.2[rep].clone(),
                ),
                brow_share,
                dzk_iter,
            );

            let point_bv_ser = bincode::serialize(&point_bv).unwrap();
            let encrypted_shares = encrypt(secret_key.as_slice(), point_bv_ser.clone());

            encrypted_share_vec.push((rep, encrypted_shares));
        }

        acss_va_state
            .encrypted_shares
            .extend(encrypted_share_vec.clone());
        for (rep, enc_share) in encrypted_share_vec.into_iter() {
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            let rbc_msg = CTRBCMsg {
                shard: shards[self.myid].clone(),
                mp: merkle_tree.gen_proof(self.myid),
                origin: dealer,
            };
            let echo_msg = ProtMsg::Echo(rbc_msg, enc_share, instance_id);
            let wrapper_msg = WrapperMsg::new(echo_msg, self.myid, secret_key.as_slice());
            let cancel_handler: CancelHandler<Acknowledgement> =
                self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }

    // Note that vec<largefield> is a polynomial <largefield>
    fn agg_share_poly_dzk_batch(
        &self,
        coefficients: Vec<Vec<Polynomial<LargeField>>>,
        column_wise_roots: Vec<Hash>,
    ) -> Vec<Polynomial<LargeField>> {
        let mut root_mul_lf: Vec<LargeField> = column_wise_roots
            .iter()
            .map(|root| LargeField::from_bytes_be(root).unwrap())
            .collect();
        let roots_original = root_mul_lf.clone();
        let mut aggregated_coefficients = Vec::new();
        for _ in 0..self.num_nodes {
            let mut shares_app = Vec::new();
            for _ in 0..self.num_faults + 1 {
                shares_app.push(LargeField::from(0));
            }
            aggregated_coefficients.push(shares_app);
        }

        root_mul_lf = (0..column_wise_roots.len())
            .into_iter()
            .map(|_| LargeField::from(1))
            .collect();
        for bv_coeff_vec in coefficients {
            for (index, (share_poly, root_lf)) in
                (0..self.num_nodes).zip(bv_coeff_vec.into_iter().zip(root_mul_lf.iter()))
            {
                for (l2_index, share) in (0..self.num_faults + 1).zip(share_poly.coefficients.into_iter()) {
                    aggregated_coefficients[index][l2_index] += root_lf * share;
                }
            }
            for index in 0..self.num_nodes {
                root_mul_lf[index] = &root_mul_lf[index] * &roots_original[index];
            }
        }
        //aggregated_coefficients
        // create vector of polymomials based on aggreagated coeffiecients where the ith polymomial is Polynomial::new)aggregated_coefficients at the ith index)
        let mut polys = Vec::new();
        for coeff_vec in aggregated_coefficients {
            polys.push(Polynomial::new(&coeff_vec[..]));
        }
        polys
    }
}
