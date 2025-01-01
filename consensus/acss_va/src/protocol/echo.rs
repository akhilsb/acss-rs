use std::collections::{HashMap, HashSet};

use consensus::reconstruct_data;
use crypto::{hash::{do_hash, Hash}, aes_hash::{MerkleTree, Proof}, decrypt, LargeField, encrypt};
use ctrbc::CTRBCMsg;
use network::{plaintcp::CancelHandler, Acknowledgement};

use types::{Replica, WrapperMsg};

use crate::{Context, msg::{PointsBV, PointsBVSer, Commitment, ProtMsg}};

use super::BatchACSSState;

impl Context{
    pub async fn process_echo(self: &mut Context, ctrbcmsg: CTRBCMsg, encrypted_share: Vec<u8>, echo_sender: Replica, instance_id: usize){
        
        if !self.acss_state.contains_key(&instance_id){
            let acss_va_state = BatchACSSState::new(ctrbcmsg.origin);
            self.acss_state.insert(instance_id, acss_va_state);
        }

        let acss_va_state = self.acss_state.get_mut(&instance_id).unwrap();
        let origin = acss_va_state.origin;

        if acss_va_state.terminated{
            // ACSS already terminated, skip processing this message
            log::debug!("ACSS {} already terminated, skipping ECHO processing",instance_id);
            return;
        }
        
        if !ctrbcmsg.verify_mr_proof(&self.hash_context) {
            log::error!(
                "Invalid Merkle Proof sent by node {}, abandoning RBC",
                echo_sender
            );
            return;
        }
        let secret_key_echo_sender = self.sec_key_map.get(&echo_sender).clone().unwrap();
        let decrypted_message = decrypt(&secret_key_echo_sender, encrypted_share);
        let point_ser: PointsBVSer = bincode::deserialize(decrypted_message.as_slice()).unwrap();

        let deser_point = PointsBV::from_ser(point_ser);
        let root = ctrbcmsg.mp.root();
        let echo_senders = acss_va_state.rbc_state.echos.entry(root).or_default();

        if echo_senders.contains_key(&echo_sender){
            return;
        }

        echo_senders.insert(echo_sender, ctrbcmsg.shard);
        // echo_sender+1 because we use point i+1 as replica i's input point
        acss_va_state.bv_echo_points.insert(echo_sender+1, deser_point);
        let size = echo_senders.len().clone();

        if size >= self.num_nodes - self.num_faults && !acss_va_state.cols_reconstructed{
            log::info!("Received n-f ECHO messages for ACSS Instance ID {}, verifying root validity",instance_id);
            let senders = echo_senders.clone();

            // Reconstruct the entire Merkle tree
            let mut shards:Vec<Option<Vec<u8>>> = Vec::new();
            for rep in 0..self.num_nodes{
                
                if senders.contains_key(&rep){
                    shards.push(Some(senders.get(&rep).unwrap().clone()));
                }

                else{
                    shards.push(None);
                }
            }

            let status = reconstruct_data(&mut shards, self.num_faults+1 , 2*self.num_faults);
            
            if status.is_err(){
                log::error!("FATAL: Error in Lagrange interpolation {}",status.err().unwrap());
                return;
            }
            let shards:Vec<Vec<u8>> = shards.into_iter().map(| opt | opt.unwrap()).collect();

            // Reconstruct Merkle Root
            let shard_hashes: Vec<Hash> = shards.clone().into_iter().map(|v| do_hash(v.as_slice())).collect();
            let merkle_tree = MerkleTree::new(shard_hashes, &self.hash_context);

            //let mut send_ready = false;
            if merkle_tree.root() == root{
            
                let mut message = Vec::new();
                for i in 0..self.num_faults+1{
                    message.extend(shards.get(i).clone().unwrap());
                }

                let my_share:Vec<u8> = shards[self.myid].clone();

                log::info!("Successfully verified commitment for ACSS instance {}",instance_id);
                // ECHO phase is completed. Save our share and the root for later purposes and quick access. 
                acss_va_state.rbc_state.echo_root = Some(root);
                acss_va_state.rbc_state.fragment = Some((my_share.clone(),merkle_tree.gen_proof(self.myid)));
                acss_va_state.rbc_state.message = Some(message.clone());

                // Deserialize commitments
                let comm: Commitment = bincode::deserialize(message.as_slice()).unwrap();
                
                // Verify DZK proofs first
                let bv_echo_points = acss_va_state.bv_echo_points.clone();
                // Reconstruct Merkle root and verify if it matches the broadcasted row polynomials
                
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
                    if !bv_echo_points.contains_key(&(rep+1)){
                        continue;
                    }
                    let col_points = bv_echo_points.get(&(rep+1)).unwrap();
                    let roots_vec: Vec<Hash> = comm.roots.iter().map(|batch_root_vec| batch_root_vec[self.myid].clone()).collect();
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
                        if total_points >= self.num_faults+1{
                            break;
                        }
                    }
                    else {
                        log::error!("Error verifying Merkle proofs of point on column sent by {}",rep);
                    }
                }
                if total_points < self.num_faults + 1{
                    log::error!("Not enough points received for polynomial interpolation, waiting for more shares");
                    return;
                }

                // Construct Vandermonde inverse matrix for the given set of indices
                let mut indices_vec: Vec<usize> = indices_verified_points.iter().map(|el| el.clone()).collect();
                indices_vec.sort();
                let mut indices_lf: Vec<LargeField> = indices_verified_points.iter().map(|el| LargeField::from(*el)).collect();
                indices_lf.sort();
                let vandermonde_matrix = self.large_field_uv_sss.vandermonde_matrix(&indices_lf);
                let inverse_vandermonde = self.large_field_uv_sss.inverse_vandermonde(vandermonde_matrix);

                // Shares and nonces of each replica
                let mut share_map: HashMap<Replica, (Vec<Vec<LargeField>>, Vec<LargeField>)> = HashMap::default();
                
                for rep in 0..self.num_nodes{
                    let mut shares_batch = Vec::new();
                    let num_batches = comm.roots.len();
                    for _ in 0..num_batches{
                        shares_batch.push(Vec::new());
                    }
                    share_map.insert(rep+1, (shares_batch,Vec::new()));
                }
                // Reconstruct column polynomials and construct commitments

                let mut batch_index = 0;
                for (eval_points_batch_wise, nonce_points_batch_wise) in verified_points.into_iter().zip(nonce_points.into_iter()){
                    let nonce_interpolated_batch_coeffs = self.large_field_uv_sss.polynomial_coefficients_with_vandermonde_matrix(&inverse_vandermonde, &nonce_points_batch_wise);
                    
                    for (party_index,point) in indices_vec.iter().zip(nonce_points_batch_wise.into_iter()){
                        let (_,nonce_map) = share_map.get_mut(party_index).unwrap();
                        nonce_map.push(point);
                    }
                    
                    for rep in 0..self.num_nodes{
                        if !indices_verified_points.contains(&(rep+1)){
                            let eval_point = self.large_field_uv_sss.mod_evaluate_at(&nonce_interpolated_batch_coeffs, rep+1);
                            let (_, nonce_map) = share_map.get_mut(&(rep+1)).unwrap();
                            nonce_map.push(eval_point);
                        }
                    }

                    for eval_points_single_bv in eval_points_batch_wise.into_iter(){
                        let single_bv_coefficients = self.large_field_uv_sss.polynomial_coefficients_with_vandermonde_matrix(&inverse_vandermonde, &eval_points_single_bv);
                        for (party_index, point) in indices_vec.iter().zip(eval_points_single_bv.into_iter()){
                            let (eval_polys, _) = share_map.get_mut(party_index).unwrap();
                            eval_polys[batch_index].push(point);
                        }

                        for rep in 0..self.num_nodes{
                            if !indices_verified_points.contains(&(rep+1)){
                                let eval_point = self.large_field_uv_sss.mod_evaluate_at(&single_bv_coefficients, rep+1);
                                let (eval_polys, _) = share_map.get_mut(&(rep+1)).unwrap();
                                eval_polys[batch_index].push(eval_point);
                            }
                        }
                    }
                    batch_index +=1;
                }
                let mut commitments_columns = Vec::new();
                for _ in 0..comm.roots.len(){
                    commitments_columns.push(Vec::new());
                }
                // Construct commitments
                for rep in 0..self.num_nodes{
                    let shares_col = share_map.get(&(rep+1)).unwrap();
                    let commitments = Self::generate_commitments_element(shares_col.0.clone(), shares_col.1.clone());
                    for (index,commitment) in (0..commitments.len()).zip(commitments.into_iter()){
                        commitments_columns[index].push(commitment);
                    }
                }
                
                let mut trees_reconstructed: Vec<MerkleTree> = Vec::new();
                for comm_vec in commitments_columns.into_iter(){
                    trees_reconstructed.push(MerkleTree::new(comm_vec, &self.hash_context));
                }
                let reconstructed_roots: Vec<Hash> = trees_reconstructed.iter().map(|tree| tree.root()).collect();
                // Match reconstructed roots with column roots
                for (recon_root, root_vec) in reconstructed_roots.into_iter().zip(comm.roots.into_iter()){
                    if recon_root != root_vec[self.myid]{
                        log::error!("Reconstructed root does not match original root, abandoning ACSS instance {}", instance_id);
                        return ;
                    }
                }

                log::info!("Successfully reconstructed all roots and verified column polynomials in ACSS instance {}", instance_id);
                acss_va_state.cols_reconstructed = true;
                // Verify if roots match and then send READY message. 
                
                acss_va_state.verified_hash = Some(root);
                // acss_va_state.secret = Some(secret_share);
                // // Fill up column shares
                
                log::info!("Sending Ready message");
                let rbc_msg = CTRBCMsg{
                    shard: my_share.clone(),
                    mp: merkle_tree.gen_proof(self.myid),
                    origin: origin
                };
                
                for (rep, shares) in share_map.into_iter(){
                    let recipient = rep-1;
                    let secret_key = self.sec_key_map.get(&(recipient)).clone().unwrap();
                    // Fetch previously encrypted shares
                    let proofs: Vec<Proof> = trees_reconstructed.iter().map(|tree| tree.gen_proof(recipient)).collect();
                    let point_bv = PointsBV{
                        evaluations: shares.0,
                        nonce_evaluation: shares.1,
                        proof: proofs,
                    };
                    let ser_share = point_bv.to_ser();
                    let enc_share = encrypt(secret_key, bincode::serialize(&ser_share).unwrap());

                    let ready_msg = ProtMsg::Ready(rbc_msg.clone(), enc_share, instance_id);
                    let wrapper_msg = WrapperMsg::new(ready_msg, self.myid, &secret_key);
                    let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(recipient, wrapper_msg).await;
                    self.add_cancel_handler(cancel_handler);
                }
            }
            else {
                log::error!("Root verification failed, abandoning ACSS instance {}", instance_id);
            }
        }
        // Go for optimistic termination if all n shares have appeared
        else if size == self.num_nodes{
            // Do not reconstruct the entire root again. Just send the merkle proof
            
            if acss_va_state.cols_reconstructed && acss_va_state.rows_reconstructed{
                log::info!("Received n ECHO messages for ACSS Instance ID {}, terminating",instance_id);
                acss_va_state.terminated = true;
                // Send Ready and terminate

                // let fragment = acss_va_state.rbc_state.fragment.clone().unwrap();
                // let ctrbc_msg = CTRBCMsg{
                //     shard: fragment.0,
                //     mp: fragment.1, 
                //     origin: acss_va_state.origin,
                // };

                // let attach_enc_shares = acss_va_state.encrypted_shares.len() > 0;
                // let encrypted_shares = acss_va_state.encrypted_shares.clone();
                //self.handle_ready(ctrbc_msg.clone(),msg.origin,instance_id).await;
                // for rep in 0..self.num_nodes{
                //     let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
                //     // Fetch previously encrypted shares
                //     let mut enc_share = Vec::new();
                //     if attach_enc_shares {
                //         enc_share.extend(encrypted_shares[rep].clone().1);
                //     }
                //     let ready_msg = ProtMsg::Ready(ctrbc_msg.clone(), enc_share, instance_id);
                //     let wrapper_msg = WrapperMsg::new(ready_msg, self.myid, &secret_key);
                //     let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(rep, wrapper_msg).await;
                //     self.add_cancel_handler(cancel_handler);
                // }
                //self.terminate("Terminated".to_string(), instance_id).await;
            }
        } 
    }
}