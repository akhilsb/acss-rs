use consensus::reconstruct_data;
use crypto::{hash::{do_hash, Hash}, aes_hash::MerkleTree};
use ctrbc::CTRBCMsg;
use network::{plaintcp::CancelHandler, Acknowledgement};
use num_bigint_dig::BigInt;
use types::{Replica, WrapperMsg};

use crate::{Context, PointBV, ACSSVAState, VACommitment, ProtMsg};

impl Context{
    pub async fn process_echo(self: &mut Context, ctrbcmsg: CTRBCMsg, point: PointBV, echo_sender: Replica, instance_id: usize){
        
        if !self.acss_state.contains_key(&instance_id){
            let acss_va_state = ACSSVAState::new(ctrbcmsg.origin);
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

        let root = ctrbcmsg.mp.root();
        let echo_senders = acss_va_state.rbc_state.echos.entry(root).or_default();

        if echo_senders.contains_key(&echo_sender){
            return;
        }

        echo_senders.insert(echo_sender, ctrbcmsg.shard);
        acss_va_state.bv_echo_points.insert(echo_sender, point);
        let size = echo_senders.len().clone();
        if size == self.num_nodes - self.num_faults {
            log::info!("Received n-f ECHO messages for ACSS Instance ID {}, sending READY message",instance_id);
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
            
            let mut message = Vec::new();
            for i in 0..self.num_faults+1{
                message.extend(shards.get(i).clone().unwrap());
            }

            let my_share:Vec<u8> = shards[self.myid].clone();

            // Reconstruct Merkle Root
            let shard_hashes: Vec<Hash> = shards.into_iter().map(|v| do_hash(v.as_slice())).collect();
            let merkle_tree = MerkleTree::new(shard_hashes, &self.hash_context);

            //let mut send_ready = false;
            if merkle_tree.root() == root{
                // ECHO phase is completed. Save our share and the root for later purposes and quick access. 
                acss_va_state.rbc_state.echo_root = Some(root);
                acss_va_state.rbc_state.fragment = Some((my_share.clone(),merkle_tree.gen_proof(self.myid)));
                acss_va_state.rbc_state.message = Some(message.clone());

                // Deserialize commitments
                let comm_hash = do_hash(message.as_slice());
                let comm: VACommitment = bincode::deserialize(message.as_slice()).unwrap();
                if acss_va_state.verified_hash.is_some(){
                    // Verify the equality of all Merkle roots
                    if acss_va_state.verified_hash.clone().unwrap() == comm_hash{
                        // Successfully the reconstructed commitment. Send READY messages now. 
                        let rbc_msg = CTRBCMsg{
                            shard: my_share.clone(),
                            mp: merkle_tree.gen_proof(self.myid),
                            origin: origin
                        };
                        //self.handle_ready(ctrbc_msg.clone(),msg.origin,instance_id).await;
                        let attach_enc_shares = true;
                        let encrypted_shares = acss_va_state.encrypted_shares.clone();
                        for rep in 0..self.num_nodes{
                            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
                            // Fetch previously encrypted shares
                            let mut enc_share = Vec::new();
                            if attach_enc_shares{
                                enc_share.extend(encrypted_shares[rep].clone().1);
                            }
                            let ready_msg = ProtMsg::Ready(rbc_msg.clone(), enc_share, instance_id);
                            let wrapper_msg = WrapperMsg::new(ready_msg, self.myid, &secret_key);
                            let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(rep, wrapper_msg).await;
                            self.add_cancel_handler(cancel_handler);
                        }
                    }
                }
                else{
                    // Verify DZK proofs first
                    let mut column_evaluation_points = Vec::new();
                    let mut nonce_evaluation_points = Vec::new();

                    let mut blinding_evaluation_points = Vec::new();
                    let mut blinding_nonce_points = Vec::new();

                    let bv_echo_points = acss_va_state.bv_echo_points.clone();
                    for (rep,dzk_poly) in (0..self.num_nodes).into_iter().zip(comm.polys){
                        
                        if bv_echo_points.contains_key(&rep){
                            
                            let (column_share,bcolumn_share, dzk_iter) = bv_echo_points.get(&rep).unwrap();
                            // Combine column and blinding column roots
                            let combined_root = self.hash_context.hash_two(column_share.2.root(), bcolumn_share.2.root());
                            let point = BigInt::from_signed_bytes_be(column_share.0.as_slice());
                            let nonce = BigInt::from_signed_bytes_be(column_share.1.as_slice());

                            let blinding_point = BigInt::from_signed_bytes_be(bcolumn_share.0.as_slice()); 
                            let blinding_nonce = BigInt::from_signed_bytes_be(bcolumn_share.1.as_slice());

                            if self.verify_dzk_proof(dzk_iter.clone() , 
                                        comm.dzk_roots[rep].clone(), 
                                                    dzk_poly, 
                                                    combined_root, 
                                                    point.clone(), 
                                                    blinding_point.clone(), 
                                                    rep){
                                column_evaluation_points.push((BigInt::from(rep+1), point.clone()));
                                nonce_evaluation_points.push((BigInt::from(rep+1), nonce));

                                blinding_evaluation_points.push((BigInt::from(rep+1), blinding_point.clone()));
                                blinding_nonce_points.push((BigInt::from(rep+1), blinding_nonce));
                            }

                            // acss_va_state.column_shares.insert(rep , (point, BigInt::from_signed_bytes_be(column_share.1.as_slice())));
                            // acss_va_state.bcolumn_shares.insert(rep, (blinding_point, BigInt::from_signed_bytes_be(bcolumn_share.1.as_slice())));
                            
                            if column_evaluation_points.len() == self.num_faults + 1{
                                break;
                            }
                        }
                    }
                    if column_evaluation_points.len() < self.num_faults +1 {
                        log::error!("Did not receive enough valid points from other parties, abandoning ACSS {}", instance_id);
                        return;
                    }
                    // Re borrow here
                    let acss_va_state = self.acss_state.get_mut(&instance_id).unwrap();
                    // Interpolate column
                    let poly_coeffs = self.large_field_uv_sss.polynomial_coefficients(&column_evaluation_points);
                    let nonce_coeffs = self.large_field_uv_sss.polynomial_coefficients(&nonce_evaluation_points);

                    let bpoly_coeffs = self.large_field_uv_sss.polynomial_coefficients(&blinding_evaluation_points);
                    let bnonce_coeffs = self.large_field_uv_sss.polynomial_coefficients(&blinding_nonce_points);
                    
                    // Used for error correction
                    let secret_share = poly_coeffs[0].clone();
                    
                    // Fill up column shares
                    for rep in 0..self.num_nodes{
                        if !acss_va_state.column_shares.contains_key(&rep){
                            acss_va_state.column_shares.insert(rep, 
                                (self.large_field_uv_sss.mod_evaluate_at(&poly_coeffs, rep+1),
                                self.large_field_uv_sss.mod_evaluate_at(&nonce_coeffs, rep+1)));
                            acss_va_state.bcolumn_shares.insert(rep, 
                                (self.large_field_uv_sss.mod_evaluate_at(&bpoly_coeffs, rep+1),
                            self.large_field_uv_sss.mod_evaluate_at(&bnonce_coeffs, rep+1)));
                        }
                    }
                    let rbc_msg = CTRBCMsg{
                        shard: my_share.clone(),
                        mp: merkle_tree.gen_proof(self.myid),
                        origin: origin
                    };
                    //self.handle_ready(ctrbc_msg.clone(),msg.origin,instance_id).await;
                    let attach_enc_shares = true;
                    let encrypted_shares = acss_va_state.encrypted_shares.clone();
                    for rep in 0..self.num_nodes{
                        let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
                        // Fetch previously encrypted shares
                        let mut enc_share = Vec::new();
                        if attach_enc_shares{
                            enc_share.extend(encrypted_shares[rep].clone().1);
                        }
                        let ready_msg = ProtMsg::Ready(rbc_msg.clone(), enc_share, instance_id);
                        let wrapper_msg = WrapperMsg::new(ready_msg, self.myid, &secret_key);
                        let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(rep, wrapper_msg).await;
                        self.add_cancel_handler(cancel_handler);
                    }
                }
            }
        }
        // Go for optimistic termination if all n shares have appeared
        else if size == self.num_nodes{
            log::info!("Received n ECHO messages for ACSS Instance ID {}, terminating",instance_id);
            // Do not reconstruct the entire root again. Just send the merkle proof
            
            let echo_root = acss_va_state.verified_hash.clone();

            if echo_root.is_some() && !acss_va_state.terminated{
                acss_va_state.terminated = true;
                // Send Ready and terminate

                let fragment = acss_va_state.rbc_state.fragment.clone().unwrap();
                let ctrbc_msg = CTRBCMsg{
                    shard: fragment.0,
                    mp: fragment.1, 
                    origin: acss_va_state.origin,
                };

                let attach_enc_shares = acss_va_state.encrypted_shares.len() > 0;
                let encrypted_shares = acss_va_state.encrypted_shares.clone();
                //self.handle_ready(ctrbc_msg.clone(),msg.origin,instance_id).await;
                for rep in 0..self.num_nodes{
                    let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
                    // Fetch previously encrypted shares
                    let mut enc_share = Vec::new();
                    if attach_enc_shares {
                        enc_share.extend(encrypted_shares[rep].clone().1);
                    }
                    let ready_msg = ProtMsg::Ready(ctrbc_msg.clone(), enc_share, instance_id);
                    let wrapper_msg = WrapperMsg::new(ready_msg, self.myid, &secret_key);
                    let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(rep, wrapper_msg).await;
                    self.add_cancel_handler(cancel_handler);
                }
                //self.terminate(msg.origin, message).await;
            }
        } 
    }
}