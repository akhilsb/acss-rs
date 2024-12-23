use consensus::reconstruct_data;
use crypto::{hash::{do_hash, Hash}, aes_hash::MerkleTree, decrypt};
use ctrbc::CTRBCMsg;
use network::{plaintcp::CancelHandler, Acknowledgement};

use types::{Replica, WrapperMsg};

use crate::{Context, PointBV, ACSSVAState, VACommitment, ProtMsg};

impl Context{
    pub async fn process_echo(self: &mut Context, ctrbcmsg: CTRBCMsg, encrypted_share: Vec<u8>, echo_sender: Replica, instance_id: usize){
        
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
        let secret_key_echo_sender = self.sec_key_map.get(&echo_sender).clone().unwrap();
        let decrypted_message = decrypt(&secret_key_echo_sender, encrypted_share);
        let point: PointBV = bincode::deserialize(decrypted_message.as_slice()).unwrap();

        let root = ctrbcmsg.mp.root();
        let echo_senders = acss_va_state.rbc_state.echos.entry(root).or_default();

        if echo_senders.contains_key(&echo_sender){
            return;
        }

        echo_senders.insert(echo_sender, ctrbcmsg.shard);
        acss_va_state.bv_echo_points.insert(echo_sender, point);
        let size = echo_senders.len().clone();

        if size == self.num_nodes - self.num_faults {
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
                let comm: VACommitment = bincode::deserialize(message.as_slice()).unwrap();
                
                if acss_va_state.verified_hash.is_some(){

                    // Verify the equality of all Merkle roots
                    if acss_va_state.verified_hash.clone().unwrap() == root{
                        // Successfully the reconstructed commitment. Send READY messages now. 
                        // Code repetition exists. Mainly because of Rust's mutable borrow restrictions
                        let rbc_msg = CTRBCMsg{
                            shard: my_share.clone(),
                            mp: merkle_tree.gen_proof(self.myid),
                            origin: origin
                        };
                        //self.handle_ready(ctrbc_msg.clone(),msg.origin,instance_id).await;
                        log::info!("Sending Ready message");

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
                    let bv_echo_points = acss_va_state.bv_echo_points.clone();
                    let proof_status = self.verify_dzk_proofs_column(
                        comm.dzk_roots[self.myid].clone(), 
                            comm.polys[self.myid].clone(), 
                            bv_echo_points,
                            instance_id
                        );
                    if proof_status.is_none(){
                        log::error!("Error verifying distributed ZK proofs for points on column of {} in ACSS instance {}", self.myid, instance_id);
                        return;
                    }
                    let (poly_coeffs,nonce_coeffs, bpoly_coeffs,bnonce_coeffs) = proof_status.unwrap();
                    // Used for error correction
                    let acss_va_state = self.acss_state.get_mut(&instance_id).unwrap();
                    let secret_share = poly_coeffs[0].clone();
                    
                    acss_va_state.verified_hash = Some(root);
                    acss_va_state.secret = Some(secret_share);
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
                    log::info!("Sending Ready message");
                    let rbc_msg = CTRBCMsg{
                        shard: my_share.clone(),
                        mp: merkle_tree.gen_proof(self.myid),
                        origin: origin
                    };
                    //self.handle_ready(ctrbc_msg.clone(),msg.origin,instance_id).await;
                    let attach_enc_shares = acss_va_state.encrypted_shares.len() > 0;
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
            else {
                log::error!("Root verification failed, abandoning ACSS instance {}", instance_id);
            }
        }
        // Go for optimistic termination if all n shares have appeared
        else if size == self.num_nodes{
            // log::info!("Received n ECHO messages for ACSS Instance ID {}, terminating",instance_id);
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