use consensus::reconstruct_data;
use crypto::{decrypt, hash::{Hash, do_hash}, aes_hash::MerkleTree};
use ctrbc::CTRBCMsg;
use network::{plaintcp::CancelHandler, Acknowledgement};
use types::{Replica, WrapperMsg};

use crate::{Context, ACSSVAState, PointBV, VACommitment, ProtMsg};

impl Context{
    pub async fn process_ready_vf(self: &mut Context, ctrbc_msg: CTRBCMsg, enc_share: Vec<u8>, ready_sender: Replica, instance_id: usize){
        log::trace!("Received {:?} as ready", ctrbc_msg);

        if !self.acss_state.contains_key(&instance_id){
            let acss_context = ACSSVAState::new(ctrbc_msg.origin);
            self.acss_state.insert(instance_id, acss_context);
        }

        let acss_va_context = self.acss_state.get_mut(&instance_id).unwrap();

        if acss_va_context.terminated{
            return;
            // ACSS Context already terminated, skip processing this message
        }

        if !ctrbc_msg.verify_mr_proof(&self.hash_context){
            log::error!(
                "Invalid Merkle Proof sent by node {}, abandoning ACSS instance {}",
                ready_sender, instance_id
            );
            return;
        }

        let root = ctrbc_msg.mp.root();
        let ready_senders = acss_va_context.rbc_state.readys.entry(root).or_default();

        if ready_senders.contains_key(&ready_sender){
            return;
            // Already processed ready from this sender, skip processing this message
        }

        ready_senders.insert(ready_sender, ctrbc_msg.shard);
        // Decrypt share
        let secret_key_ready_sender = self.sec_key_map.get(&ready_sender).clone().unwrap();
        let dec_msg = decrypt(&secret_key_ready_sender, enc_share);

        let deser_share: PointBV = bincode::deserialize(dec_msg.as_slice()).unwrap();
        acss_va_context.bv_ready_points.insert(ready_sender, deser_share);

        if ready_senders.len() == self.num_faults + 1{

            if acss_va_context.rbc_state.echo_root.is_some() && 
                acss_va_context.rbc_state.echo_root.unwrap() == root &&
                acss_va_context.verified_hash.is_some() &&
                acss_va_context.verified_hash.unwrap() == root{
                // Upon these conditions being true, just wait for n-f readys because we already conducted these checks
                return;
            }
            else{
                // Verify the points sent by parties
                // Reconstruct the entire Merkle tree
                let mut shards:Vec<Option<Vec<u8>>> = Vec::new();
                for rep in 0..self.num_nodes{
                    
                    if ready_senders.contains_key(&rep){
                        shards.push(Some(ready_senders.get(&rep).unwrap().clone()));
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
                
                let mut message: Vec<u8> = Vec::new();
                for i in 0..self.num_faults+1{
                    message.extend(shards.get(i).clone().unwrap());
                }

                let my_share:Vec<u8> = shards[self.myid].clone();
                // Reconstruct Merkle Root
                let shard_hashes: Vec<Hash> = shards.clone().into_iter().map(|v| do_hash(v.as_slice())).collect();
                let merkle_tree = MerkleTree::new(shard_hashes, &self.hash_context);

                if merkle_tree.root() == root{
                    // Deserialize commitments
                    let comm: VACommitment = bincode::deserialize(message.as_slice()).unwrap();
                    let bv_ready_points = acss_va_context.bv_ready_points.clone();

                    let proof_status = self.verify_dzk_proofs_column(
                        comm.dzk_roots[self.myid].clone(), 
                        comm.polys[self.myid].clone(), 
                        bv_ready_points, 
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
                        origin: ctrbc_msg.origin
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
        }
        else if ready_senders.len() == self.num_nodes - self.num_faults{
            log::info!("Received n-f READY messages for ACSS Instance ID {}, terminating",instance_id);
            // Terminate protocol
            acss_va_context.terminated = true;
            let _term_msg = acss_va_context.secret.clone().unwrap();
            //self.terminate(msg.origin,term_msg).await;
        }
    }
}