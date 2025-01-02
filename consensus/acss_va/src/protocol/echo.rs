use consensus::reconstruct_data;
use crypto::{hash::{do_hash, Hash}, aes_hash::{MerkleTree, Proof}, decrypt, encrypt, LargeField};
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

        if size >= self.num_faults +1  && !acss_va_state.cols_reconstructed{
            log::info!("Received f+1 ECHO messages for ACSS Instance ID {}, verifying root validity",instance_id);
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
                
                let verf_status = self.interpolate_points_on_share_poly(
                    comm.clone(), 
                    bv_echo_points,
                    true,
                    (1..self.num_nodes+1).into_iter().map(|el| LargeField::from(el)).collect()
                );
                if verf_status.is_none(){
                    log::error!("Error verifying column polynomials, abandoning ACSS instance {}",instance_id);
                    return;
                }

                let share_map = verf_status.unwrap();
                let mut commitments_columns = Vec::new();
                for _ in 0..comm.roots.len(){
                    commitments_columns.push(Vec::new());
                }
                // Construct commitments
                for shares_col in share_map.clone(){
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
                        return;
                    }
                }

                log::info!("Successfully reconstructed all roots and verified column polynomials in ACSS instance {}", instance_id);
                let acss_va_state = self.acss_state.get_mut(&instance_id).unwrap();
                acss_va_state.cols_reconstructed = true;
                // Verify if roots match and then send READY message. 
                
                acss_va_state.verified_hash = Some(root);
                // acss_va_state.secret = Some(secret_share);
                // // Fill up column shares
                acss_va_state.col_share_map.extend(share_map);
                acss_va_state.col_merkle_trees = Some(trees_reconstructed);
            }
            else {
                log::error!("Root verification failed, abandoning ACSS instance {}", instance_id);
            }
        }
        else if size == self.num_nodes - self.num_faults{
            if acss_va_state.cols_reconstructed && 
                acss_va_state.verified_hash.is_some() &&
                acss_va_state.verified_hash.unwrap() == ctrbcmsg.mp.root(){
                acss_va_state.ready_sent = true;
                log::info!("Received n-f ECHO messages for ACSS instance with ID {}, sending Ready message",instance_id);
                let (shard,mp) = acss_va_state.rbc_state.fragment.clone().unwrap();
                let rbc_msg = CTRBCMsg{
                    shard: shard.clone(),
                    mp: mp,
                    origin: origin
                };
                let trees_reconstructed = acss_va_state.col_merkle_trees.clone().unwrap();
                let share_map = acss_va_state.col_share_map.clone();
                for (rep, shares) in (0..self.num_nodes).into_iter().zip(share_map.into_iter()){
                    let recipient = rep;
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
        }
        // Go for optimistic termination if all n shares have appeared
        else if size == self.num_nodes{
            // Do not reconstruct the entire root again. Just send the merkle proof
            if acss_va_state.cols_reconstructed && acss_va_state.rows_reconstructed{
                log::info!("Received n ECHO messages for ACSS Instance ID {}, terminating",instance_id);
                acss_va_state.terminated = true;
                self.terminate("Terminated".to_string(), instance_id).await;
            }
        } 
    }
}