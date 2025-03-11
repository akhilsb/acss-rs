use consensus::{reconstruct_data, LargeField};
use crypto::{decrypt, hash::{Hash, do_hash}, aes_hash::{MerkleTree, Proof}, encrypt};
use ctrbc::CTRBCMsg;
use network::{plaintcp::CancelHandler, Acknowledgement};
use types::{Replica, WrapperMsg};

use crate::{Context, msg::{PointsBV, PointsBVSer, ProtMsg, Commitment}, protocol::BatchACSSState};
use lambdaworks_math::traits::ByteConversion;

impl Context{
    pub async fn process_ready(self: &mut Context, ctrbc_msg: CTRBCMsg, enc_share: Vec<u8>, ready_sender: Replica, instance_id: usize){
        log::trace!("Received {:?} as ready", ctrbc_msg);

        if !self.acss_state.contains_key(&instance_id){
            let acss_context = BatchACSSState::new(ctrbc_msg.origin);
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

        let deser_share: PointsBVSer = bincode::deserialize(dec_msg.as_slice()).unwrap();
        let points = PointsBV::from_ser(deser_share);
        acss_va_context.bv_ready_points.insert(ready_sender+1, points.clone());

        if ready_senders.len() >= self.num_faults + 1 && acss_va_context.verified_hash.is_none(){

            if acss_va_context.verified_hash.is_some() &&
                acss_va_context.verified_hash.unwrap() == root && 
                acss_va_context.ready_sent{
                log::error!("Ready already sent for ACSS instance {}", instance_id);
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
                let my_share:Vec<u8> = shards[self.myid].clone();

                let mut message: Vec<u8> = Vec::new();
                for i in 0..self.num_faults+1{
                    message.extend(shards.get(i).clone().unwrap());
                }

                // Reconstruct Merkle Root
                let shard_hashes: Vec<Hash> = shards.clone().into_iter().map(|v| do_hash(v.as_slice())).collect();
                let merkle_tree = MerkleTree::new(shard_hashes, &self.hash_context);

                if merkle_tree.root() == root{
                    if acss_va_context.verified_hash.is_none(){
                        acss_va_context.verified_hash = Some(root);
                        acss_va_context.rbc_state.message = Some(message.clone());
                        acss_va_context.rbc_state.echo_root = Some(root);
                        acss_va_context.rbc_state.fragment = Some((my_share.clone(),merkle_tree.gen_proof(self.myid)));
                    }

                    if !acss_va_context.col_share_map.is_empty(){
                        // Deserialize commitments
                        let (shard,mp) = acss_va_context.rbc_state.fragment.clone().unwrap();
                        let rbc_msg = CTRBCMsg{
                            shard: shard.clone(),
                            mp: mp,
                            origin: ctrbc_msg.origin
                        };
                        let trees_reconstructed = acss_va_context.col_merkle_trees.clone().unwrap();
                        let share_map = acss_va_context.col_share_map.clone();
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
            }
        }
        else if ready_senders.len() >= self.num_nodes - self.num_faults && !acss_va_context.terminated{ 
            log::info!("Received n-f READY messages for ACSS Instance ID {}",instance_id);
            if acss_va_context.rows_reconstructed{
                log::info!("Already verified row polynomials, terminating ACSS instance {}", instance_id);
            }
            else {
                // Interpolate share
                if acss_va_context.verified_hash.is_none(){
                    log::error!("This case has not been handled yet, abandoning ACSS instance {}",instance_id);
                    return;
                }
                let ser_commitment = acss_va_context.rbc_state.message.clone().unwrap();
                let commitment: Commitment = bincode::deserialize(&ser_commitment).unwrap();
                let bv_ready_points = acss_va_context.bv_ready_points.clone();

                // Sample F(x,0) polynomial next
                let eval_point_start: isize = ((self.num_faults) as isize) * (-1);
                let mut eval_point_indices_lf: Vec<LargeField> = (eval_point_start..1).into_iter().map(|index| LargeField::from(index as u64)).collect();
                eval_point_indices_lf.reverse();
                let eval_points_len = eval_point_indices_lf.len();

                let verf_status = self.interpolate_points_on_share_poly(
                    commitment.clone(), 
                    bv_ready_points, 
                    false, 
                    eval_point_indices_lf
                );

                if verf_status.is_none(){
                    log::error!("Row interpolation failed, abandoning ACSS instance {}", instance_id);
                    return;
                }
                
                let shares = verf_status.unwrap();
                let tot_batches = commitment.roots.len();
                for (batch, 
                    (batch_roots, 
                        (batch_blinding_commitments,
                            (dzk_poly, blinding_nonces)))) in 
                                (0..tot_batches).zip(commitment.roots.into_iter()
                                        .zip(commitment.blinding_roots.into_iter()
                                            .zip(commitment.dzk_poly.into_iter()
                                                .zip(commitment.blinding_nonces.into_iter())))){
                    let dzk_root = MerkleTree::new(batch_roots,&self.hash_context).root();
                    let blinding_commitment = batch_blinding_commitments[self.myid].clone();
                    let blinding_root = MerkleTree::new(batch_blinding_commitments, &self.hash_context).root();
                    let master_root_batch = self.hash_context.hash_two(dzk_root, blinding_root);
                    let mut master_root_lf = LargeField::from_bytes_be(master_root_batch.as_slice()).unwrap();
            
                    // Generate DZK polynomial
                    let mut agg_value = LargeField::from(0);
                    let polys_in_batch = commitment.batch_count;
                    let mut master_root_lf_mul= master_root_lf.clone();
                    for poly_index in 0..polys_in_batch{
                        for eval_index in 0..eval_points_len{
                            agg_value += shares[eval_index].0[batch][poly_index].clone()*&master_root_lf_mul;
                            master_root_lf_mul = &master_root_lf_mul*&master_root_lf;
                        }
                    }

                    
                    let dzk_poly_point = LargeField::from_bytes_be(dzk_poly[self.myid+1].clone().as_slice()).unwrap();
                    let mut sub_point = dzk_poly_point - agg_value;
              

                    let mut appended_poly = Vec::new();
                    appended_poly.extend(sub_point.to_bytes_be().to_vec());
                    appended_poly.extend(blinding_nonces[self.myid].clone());
                    let hash_blinding = do_hash(&appended_poly);

                    if hash_blinding != blinding_commitment{
                        log::error!("Error verifying DZK proof of polynomial, start blame process for ACSS instance {}",instance_id);
                        return;
                    }
                }
                log::info!("Verified dzk proofs for ACSS instance {}", instance_id);
                let acss_va_context: &mut BatchACSSState = self.acss_state.get_mut(&instance_id).unwrap();
                if acss_va_context.shares.is_none(){
                    // Interpolate and set shares. 
                    let mut shares_concatenated = Vec::new();
                    for shares_poly in shares{
                        for shares_each_row in shares_poly.0{
                            shares_concatenated.extend(shares_each_row);
                        }
                    }
                    acss_va_context.shares = Some(shares_concatenated);
                    acss_va_context.rows_reconstructed = true;
                }

            }
            log::info!("Received n-f READY messages for ACSS Instance ID {}, terminating",instance_id);
            // Terminate protocol
            // Interpolate rows and verify distributed ZK proof
            let acss_va_context: &mut BatchACSSState = self.acss_state.get_mut(&instance_id).unwrap();
            acss_va_context.terminated = true;
            let _term_msg = "Terminated";
            let shares = acss_va_context.shares.clone().unwrap();
            let root_commitment = acss_va_context.verified_hash.clone().unwrap();
            // Get shares and then terminate
            self.terminate(shares, root_commitment, instance_id).await;
        }
    }
    // Invoke this function once you terminate the protocol
    pub async fn terminate(&mut self, shares: Vec<LargeField>, root_comm: Hash, instance_id: usize) {
        
        let true_inst_id = instance_id%self.threshold;
        let sender_party = instance_id/self.threshold;
        log::info!("Terminating ACSS for instance id {}, true_inst_id: {}, sender_party: {}",instance_id, true_inst_id, sender_party);

        let shares_ser = shares.into_iter().map(|share| share.to_bytes_be().to_vec()).collect();
        let _status = self.out_acss_shares.send((true_inst_id, sender_party, root_comm, shares_ser)).await;
    }
}