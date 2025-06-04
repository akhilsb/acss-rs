use consensus::reconstruct_data;
use crypto::{hash::{Hash, do_hash}, aes_hash::MerkleTree};
use ctrbc::CTRBCMsg;
use types::Replica;

use crate::{context::Context, msg::ProtMsg};

use super::ASKSState;

impl Context{
    pub async fn process_asks_echo(&mut self, ctrbc_msg: CTRBCMsg, echo_sender: Replica, reconstruct_to_all: bool, instance_id: usize){
        log::info!("Processing ASKS ECHO from {} for instance {}", echo_sender, instance_id);
        if !self.asks_state.contains_key(&instance_id){
            let new_state = ASKSState::new(ctrbc_msg.origin, reconstruct_to_all);
            self.asks_state.insert(instance_id, new_state);
        }

        let asks_state = self.asks_state.get_mut(&instance_id).unwrap();

        if asks_state.terminated{
            // ACSS already terminated, skip processing this message
            log::debug!("ASKS {} already terminated, skipping ECHO processing",instance_id);
            return;
        }

        if !ctrbc_msg.verify_mr_proof(&self.hash_context) {
            log::error!(
                "Invalid Merkle Proof sent by node {}, abandoning ECHO",
                echo_sender
            );
            return;
        }

        let root = ctrbc_msg.mp.root();
        let echo_senders = asks_state.rbc_state.echos.entry(root).or_default();

        if echo_senders.contains_key(&echo_sender){
            return;
        }

        echo_senders.insert(echo_sender, ctrbc_msg.shard);
        
        let size = echo_senders.len().clone();
        if size == self.num_nodes - self.num_faults{
            log::info!("Received n-f ECHO messages for ASKS Instance ID {}, sending READY message",instance_id);
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
            let hashes_rbc: Vec<Hash> = shards
                .into_iter()
                .map(|x| do_hash(x.as_slice()))
                .collect();

            let merkle_tree = MerkleTree::new(hashes_rbc, &self.hash_context);
            if merkle_tree.root() == root{
                
                // ECHO phase is completed. Save our share and the root for later purposes and quick access. 
                asks_state.rbc_state.echo_root = Some(root);
                asks_state.rbc_state.fragment = Some((my_share.clone(),merkle_tree.gen_proof(self.myid)));
                asks_state.rbc_state.message = Some(message.clone());

                let deser_root_vec: Vec<Hash> = bincode::deserialize(&message).unwrap();
                asks_state.roots = Some(deser_root_vec);

                // Send ready message
                let ctrbc_msg = CTRBCMsg{
                    shard: my_share,
                    mp: merkle_tree.gen_proof(self.myid),
                    origin: ctrbc_msg.origin,
                };
                
                //self.handle_ready(ctrbc_msg.clone(),ctrbc_msg.origin,instance_id).await;
                let ready_msg = ProtMsg::Ready(ctrbc_msg, reconstruct_to_all, instance_id);
                self.broadcast(ready_msg).await;
            }
        }
        // Go for optimistic termination if all n shares have appeared
        else if size == self.num_nodes{
            log::info!("Received n ECHO messages for ASKS Instance ID {}, terminating",instance_id);
            // Do not reconstruct the entire root again. Just send the merkle proof
            
            let echo_root = asks_state.rbc_state.echo_root.clone();

            if echo_root.is_some() && !asks_state.terminated{
                asks_state.terminated = true;
                let _message = asks_state.rbc_state.message.clone().unwrap();
                //self.reconstruct_asks(instance_id).await;
                self.terminate(instance_id, None).await;
            }
        }
    }
}