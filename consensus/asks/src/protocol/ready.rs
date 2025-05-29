use consensus::reconstruct_data;
use crypto::{hash::{Hash, do_hash}, aes_hash::MerkleTree, LargeField};
use ctrbc::CTRBCMsg;
use types::Replica;

use crate::{context::Context, protocol::ASKSState, msg::ProtMsg};

impl Context{

    pub async fn process_asks_ready(&mut self, ctrbc_msg: CTRBCMsg, ready_sender: Replica, reconstruct_to_all: bool,instance_id: usize){
        log::info!("Processing ASKS READY from {} for instance {}", ready_sender, instance_id);
        if !self.asks_state.contains_key(&instance_id){
            let asks_state = ASKSState::new(ctrbc_msg.origin, reconstruct_to_all);
            self.asks_state.insert(instance_id, asks_state);
        }

        let asks_context = self.asks_state.get_mut(&instance_id).unwrap();

        if asks_context.terminated{
            return;
            // RBC Context already terminated, skip processing this message
        }
        // check if verifies
        if !ctrbc_msg.verify_mr_proof(&self.hash_context) {
            log::error!(
                "Invalid Merkle Proof sent by node {}, abandoning RBC",
                ready_sender
            );
            return;
        }

        let root = ctrbc_msg.mp.root();
        let ready_senders = asks_context.rbc_state.readys.entry(root).or_default();

        if ready_senders.contains_key(&ready_sender){
            return;
        }

        ready_senders.insert(ready_sender, ctrbc_msg.shard);

        let size = ready_senders.len().clone();

        if size == self.num_faults + 1{

            // Sent ECHOs and getting a ready message for the same ECHO
            if asks_context.rbc_state.echo_root.is_some() && asks_context.rbc_state.echo_root.clone().unwrap() == root{
                
                // No need to interpolate the Merkle tree again. 
                // If the echo_root variable is set, then we already sent ready for this message.
                // Nothing else to do here. Quit the execution. 

                return;
            }

            let ready_senders = ready_senders.clone();

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
                
                // Ready phase is completed. Save our share for later purposes and quick access. 
                asks_context.rbc_state.fragment = Some((my_share.clone(),merkle_tree.gen_proof(self.myid)));

                asks_context.rbc_state.message = Some(message.clone());

                let deser_root_vec: Vec<Hash> = bincode::deserialize(&message).unwrap();
                asks_context.roots = Some(deser_root_vec);
                // Insert own ready share
                asks_context.rbc_state.readys.get_mut(&root).unwrap().insert(self.myid, my_share.clone());
                // Send ready message
                let ctrbc_msg = CTRBCMsg{
                    shard: my_share,
                    mp: merkle_tree.gen_proof(self.myid),
                    origin: ctrbc_msg.origin,
                };
                
                let ready_msg = ProtMsg::Ready(ctrbc_msg.clone(), reconstruct_to_all, instance_id);

                self.broadcast(ready_msg).await;
            }
        }
        else if size >= self.num_nodes - self.num_faults && !asks_context.rbc_state.terminated {
            log::info!("Received n-f READY messages for RBC Instance ID {}, terminating",instance_id);
            // Terminate protocol
            asks_context.rbc_state.terminated = true;
            asks_context.terminated = true;
            self.terminate(instance_id, None).await;
        }
    }

    pub async fn terminate(&mut self, instance_id: usize, secrets: Option<Vec<LargeField>>){
        let instance: usize = instance_id % self.threshold;
        let rep = instance_id/self.threshold;

        if secrets.is_none(){
            // Completed sharing
            let msg = (instance, rep, None);
            let status = self.out_asks_values.send(msg).await;
            log::info!("Sent result back to original channel {:?}", status);
        }
        else{
            // Completed reconstruction of the secret
            let msg = (instance,rep, Some(secrets.unwrap()));
            let status = self.out_asks_values.send(msg).await;
            log::info!("Sent result back to original channel {:?}", status);
        }
    }
}