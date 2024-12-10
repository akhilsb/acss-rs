use consensus::reconstruct_data;

use super::init::construct_merkle_tree;
use crate::{CTRBCMsg, Context};
use crate::{ProtMsg};

impl Context {
    pub async fn handle_echo(self: &mut Context, msg: CTRBCMsg, instance_id: usize) {
        /*
        1. mp verify
        2. wait until receiving n - t echos of the same root
        3. lagrange interoplate f and m
        4. reconstruct merkle tree, verify roots match.
        5. if all pass, send ready <fi, pi>
         */

        let rbc_context = self.rbc_context.entry(instance_id).or_default();

        if rbc_context.terminated{
            // RBC Already terminated, skip processing this message
            return;
        }
        // check if verifies
        if !msg.verify_mr_proof(&self.hash_context) {
            log::error!(
                "Invalid Merkle Proof sent by node {}, abandoning RBC",
                msg.origin
            );
            return;
        }

        let root = msg.mp.root();
        let echo_senders = rbc_context.echos.entry(root).or_default();

        if echo_senders.contains_key(&msg.origin){
            return;
        }

        echo_senders.insert(msg.origin, msg.shard);
        
        let size = echo_senders.len().clone();
        if size == self.num_nodes - self.num_faults{
            log::info!("Received n-f ECHO messages for RBC Instance ID {}, sending READY message",instance_id);
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
            let merkle_tree = construct_merkle_tree(shards, &self.hash_context);
            if merkle_tree.root() == root{
                
                // ECHO phase is completed. Save our share and the root for later purposes and quick access. 
                rbc_context.echo_root = Some(root);
                rbc_context.fragment = Some((my_share.clone(),merkle_tree.gen_proof(self.myid)));
                rbc_context.message = Some(message);

                // Send ready message
                let ctrbc_msg = CTRBCMsg{
                    shard: my_share,
                    mp: merkle_tree.gen_proof(self.myid),
                    origin: self.myid,
                };
                
                self.handle_ready(ctrbc_msg.clone(),instance_id).await;
                let ready_msg = ProtMsg::Ready(ctrbc_msg, instance_id);
                self.broadcast(ready_msg).await;
            }
        }
        // Go for optimistic termination if all n shares have appeared
        else if size == self.num_nodes{
            log::info!("Received n ECHO messages for RBC Instance ID {}, terminating",instance_id);
            // Do not reconstruct the entire root again. Just send the merkle proof
            
            let echo_root = rbc_context.echo_root.clone();

            if echo_root.is_some() && !rbc_context.terminated{
                rbc_context.terminated = true;
                // Send Ready and terminate

                let fragment = rbc_context.fragment.clone().unwrap();
                let ctrbc_msg = CTRBCMsg{
                    shard: fragment.0,
                    mp: fragment.1, 
                    origin: self.myid,
                };

                let message = rbc_context.message.clone().unwrap();

                let ready_msg = ProtMsg::Ready(ctrbc_msg, instance_id);
                
                self.broadcast(ready_msg).await;
                self.terminate(message).await;
            }

        }
    }
}
