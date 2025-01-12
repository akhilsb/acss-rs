use crypto::hash::do_hash;
use ctrbc::RBCState;
use types::Replica;

use crate::{context::Context, msg::ProtMsg};

impl Context{
    pub async fn init_ra(&mut self, instance_id: usize, representative_rep: Replica, value: usize){
        log::info!("Request to start Reliable Agreement for instance {} corresponding to replica {}", instance_id, representative_rep);
        if !self.ra_state.contains_key(&instance_id){
            let rbc_context = RBCState::new(representative_rep);
            self.ra_state.insert(instance_id, rbc_context);
        }

        let ra_state = self.ra_state.get_mut(&instance_id).unwrap();
        if ra_state.terminated{
            // RBC Already terminated, skip processing this message
            return;
        }
        
        let root = do_hash(&value.to_be_bytes());
        let echo_senders = ra_state.echos.entry(root).or_default();

        echo_senders.insert(self.myid , value.to_be_bytes().to_vec());
        // Broadcast ECHO
        let echo = ProtMsg::Echo( instance_id, value);
        self.broadcast(echo).await;
    }

    pub async fn process_echo_ra(&mut self, instance_id: usize, echo_sender: Replica, value: usize){
        // Broadcast ECHO message
        if !self.ra_state.contains_key(&instance_id){
            let (_inst, representative_rep) = replica_from_inst_id(self.threshold, instance_id);
            let rbc_context = RBCState::new(representative_rep);
            self.ra_state.insert(instance_id, rbc_context);
        }

        let ra_state = self.ra_state.get_mut(&instance_id).unwrap();
        
        if ra_state.terminated{
            // RBC Already terminated, skip processing this message
            return;
        }
        
        let root = do_hash(&value.to_be_bytes());
        let echo_senders = ra_state.echos.entry(root).or_default();

        if echo_senders.contains_key(&echo_sender){
            return;
        }

        echo_senders.insert(echo_sender, value.to_be_bytes().to_vec());

        let size = echo_senders.len().clone();
        if size == self.num_nodes - self.num_faults{
            log::info!("Received n-f ECHO messages for RA Instance ID {}, sending READY message", instance_id);
            // Send ready message
            ra_state.echo_root = Some(root);
            let ready_msg = ProtMsg::Ready(instance_id, value);
            self.broadcast(ready_msg).await;
            
        }
        // Go for optimistic termination if all n shares have appeared
        else if size == self.num_nodes{
            log::info!("Received n ECHO messages for RA Instance ID {}, terminating",instance_id);
            if !ra_state.terminated{
                ra_state.terminated = true;
                self.terminate(instance_id, value).await;
            }
        }
    }

}

pub fn replica_from_inst_id(threshold: usize, instance_id: usize)-> (Replica, usize){
    let instance = instance_id%threshold;
    let rep = instance_id/threshold;
    (rep, instance)
}