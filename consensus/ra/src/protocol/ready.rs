use crypto::hash::do_hash;
use ctrbc::RBCState;
use types::Replica;

use crate::{context::Context, msg::ProtMsg};

use super::echo::replica_from_inst_id;

impl Context{
    pub async fn process_ra_ready(&mut self, instance_id: usize, ready_sender: Replica, value: usize){
        if !self.ra_state.contains_key(&instance_id){
            let (_inst, representative_rep) = replica_from_inst_id(self.threshold, instance_id);
            let ra_context = RBCState::new(representative_rep);
            self.ra_state.insert(instance_id , ra_context);
        }

        let ra_context = self.ra_state.get_mut(&instance_id).unwrap();

        if ra_context.terminated{
            return;
            // RBC Context already terminated, skip processing this message
        }

        let root = do_hash(&value.to_be_bytes());
        let ready_senders = ra_context.readys.entry(root).or_default();

        if ready_senders.contains_key(&ready_sender){
            return;
        }

        ready_senders.insert(ready_sender, value.to_be_bytes().to_vec());

        let size = ready_senders.len().clone();

        if size == self.num_faults + 1{

            // Sent ECHOs and getting a ready message for the same ECHO
            if ra_context.echo_root.is_some(){
                // If the echo_root variable is set, then we already sent ready for this message.
                // Nothing else to do here. Quit the execution. 
                return;
            }
            let ready_msg = ProtMsg::Ready(instance_id, value);
            self.broadcast(ready_msg).await;
        }
        else if size >= self.num_nodes - self.num_faults && !ra_context.terminated {
            log::info!("Received n-f READY messages for RA Instance ID {}, terminating",instance_id);
            // Terminate protocol
            ra_context.terminated = true;
            self.terminate(instance_id, value).await;
        }
    }

    pub async fn terminate(&mut self, instance_id: usize, value: usize){
        let instance: usize = instance_id % self.threshold;
        let rep = instance_id/self.threshold;

        let msg = (rep, instance, value);
        let status = self.out_ra_values.send(msg).await;
        log::info!("Sent result back to original channel {:?}", status);
    }
}