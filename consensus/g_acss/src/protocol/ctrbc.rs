use crate::{protocol::ACSSABState, CommDZKMsg, Context};

impl Context{
    pub async fn handle_ctrbc_termination(&mut self, _inst_id: usize, sender_rep: usize, content: Vec<u8>){
        log::info!("Received CTRBC termination message from sender {}",sender_rep);

        // Deserialize message
        let commitment_msg: CommDZKMsg = bincode::deserialize(content.as_slice()).unwrap();
        let instance_id = commitment_msg.instance_id;
        if !self.acss_ab_state.contains_key(&instance_id) {
            let acss_state = ACSSABState::new();
            self.acss_ab_state.insert(instance_id, acss_state);
        }
        let acss_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        // Compute root commitment
        let root_commitment = Self::root_commitment(&commitment_msg.comm);
        let blinding_root_commitment = Self::root_commitment(&commitment_msg.blinding_comm);
        
        let root_commitment = self.hash_context.hash_two(root_commitment.clone(), blinding_root_commitment.clone());

        acss_state.commitments.insert(sender_rep, commitment_msg);

        acss_state.commitment_root_fe.insert(sender_rep, root_commitment);
        log::info!("Deserialization successful for sender {} for instance ID {}",sender_rep,instance_id);
        self.interpolate_shares(sender_rep, instance_id).await;
        self.verify_shares(sender_rep,instance_id).await;
    }
}