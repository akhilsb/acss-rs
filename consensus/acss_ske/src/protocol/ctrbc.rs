use consensus::VACommitment;
use crypto::hash::{Hash, do_hash};

use crate::{Context, protocol::ACSSABState};

impl Context{
    pub async fn handle_ctrbc_termination(&mut self, _inst_id: usize, sender_rep: usize, content: Vec<u8>){
        log::info!("Received CTRBC termination message from sender {}",sender_rep);
        // Deserialize message
        let va_comm: VACommitment = bincode::deserialize(content.as_slice()).unwrap();
        let instance_id = va_comm.instance_id;
        log::info!("Successfully deserialized CTRBC message from party {} with instance_id {}", sender_rep, instance_id);

        if !self.acss_ab_state.contains_key(&instance_id) {
            let acss_state = ACSSABState::new();
            self.acss_ab_state.insert(instance_id, acss_state);
        }
        let acss_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        // Compute root commitment
        let root_commitment = Self::compute_root_commitment(va_comm.column_roots.clone(), va_comm.blinding_column_roots.clone());
        acss_state.commitments.insert(sender_rep, va_comm);

        acss_state.commitment_root_fe.insert(sender_rep, root_commitment);
        log::info!("Deserialization successful for sender {} for instance ID {}",sender_rep,instance_id);
        self.interpolate_shares(sender_rep, instance_id).await;
        self.verify_shares(sender_rep,instance_id).await;
    }

    pub fn compute_root_commitment(comm_vector: Vec<Hash>, nonce_vector: Vec<Hash>)-> Hash{
        let mut agg_vector = Vec::new();
        for hash in comm_vector{
            agg_vector.extend(hash);
        }
        for nonce in nonce_vector{
            agg_vector.extend(nonce);
        }
        return do_hash(agg_vector.as_slice());
    }
}