use network::{Acknowledgement, plaintcp::CancelHandler};
use types::{Replica, WrapperMsg};

use crate::{Context, protocol::ibft_state::IBFTState, ProtMsg};

impl Context{
    pub async fn init_acss_term_procedure(&mut self, term_party: Replica, instance_id: usize){
        log::debug!("Sending termination event to the leader {} for ACSS initialized by party {}", self.leader_id,term_party);
        let prot_msg = ProtMsg::ACSSTerm(term_party, instance_id);

        let secret_key = self.sec_key_map.get(&self.leader_id).unwrap().clone();
        let wrapper_msg = WrapperMsg::new(prot_msg,self.myid, &secret_key);

        let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(self.leader_id, wrapper_msg).await;
        self.add_cancel_handler(cancel_handler);
    }

    pub async fn process_acss_termination(&mut self, instance_id: usize, term_party: Replica, sender: Replica){
        log::info!("Received ACSS termination event from party {} for ACSS instantiated by {} in instance id {}",sender, term_party, instance_id);
        if !self.ibft_state_map.contains_key(&instance_id){
            let ibft_state_map = IBFTState::new();
            self.ibft_state_map.insert(instance_id, ibft_state_map);
        }
        let ibft_state = self.ibft_state_map.get_mut(&instance_id).unwrap();
        ibft_state.add_termination(term_party);

        if ibft_state.consensus_inp_set.contains(&term_party) {
            log::warn!("Party {} already has been included in consensus input", term_party);
            return;
        }

        if ibft_state.termination_map.get(&term_party).unwrap().clone() >= self.num_nodes-self.num_faults{
            ibft_state.add_consensus_inp(term_party);
        }

        if ibft_state.consensus_inp_set.len() >= self.consensus_threshold && 
            self.myid == self.leader_id && 
            !ibft_state.broadcast_started{

            log::info!("Consensus set reached size n-t, using CTRBC channel to broadcast set for instance {}", instance_id);
            let mut inp_set_vec = Vec::new();
            inp_set_vec.extend(ibft_state.consensus_inp_set.iter().cloned());

            let ctrbc_msg = (instance_id, inp_set_vec);
            let ser_msg = bincode::serialize(&ctrbc_msg).expect("Failed to serialize CTRBC message");

            let ctrbc_status = self.ctrbc_req.send(ser_msg).await;
            if ctrbc_status.is_err() {
                log::error!("Failed to send CTRBC request for instance {}", instance_id);
            } else {
                log::info!("CTRBC request sent successfully for instance {}", instance_id);
            }
            ibft_state.broadcast_started = true;
        }
    }

    pub async fn process_ctrbc_termination(&mut self, ctrbc_msg: Vec<u8>){
        let (instance_id,party_set): ( usize, Vec<Replica>) = bincode::deserialize(&ctrbc_msg)
            .expect("Failed to deserialize CTRBC message");
        log::info!("Received CTRBC termination for instance id {} with party set {:?}", instance_id, party_set);
        if !self.ibft_state_map.contains_key(&instance_id){
            let ibft_state = IBFTState::new();
            self.ibft_state_map.insert(instance_id, ibft_state);
        }
        
        let ibft_state = self.ibft_state_map.get_mut(&instance_id).unwrap();
        ibft_state.add_consensus_out(party_set.clone());

        let out_status = self.acs_out_channel.send((instance_id, party_set)).await;
        if out_status.is_err() {
            log::error!("Failed to send CTRBC request for instance {}", instance_id);
        } else {
            log::info!("CTRBC request sent successfully for instance {}", instance_id);
        }
    }
}