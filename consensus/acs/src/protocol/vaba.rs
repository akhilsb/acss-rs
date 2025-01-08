use crypto::LargeField;
use types::Replica;

use crate::Context;

use super::VABAState;

impl Context{
    pub async fn start_vaba(&mut self, pre: Replica, justify: Vec<(Replica, Replica)>, instance: usize){
        // Create VABA state
        if !self.acs_state.vaba_states.contains_key(&instance){
            let vaba_context = VABAState::new(pre, justify);
            self.acs_state.vaba_states.insert(instance , vaba_context);
        }
        else{
            let vaba_context = self.acs_state.vaba_states.get_mut(&instance).unwrap();
            vaba_context.pre = Some(pre);
            vaba_context.justify = Some(justify);
        }
        // Start ASKS
        let status = self.asks_req.send((instance, false)).await;
        self.broadcast_pre(instance).await;
        if status.is_err(){
            log::error!("Error sending transaction to the ASKS queue, abandoning ACS instance");
            return;
        }
    }

    pub async fn process_asks_termination(&mut self, instance: usize, sender: Replica, value: Option<LargeField>){
        if !self.acs_state.vaba_states.contains_key(&instance){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(instance, vaba_context);
        }
        
        let vaba_context = self.acs_state.vaba_states.get_mut(&instance).unwrap();
        
        if value.is_none(){
            vaba_context.term_asks_instances.push(sender);
            self.broadcast_pre(instance).await;
        }
        else{
            vaba_context.reconstructed_values.insert(sender, value.unwrap());
        }
    }

    pub async fn process_pre_broadcast(&mut self, inst: usize, broadcaster: usize, rbc_value: Vec<u8>){
        let msg: (Replica, Vec<Replica>, Vec<(Replica,Replica)>) = bincode::deserialize(rbc_value.as_slice()).unwrap();
        
        let pre_i = msg.0;
        // ASKS instances
        let p_i = msg.1;
        let justification = msg.2;

        if !self.acs_state.vaba_states.contains_key(&inst){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(inst, vaba_context);
        }
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        let pre_justify = (pre_i, justification);
        vaba_context.pre_justify_votes.insert(broadcaster, pre_justify);

        vaba_context.gather_state.terminated_rbcs.insert(broadcaster, p_i);
        // Process witness
        self.check_witness(inst);
    }

    pub async fn broadcast_pre(&mut self, inst: usize){
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        if vaba_context.term_asks_instances.len() == self.num_faults+1 &&
            vaba_context.pre.is_some() && 
            vaba_context.justify.is_some(){
            // Start new RBC instance
            let p_i = vaba_context.term_asks_instances.clone();
            
            let ctrbc_msg = (vaba_context.pre.clone().unwrap(), 
                p_i, 
                vaba_context.justify.clone().unwrap()
            );
            
            let ser_msg = bincode::serialize(&ctrbc_msg).unwrap();
            let status = self.ctrbc_req.send(ser_msg).await;

            if status.is_err(){
                log::error!("Error sending transaction to the ASKS queue, abandoning ACS instance");
                return;
            }
        }
    }

    pub fn check_witness(&mut self, inst: usize){
        if inst == 1{
            let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
            
        }
        else{

        }
    }
}