use crypto::LargeField;
use types::Replica;

use crate::Context;

use super::VABAState;

impl Context{
    pub async fn start_vaba(&mut self, pre: Replica, justify: Vec<(Replica, Replica)>, instance: usize){
        // Create VABA state
        if self.acs_state.vaba_states.len() < instance-1{
            log::error!("Error creating VABA instance, instance ID {} is wrong", instance);
            return;
        }
        else if self.acs_state.vaba_states.len() < instance {
            self.acs_state.vaba_states.push(VABAState::new(pre, justify));   
        }
        else{
            let acs_state = self.acs_state.vaba_states.get_mut(instance-1).unwrap();
            acs_state.pre = Some(pre);
            acs_state.justify = Some(justify);
        }
        // Start ASKS
        let status = self.asks_req.send((instance, false)).await;
        if status.is_err(){
            log::error!("Error sending transaction to the ASKS queue, abandoning ACS instance");
            return;
        }
    }

    pub async fn process_asks_termination(&mut self, instance: usize, sender: Replica, value: Option<LargeField>){
        if self.acs_state.vaba_states.len() < instance{
            // Add instance-self.acs_state.vaba_states.len() VABAContexts to the state
            for _ in self.acs_state.vaba_states.len()..instance{
                self.acs_state.vaba_states.push(VABAState::new_without_pre_justify());
            }
        }

        let vaba_context = self.acs_state.vaba_states.get_mut(instance-1).unwrap();
        if value.is_none(){
            vaba_context.term_asks_instances.push(sender);
            self.broadcast_pre(instance).await;
        }
        else{
            vaba_context.reconstructed_values.insert(sender, value.unwrap());
        }
    }

    pub async fn broadcast_pre(&mut self, inst: usize){
        let vaba_context = self.acs_state.vaba_states.get_mut(inst).unwrap();
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
}