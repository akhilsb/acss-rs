use crypto::LargeField;
use types::Replica;

use crate::Context;

use super::VABAState;

impl Context{
    pub async fn process_asks_termination(&mut self, instance: usize, sender: Replica, value: Option<LargeField>){
        if !self.acs_state.vaba_states.contains_key(&instance){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(instance, vaba_context);
        }
        
        let vaba_context = self.acs_state.vaba_states.get_mut(&instance).unwrap();
        
        if value.is_none(){
            vaba_context.term_asks_instances.insert(sender);
            // Remove pending asks instances from the map of unvalidated pre_justify_votes
            for (_rep, map) in vaba_context.unvalidated_pre_justify_votes.iter_mut(){
                map.1.remove(&sender);
            }
            self.broadcast_pre(instance).await;
            self.check_witness_pre_broadcast(instance).await;
        }
        else{
            vaba_context.reconstructed_values.insert(sender, value.unwrap());
        }
    }
}