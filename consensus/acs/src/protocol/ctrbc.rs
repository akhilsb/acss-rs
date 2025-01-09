use std::collections::{HashSet};

use types::Replica;

use crate::Context;

impl Context{
    pub async fn handle_ctrbc_event(&mut self, broadcaster: usize, instance: usize, value: Vec<u8>){
        if instance == 1{
            
            // First instance is for the RBC of the core ACS instance
            // Replace this part with ACSS protocol invocation
            
            let replicas_list: Vec<Replica> = bincode::deserialize(value.as_slice()).unwrap();
            self.acs_state.broadcast_messages.insert(broadcaster , replicas_list);
            
            if self.acs_state.broadcast_messages.len() == self.num_nodes - self.num_faults{
                // Invoke CTRBC to broadcast list of indices
                let key_set:Vec<Replica> = self.acs_state.broadcast_messages.keys().map(|key | key.clone()).collect();
                let ser_value = bincode::serialize(&key_set).unwrap();

                
                let _status = self.ctrbc_req.send(ser_value).await;
            }
            
            let mut added_witnesses = Vec::new();
            // Check for witnesses after each accepted broadcast
            for (rep_key, broadcast_list) in self.acs_state.broadcasts_left_to_be_accepted.iter_mut(){
                broadcast_list.remove(&broadcaster);
                if broadcast_list.len() == 0{
                    // Add party to witness list
                    log::info!("Added party {} to list of first witnesses self.acs_state.accepted_witnesses", *rep_key);
                    added_witnesses.push(*rep_key);
                }
            }
            for witness in added_witnesses.iter(){
                self.acs_state.broadcasts_left_to_be_accepted.remove(&witness);
                self.acs_state.accepted_witnesses.insert(*witness);
            }
            
            // Check if any new witnesses were added after this broadcast terminated
            if !added_witnesses.is_empty(){
                self.check_witness_pre_broadcast(instance).await;
            }
        }
        else if instance == 2 {
            // Second RBC instance is for list of broadcasts
            let replicas_list: Vec<Replica> = bincode::deserialize(value.as_slice()).unwrap();
            self.acs_state.re_broadcast_messages.insert(broadcaster, replicas_list.clone());
            
            // Check for witnesses
            let mut hashset_replicas: HashSet<usize> = HashSet::default();
            for rep in replicas_list.into_iter(){
                if !self.acs_state.broadcast_messages.contains_key(&rep){
                    hashset_replicas.insert(rep);
                }
            }
            
            if hashset_replicas.is_empty(){
                // Add witness to witness list
                self.acs_state.accepted_witnesses.insert(broadcaster);
                self.check_witness_pre_broadcast(instance).await;
            }
            else {
                self.acs_state.broadcasts_left_to_be_accepted.insert(broadcaster, hashset_replicas);
            }

            // If this is the first witness accepted for the first time ever
            if self.acs_state.accepted_witnesses.len() == 1 && self.acs_state.vaba_states.len() == 0{
                // Start first phase of VABA
                // Start ASKS first
                let pre_i = broadcaster;
                self.start_vaba( pre_i, Vec::new(), 1).await;
            }
        }
        else{
            // Second instance RBC is for VABA instance
            let true_inst = instance - 2;
            let tot_rbcs_per_vaba = 4;
            if true_inst % tot_rbcs_per_vaba == 1{
                // This broadcast corresponds to Broadcast termination of (pre_v, asks_v, justify_v)
                let msg: (Vec<Replica>, Vec<Replica>, Vec<Replica>) = bincode::deserialize(&value).unwrap();

            }
        }
    }
}