use std::collections::{HashSet};

use types::Replica;

use crate::{Context, msg::CTRBCInterface};

impl Context{
    pub async fn process_ctrbc_event(&mut self, broadcaster: usize, _instance: usize, value: Vec<u8>){
        let deser_msg: CTRBCInterface = bincode::deserialize(value.as_slice()).unwrap();
        let instance = deser_msg.id;
        let value = deser_msg.msg;
        if instance == 1 {
            // First instance is for the RBC of the core ACS instance
            //let replicas_list: Vec<Replica> = bincode::deserialize(value.as_slice()).unwrap();
            log::info!("Received L1 CTRBC broadcast from party {}", broadcaster);
            self.acs_state.broadcast_messages.insert(broadcaster , Vec::new());
            
            if self.acs_state.broadcast_messages.len() == self.num_nodes - self.num_faults{
                // Invoke CTRBC to broadcast list of indices
                let key_set:Vec<Replica> = self.acs_state.broadcast_messages.keys().map(|key | key.clone()).collect();
                let ser_value = bincode::serialize(&key_set).unwrap();

                let ctrbc_msg = CTRBCInterface{
                    id: 2,
                    msg: ser_value
                };

                let ser_inst_id_val = bincode::serialize(&ctrbc_msg).unwrap();

                log::info!("Received n-f broadcasts of the initial value, broadcasting the list of broadcasts");
                let _status = self.ctrbc_req.send(ser_inst_id_val).await;
            }
            self.check_witnesses_rbc_inst(broadcaster).await;
        }
        else if instance == 2 {
            log::info!("Received L2 CTRBC broadcast from party {}", broadcaster);
            // Second RBC instance is for list of broadcasts
            let replicas_list: Vec<Replica> = bincode::deserialize(value.as_slice()).unwrap();
            self.acs_state.re_broadcast_messages.insert(broadcaster, replicas_list.clone());
            self.check_witnesses_rbc_inst_single_party(broadcaster).await;
        }
        else{
            // Second instance RBC is for VABA instance
            let true_inst_mod = instance - 2;
            let tot_rbcs_per_vaba = 2;
            log::info!("Received L3 CTRBC broadcast from party {} for true_inst_mod {}", broadcaster, true_inst_mod);

            if true_inst_mod % tot_rbcs_per_vaba == 1{
                let vaba_index = (true_inst_mod/tot_rbcs_per_vaba) + 1;
                // This broadcast corresponds to Broadcast termination of (pre_v, asks_v, justify_v)
                self.process_pre_broadcast(vaba_index, broadcaster, value).await;
            }
            else if true_inst_mod % tot_rbcs_per_vaba == 0{
                let vaba_index = true_inst_mod/tot_rbcs_per_vaba;
                // This broadcast corresponds to a Vote instance
                // This case has not been handled
                self.process_vote(vaba_index, value, broadcaster).await;
            }
        }
    }

    pub async fn check_witnesses_rbc_inst(&mut self, broadcaster: usize){
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
            self.check_witness_pre_broadcast(1).await;
        }

        // If this is the first witness accepted for the first time ever
        if self.acs_state.accepted_witnesses.len() >= 1 && !self.acs_state.vaba_started{
            // Start first phase of VABA
            // Start ASKS first
            let pre_i = broadcaster;
            self.start_vaba(pre_i, Vec::new(), 1).await;
            self.acs_state.vaba_started = true;
        }
    }

    pub async fn check_witnesses_rbc_inst_single_party(&mut self, broadcaster: usize){
        // Check for witnesses
        let replicas_list = self.acs_state.re_broadcast_messages.get(&broadcaster).unwrap();
        let mut hashset_replicas: HashSet<usize> = HashSet::default();
        for rep in replicas_list.into_iter(){
            if !self.acs_state.broadcast_messages.contains_key(&rep){
                hashset_replicas.insert(*rep);
            }
        }
        
        if hashset_replicas.is_empty(){
            // Add witness to witness list
            self.acs_state.accepted_witnesses.insert(broadcaster);
            self.check_witness_pre_broadcast(1).await;
        }
        else {
            self.acs_state.broadcasts_left_to_be_accepted.insert(broadcaster, hashset_replicas.clone());
        }

        // If this is the first witness accepted for the first time ever
        if self.acs_state.accepted_witnesses.len() >= 1 && !self.acs_state.vaba_started{
            // Start first phase of VABA
            // Start ASKS first
            let pre_i = broadcaster;
            self.start_vaba( pre_i, Vec::new(), 1).await;
            self.acs_state.vaba_started = true;
        }
    }

    pub async fn process_termination_event(&mut self, replica: usize){
        self.acs_input_set.insert(replica);
        log::info!("Completed sharing process for secrets originated by {}, adding to acs_set", replica);
        let ctrbc_msg = CTRBCInterface{
            id: 1,
            msg: Vec::new()
        };
        let ser_msg = bincode::serialize(&ctrbc_msg).unwrap();
        self.process_ctrbc_event(replica, 1, ser_msg).await;
    }
}