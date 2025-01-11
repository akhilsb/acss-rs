use std::collections::{HashSet, HashMap};

use types::Replica;

use crate::{Context, msg::ProtMsg};

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
        let status = self.asks_req.send((instance, None, false)).await;
        self.broadcast_pre(instance).await;
        if status.is_err(){
            log::error!("Error sending transaction to the ASKS queue, abandoning ACS instance");
            return;
        }
    }

    pub async fn process_pre_broadcast(&mut self, inst: usize, broadcaster: usize, rbc_value: Vec<u8>){
        let msg: (Replica, Vec<Replica>, Vec<(Replica,Replica)>) = bincode::deserialize(rbc_value.as_slice()).unwrap();
        
        // let pre_i = msg.0;
        // // ASKS instances
        // let p_i = msg.1;
        // let justification = msg.2;

        if !self.acs_state.vaba_states.contains_key(&inst){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(inst, vaba_context);
        }
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        vaba_context.pre_justify_votes.insert(broadcaster, msg.clone());

        //vaba_context.gather_state.terminated_rbcs.insert(broadcaster, p_i);
        // Process witness
        self.check_witness_single_party(inst, broadcaster).await;
        
    }

    pub async fn process_ra_termination(&mut self, inst: usize, representative_rep: usize){
        if !self.acs_state.vaba_states.contains_key(&inst){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(inst , vaba_context);
        }
        
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        vaba_context.reliable_agreement.insert(representative_rep);
        
        // Check if received enough Reliable Agreement instances to start Gather protocol. 
        self.check_gather_start(inst).await;
        // Check if received enough Reliable Agreement instances to start next phase of Gather protocol. 
        self.check_gather_echo_termination(inst, vec![representative_rep]).await;
    }

    pub async fn broadcast_pre(&mut self, inst: usize){
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        if vaba_context.term_asks_instances.len() == self.num_faults+1 &&
            vaba_context.pre.is_some() && 
            vaba_context.justify.is_some() &&
            !vaba_context.pre_broadcast {
            log::info!("Starting Pre broadcast for instance_id {}", inst);
            // Start new RBC instance
            let p_i: Vec<Replica> = vaba_context.term_asks_instances.clone().into_iter().collect();
            
            let ctrbc_msg = (
                vaba_context.pre.clone().unwrap(), 
                p_i, 
                vaba_context.justify.clone().unwrap()
            );
            
            let ser_msg = bincode::serialize(&ctrbc_msg).unwrap();
            let status = self.ctrbc_req.send(ser_msg).await;

            if status.is_err(){
                log::error!("Error sending transaction to the ASKS queue, abandoning ACS instance");
                return;
            }
            vaba_context.pre_broadcast = true;
        }
    }

    // Checks if the termination of an RBC added any new witnesses for PRE Broadcast
    pub async fn check_witness_pre_broadcast(&mut self, inst: usize){
        log::info!("Checking for witnesses in inst {}", inst);
        let mut list_of_witnesses = Vec::new();
        if !self.acs_state.vaba_states.contains_key(&inst){
            return;
        }
        if inst == 1{
            let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
            // For the first RBC instance, check the list of witnesses
            for (key, entry) in vaba_context.unvalidated_pre_justify_votes.iter_mut(){
                // If this party indeed indicated the broadcaster as a pre-vote, then check if other conditions are true as well
                if entry.0.is_some() && (self.acs_state.accepted_witnesses.contains(&entry.0.clone().unwrap())){
                    if entry.1.is_empty(){
                        log::info!("Found new witness {} at check_witness_pre_broadcast for inst {}", *key, inst);
                        list_of_witnesses.push(*key);
                    }
                    
                    else{
                        // More ASKS instances need to be accepted
                        entry.0 = None;
                    }
                }
            }
            
        }
        else{

        }
        // Start reliable agreement for new witnesses
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        for witness in list_of_witnesses.iter(){
            vaba_context.unvalidated_pre_justify_votes.remove(witness);
            vaba_context.validated_pre_justify_votes.insert(*witness);
            
            if vaba_context.validated_pre_justify_votes.len() <= self.num_nodes - self.num_faults{
                log::info!("Starting Reliable Agreement for witness {}", *witness);
                let status = self.ra_req_send.send((*witness,1)).await;
                if status.is_err(){
                    log::error!("Error sending transaction to the RA queue, abandoning ACS instance");
                    return;
                }
            }
        }
        self.check_gather_start(inst).await;
    }

    pub async fn check_witness_single_party(&mut self, inst: usize, broadcaster: Replica){
        if !self.acs_state.vaba_states.contains_key(&inst){
            return;
        }
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        let (pre,asks_insts, justify) = vaba_context.pre_justify_votes.get(&broadcaster).unwrap();

        if inst == 1{
            // Check if party pre's specified ASKS instances have terminated
            let mut remaining_asks_instances = HashSet::default();
            remaining_asks_instances.extend(asks_insts.clone());
            for asks_inst in asks_insts{
                if vaba_context.term_asks_instances.contains(asks_inst){
                    remaining_asks_instances.remove(asks_inst);
                }
            }

            // Check if party pre's RBC terminated in the first phase
            if remaining_asks_instances.is_empty() && self.acs_state.accepted_witnesses.contains(pre){
                // Add party to set of witnesses
                vaba_context.validated_pre_justify_votes.insert(broadcaster.clone());

            }

            else{
                
                // Create an entry in unvalidated votes
                let pre_option;
                if self.acs_state.accepted_witnesses.contains(pre){
                    pre_option = None;
                }
                else {
                    pre_option = Some(*pre);
                }

                // Create remaining justifies
                let mut vote_map = HashMap::default();
                for (vote_broadcaster, vote) in justify.into_iter(){
                    vote_map.insert(*vote_broadcaster, *vote);
                }
                
                vaba_context.unvalidated_pre_justify_votes.insert(broadcaster, (pre_option, remaining_asks_instances, vote_map));
            }
        }
        else{
            // Check if justified votes have been broadcasted and validated. 
            // Fetch the previous VABA context
            // TODO: Case unhandled
            return;
        }

        //let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        // Start reliable agreement if needed
        
        if vaba_context.validated_pre_justify_votes.contains(&broadcaster) && 
            vaba_context.validated_pre_justify_votes.len() <= self.num_nodes - self.num_faults{
            log::info!("Starting Reliable Agreement for witness {} under method check_witness_single_party", broadcaster);
            let status = self.ra_req_send.send((broadcaster,1)).await;
            if status.is_err(){
                log::error!("Error sending transaction to the RA queue, abandoning ACS instance");
                return;
            }
        }
        let gather2 = vaba_context.gather_state.gather2_started;
        self.check_gather_start(inst).await;

        if gather2 {
            self.check_gather_echo2_termination(inst, vec![broadcaster]).await;
        }
        else{
            self.check_gather_echo_termination(inst, vec![broadcaster]).await;
        }
    }

    pub async fn check_gather_start(&mut self, inst: usize){
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        if vaba_context.validated_pre_justify_votes.len() >= self.num_nodes - self.num_faults && !vaba_context.gather_started{
            
            let mut gather_start_set = Vec::new();
            for rep in vaba_context.validated_pre_justify_votes.iter(){
                if vaba_context.reliable_agreement.contains(rep){
                    gather_start_set.push(*rep);
                }
            }
            
            if gather_start_set.len() >= self.num_nodes - self.num_faults{
                // Start Gather by sending Gather Echo
                let prot_msg = ProtMsg::GatherEcho(inst , gather_start_set);
                
                // Gather started here
                vaba_context.gather_started = true;
                self.broadcast(prot_msg).await;
            }
        }
    }
}