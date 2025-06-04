use std::collections::HashSet;

use types::Replica;

use crate::{Context, msg::ProtMsg};

use super::VABAState;

impl Context{
    pub async fn process_gather_echo(&mut self, gather_indices: Vec<Replica>, broadcaster: usize, inst: usize){
        if !self.acs_state.vaba_states.contains_key(&inst){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(inst, vaba_context);
        }

        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        vaba_context.gather_state.received_gather_echos.insert(broadcaster , gather_indices.clone());
        let mut set_indices = HashSet::default();
        set_indices.extend(gather_indices);
        vaba_context.gather_state.unvalidated_gather_echos.insert(broadcaster, set_indices);

        // Check gather termination
        self.check_gather_echo_new_party(inst, broadcaster).await;
    }

    pub async fn check_gather_echo_termination(&mut self, inst: usize, terminated_rbcs: Vec<Replica>){
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        let mut new_witnesses = Vec::new();
        
        for (rep, map) in vaba_context.gather_state.unvalidated_gather_echos.iter_mut(){
            for terminated_rbc in terminated_rbcs.clone().into_iter(){
                // First, the broadcasts of parties in map must terminate and be validated
                if vaba_context.validated_pre_justify_votes.contains(&terminated_rbc) && vaba_context.reliable_agreement.contains(&terminated_rbc){
                    map.remove(&terminated_rbc);
                }
            }
            if map.is_empty(){
                log::info!("Validated Gather Echo, adding party {} as witness", *rep);
                new_witnesses.push(*rep);
            }
        }

        for witness in new_witnesses.iter(){
            vaba_context.gather_state.unvalidated_gather_echos.remove(&witness);
        }
        vaba_context.gather_state.validated_gather_echos.extend(new_witnesses);
        
        // Upon collecting n-f ECHOs, broadcast this list again as ECHO2s. 
        if vaba_context.gather_state.validated_gather_echos.len() == self.num_nodes - self.num_faults{
            self.init_gather_echo2(inst).await;
        }
        self.check_gather_echo2_termination(inst, terminated_rbcs).await;
    }

    pub async fn check_gather_echo_new_party(&mut self, inst: usize, sender: Replica){
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        let gather_indices = vaba_context.gather_state.unvalidated_gather_echos.get_mut(&sender).unwrap();
        for index in gather_indices.clone().into_iter(){
            if vaba_context.validated_pre_justify_votes.contains(&index) && vaba_context.reliable_agreement.contains(&index){
                gather_indices.remove(&index);
            }
        }
        if gather_indices.is_empty(){
            // Add party as witness
            log::info!("Added party {} as Gather ECHO1 witness", sender);
            vaba_context.gather_state.validated_gather_echos.insert(sender);
            vaba_context.gather_state.unvalidated_gather_echos.remove(&sender);
        }
        // Upon collecting n-f ECHOs, broadcast this list again as ECHO2s. 
        if vaba_context.gather_state.validated_gather_echos.len() >= self.num_nodes - self.num_faults{
            self.init_gather_echo2(inst).await;
        }
    }

    pub async fn init_gather_echo2(&mut self, inst: usize){
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        
        // Union witnesses
        if !vaba_context.gather_state.gather2_started{
            let mut union_witness_list: HashSet<Replica> = HashSet::default();
            for witness in vaba_context.gather_state.validated_gather_echos.iter(){
                let list_witnesses = vaba_context.gather_state.received_gather_echos.get(witness).unwrap();
                union_witness_list.extend(list_witnesses);
            }
            let mut vec_witnesses = Vec::new();
            for rep in 0..self.num_nodes{
                if union_witness_list.contains(&rep){
                    vec_witnesses.push(rep);
                }
            }
            
            log::info!("Starting Gather Echo2 with witnesses {:?}", vec_witnesses);
            let prot_msg = ProtMsg::GatherEcho2(inst , vec_witnesses);
            vaba_context.gather_state.gather2_started = true;
            self.broadcast(prot_msg).await;
        }
    }

    pub async fn process_gather_echo2(&mut self, gather_indices: Vec<Replica>, broadcaster: usize, inst: usize){
        log::info!("Processing Gather Echo2 from {} with indices {:?}", broadcaster, gather_indices);
        if !self.acs_state.vaba_states.contains_key(&inst){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(inst, vaba_context);
        }

        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        vaba_context.gather_state.received_gather_echo2s.insert(broadcaster , gather_indices.clone());
        let mut set_indices = HashSet::default();
        set_indices.extend(gather_indices);
        vaba_context.gather_state.unvalidated_gather_echo2s.insert(broadcaster, set_indices);

        // Check gather termination
        self.check_gather_echo2_new_party(inst, broadcaster).await;
    }

    pub async fn check_gather_echo2_termination(&mut self, inst: usize, terminated_rbcs: Vec<Replica>){
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        let mut new_witnesses = Vec::new();
        for (rep, map) in vaba_context.gather_state.unvalidated_gather_echo2s.iter_mut(){
            // First, the broadcasts of parties in map must terminate and be validated
            for terminated_rbc in terminated_rbcs.clone().into_iter(){
                // First, the broadcasts of parties in map must terminate and be validated
                if vaba_context.validated_pre_justify_votes.contains(&terminated_rbc) && vaba_context.reliable_agreement.contains(&terminated_rbc){
                    map.remove(&terminated_rbc);
                }
            }
            if map.is_empty(){
                log::info!("Validated Gather Echo2, adding party {} as witness", *rep);
                new_witnesses.push(*rep);
            }
        }
        for witness in new_witnesses.iter(){
            vaba_context.gather_state.unvalidated_gather_echo2s.remove(&witness);
        }
        vaba_context.gather_state.validated_gather_echo2s.extend(new_witnesses);
        
        // Upon collecting n-f ECHOs, broadcast this list again as ECHO2s. 
        if vaba_context.gather_state.validated_gather_echo2s.len() >= self.num_nodes - self.num_faults{
            self.init_asks_reconstruction(inst).await;
        }
    }

    pub async fn check_gather_echo2_new_party(&mut self, inst: usize, sender: Replica){
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        let gather_indices = vaba_context.gather_state.unvalidated_gather_echo2s.get_mut(&sender).unwrap();
        for index in gather_indices.clone().into_iter(){
            if vaba_context.validated_pre_justify_votes.contains(&index) && vaba_context.reliable_agreement.contains(&index){
                gather_indices.remove(&index);
            }
        }
        if gather_indices.is_empty(){
            // Add party as witness
            log::info!("Added party {} as Gather ECHO2 witness", sender);
            vaba_context.gather_state.validated_gather_echo2s.insert(sender);
            vaba_context.gather_state.unvalidated_gather_echo2s.remove(&sender);
        }
        // Upon collecting n-f ECHOs, broadcast this list again as ECHO2s. 
        if vaba_context.gather_state.validated_gather_echo2s.len() >= self.num_nodes - self.num_faults{
            // Start next phase of the protocol. Reconstruct ASKS instances. 
            self.init_asks_reconstruction(inst).await;
        }
    }    
}