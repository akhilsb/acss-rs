use std::collections::{HashSet, HashMap};

use types::Replica;

use crate::{Context, msg::{ProtMsg, CTRBCInterface}};

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
        // (Instance ID, Number of secrets to be proposed, All_to_all reconstruction, Reconstruction Request?, Reconstruction_related_data) 
        let status = self.asks_req.send((instance,1, true, false, None, None)).await;
        log::info!("Sent ASKS request for instance {} with status: {:?}", instance, status);
        self.broadcast_pre(instance).await;
        if status.is_err(){
            log::error!("Error sending transaction to the ASKS queue, abandoning ACS instance");
            return;
        }
    }

    pub async fn process_pre_broadcast(&mut self, inst: usize, broadcaster: usize, rbc_value: Vec<u8>){
        log::info!("Received pre-broadcast for instance {} from Replica {}", inst, broadcaster);
        let msg: (Replica, Vec<Replica>, Vec<(Replica,Replica)>) = bincode::deserialize(rbc_value.as_slice()).unwrap();
        
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

    pub async fn process_ra_termination(&mut self, inst: usize, representative_rep: usize, value: usize){
        if !self.acs_state.vaba_states.contains_key(&inst){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(inst , vaba_context);
        }
        
        // Termination Gadget value
        if representative_rep == self.num_nodes{
            // Output this value finally
            log::info!("ACS output of value {}", value);
            log::info!("ACS output {:?}", self.acs_state.re_broadcast_messages.get(&value).unwrap());
            // Shift all this part of the code to a new repository
            // Compute random linear combination of shares
            let output_set = self.acs_state.re_broadcast_messages.get(&value).unwrap();
            let _status = self.acs_out_channel.send((1,output_set.clone())).await;
            
            //self.acs_state.acs_output.extend(output_set);
            //self.gen_rand_shares().await;
        }
        else{
            let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
            vaba_context.reliable_agreement.insert(representative_rep);
        }
              
        // Check if received enough Reliable Agreement instances to start Gather protocol. 
        self.check_gather_start(inst).await;
        // Check if received enough Reliable Agreement instances to start next phase of Gather protocol. 
        self.check_gather_echo_termination(inst, vec![representative_rep]).await;
    }

    pub async fn broadcast_pre(&mut self, inst: usize){
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        if vaba_context.term_asks_instances.len() >= self.num_faults+1 &&
            vaba_context.pre.is_some() && 
            vaba_context.justify.is_some() &&
            !vaba_context.pre_broadcast {
            log::info!("Starting Pre broadcast for instance_id {}", inst);
            // Start new RBC instance
            let mut p_i: Vec<Replica> = vaba_context.term_asks_instances.clone().into_iter().collect();
            p_i.truncate(self.num_faults+1);
            
            let ctrbc_msg = (
                vaba_context.pre.clone().unwrap(), 
                p_i, 
                vaba_context.justify.clone().unwrap()
            );

            let ser_msg = bincode::serialize(&(ctrbc_msg)).unwrap();

            let ctrbc_msg = CTRBCInterface{
                id: 3,
                msg: ser_msg
            };

            let ser_msg_inst_id = bincode::serialize(&ctrbc_msg).unwrap();
            let status = self.ctrbc_req.send(ser_msg_inst_id).await;

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
                if (entry.0.is_some() && (self.acs_state.accepted_witnesses.contains(&entry.0.clone().unwrap()))) || 
                    entry.0.is_none(){
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
            // 
        }
        // Start reliable agreement for new witnesses
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        for witness in list_of_witnesses.iter(){
            vaba_context.unvalidated_pre_justify_votes.remove(witness);
            log::info!("Validated party {}'s Pre vote, adding party to validated list", *witness);
            vaba_context.validated_pre_justify_votes.insert(*witness);
            
            if vaba_context.reliable_agreement.len() <= self.num_nodes - self.num_faults{
                log::info!("Starting Reliable Agreement for witness {}", *witness);
                let status = self.ra_req_send.send((*witness,1, inst)).await;
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
                log::info!("Validated party {}'s Pre vote, adding party to validated list", broadcaster);
                vaba_context.validated_pre_justify_votes.insert(broadcaster.clone());
            }

            else{
                log::info!("Party {}'s Pre vote is not validated, adding to unvalidated votes", broadcaster);
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
            vaba_context.reliable_agreement.len() <= self.num_nodes - self.num_faults{
            log::info!("Starting Reliable Agreement for witness {} under method check_witness_single_party", broadcaster);
            let status = self.ra_req_send.send((broadcaster,1, inst)).await;
            if status.is_err(){
                log::error!("Error sending transaction to the RA queue, abandoning ACS instance");
                return;
            }
        }
        self.check_gather_start(inst).await;
        self.check_gather_echo_termination(inst, vec![broadcaster]).await;
    }

    pub async fn check_gather_start(&mut self, inst: usize){
        log::info!("Checking if Gather can be started for instance {}", inst);
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        if vaba_context.validated_pre_justify_votes.len() >= self.num_nodes - self.num_faults && 
            vaba_context.reliable_agreement.len() >= self.num_nodes-self.num_faults &&
            !vaba_context.gather_started{
            // Check if the intersection of pre_justify votes and reliable agreement votes is greater than n-f

            let mut gather_start_set = Vec::new();
            for rep in vaba_context.validated_pre_justify_votes.iter(){
                if vaba_context.reliable_agreement.contains(rep){
                    gather_start_set.push(*rep);
                }
            }
            
            if gather_start_set.len() >= self.num_nodes - self.num_faults{
                // Start Gather by sending Gather Echo
                log::info!("Starting Gather Phase 1 with indices {:?}", gather_start_set);
                let prot_msg = ProtMsg::GatherEcho(inst , gather_start_set);
                
                // Gather started here
                vaba_context.gather_started = true;
                self.broadcast(prot_msg).await;
            }
        }
    }

    pub async fn start_vote_phase(&mut self, instance: usize, leader: Replica){
        log::info!("Starting Vote Phase for instance {} with leader {}", instance, leader);
        let vaba_context = self.acs_state.vaba_states.get_mut(&instance).unwrap();
        let pre_value_of_leader = vaba_context.pre_justify_votes.get(&leader).unwrap().0;

        // Broadcast this value
        if !vaba_context.vote_broadcasted{
            
            let ctrbc_msg = CTRBCInterface{
                id: 4,
                msg: pre_value_of_leader.to_be_bytes().to_vec()
            };
            
            let ser_msg_inst_id = bincode::serialize(&ctrbc_msg).unwrap();

            let status = self.ctrbc_req.send(ser_msg_inst_id).await;
            if status.is_err(){
                log::error!("Error sending transaction to the ASKS queue, abandoning ACS instance");
                return;
            }
            vaba_context.vote_broadcasted = true;
        }
    }

    pub async fn process_vote(&mut self, inst: usize, value: Vec<u8>, broadcaster: Replica){
        if !self.acs_state.vaba_states.contains_key(&inst){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(inst , vaba_context);
        }
        
        let vaba_context = self.acs_state.vaba_states.get_mut(&inst).unwrap();
        let mut bytes: [u8;8] = [0;8];
        for (index, value) in (0..8).into_iter().zip(value.into_iter()){
            bytes[index] = value;
        }

        let vote_rep = usize::from_be_bytes(bytes);
        log::info!("Received vote for instance {} from party {}", vote_rep, broadcaster);
        if vaba_context.votes.contains_key(&vote_rep){
            let rep_list = vaba_context.votes.get_mut(&vote_rep).unwrap();
            rep_list.insert(broadcaster);
            if rep_list.len() == self.num_nodes - self.num_faults{
                // Start Reliable Agreement as a termination gadget
                log::info!("Vote for {} has been validated, starting Reliable Agreement", vote_rep);
                let status = self.ra_req_send.send((self.num_nodes, vote_rep, inst)).await;
                if status.is_err(){
                    log::error!("Error sending transaction to the RA queue, abandoning ACS instance");
                    return;
                }
            }
        }
        else{
            let mut rep_list: HashSet<Replica> = HashSet::default();
            rep_list.insert(broadcaster);
            vaba_context.votes.insert(vote_rep, rep_list);
        }
    }
}