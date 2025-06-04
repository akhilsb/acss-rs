use std::collections::HashSet;

use crypto::LargeField;
use types::{Replica};

use crate::Context;

use super::VABAState;

impl Context{
    pub async fn process_asks_termination(&mut self, instance: usize, sender: Replica, value: Option<Vec<LargeField>>){
        log::info!("Processing ASKS termination for instance {} from sender {}", instance, sender);
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
            let value = value.unwrap()[0].clone();
            vaba_context.reconstructed_values.insert(sender, value);
        }
    }

    pub async fn init_asks_reconstruction(&mut self, instance: usize){
        // Generate list of all ASKS instances to be reconstructed
        // Reconstruct all received ASKS shares
        let vaba_context = self.acs_state.vaba_states.get_mut(&instance).unwrap();
        if vaba_context.asks_reconstruction_started{
            return;
        }
        log::info!("Secret reconstruction started for instance {}", instance);
        for rep in 0..self.num_nodes{
            vaba_context.ranks_parties.insert(rep, LargeField::from(0));
        }
        // Preprocess list of ASKS instances to be reconstructed for each oracle
        let mut union_set: HashSet<Replica> = HashSet::default();
        for rep in vaba_context.gather_state.validated_gather_echo2s.iter(){
            let set_indices = vaba_context.gather_state.received_gather_echo2s.get(rep).unwrap();
            for index in set_indices{
                union_set.insert(*index);
            }
        }
        // Fetch list of asks instances specified by this party
        for rep in union_set{
            let (_,asks_instances,_) = vaba_context.pre_justify_votes.get(&rep).unwrap();
            let mut asks_instance_set: HashSet<Replica> = HashSet::default();
            asks_instance_set.extend(asks_instances);

            // Remove already reconstructed instances from this list
            let mut agg_secret = LargeField::from(0);
            for inst in asks_instances{
                if vaba_context.asks_reconstructed_values.contains_key(inst){
                    let recon_value = vaba_context.asks_reconstructed_values.get(inst).unwrap();
                    agg_secret = agg_secret + recon_value;
                    asks_instance_set.remove(inst);
                }
            }
            if !asks_instance_set.is_empty(){
                vaba_context.asks_reconstruction_list.insert(rep, asks_instance_set);
            }
        }

        for rep in vaba_context.term_asks_instances.iter(){
            let _status = self.asks_req.send((instance, 1, true, true, None, Some(*rep))).await;
        }
        // Reconstruction true
        vaba_context.asks_reconstruction_started = true;
        // Wait until receiving all results for ranks
        self.check_reconstruction_phase_terminated(instance).await;
    }

    pub async fn process_asks_reconstruction_result(&mut self, instance: usize, secret_preparer_rep: usize, recon_result: Vec<LargeField>){
        log::info!("Received reconstruction result from ASKS for instance {} and Replica {}", instance, secret_preparer_rep);
        
        let recon_result = recon_result[0].clone();
        // Compute Rank of reconstruction
        if !self.acs_state.vaba_states.contains_key(&instance){
            let vaba_context = VABAState::new_without_pre_justify();
            self.acs_state.vaba_states.insert(instance, vaba_context);
        }
        
        let vaba_context = self.acs_state.vaba_states.get_mut(&instance).unwrap();

        vaba_context.asks_reconstructed_values.insert(secret_preparer_rep, recon_result.clone());
        self.check_reconstruction_phase_terminated(instance).await;
    }

    pub async fn check_reconstruction_phase_terminated(&mut self, instance: usize){
        let vaba_context = self.acs_state.vaba_states.get_mut(&instance).unwrap();
        
        if vaba_context.asks_reconstruction_started{
            let mut new_ranks_reconstructed_parties = Vec::new();
            for (secret_preparer_rep, recon_result) in vaba_context.asks_reconstructed_values.iter(){
                for (rep, set_indices) in vaba_context.asks_reconstruction_list.iter_mut(){
                    if set_indices.contains(&secret_preparer_rep){
                        let mut agg_secret_old = vaba_context.ranks_parties.get(rep).unwrap().clone();
                        
                        agg_secret_old += recon_result.clone();
                        vaba_context.ranks_parties.insert(*rep, agg_secret_old);
                        set_indices.remove(&secret_preparer_rep);
    
                        if set_indices.is_empty(){
                            new_ranks_reconstructed_parties.push(*rep);
                        }
                    }
                }
            }
            for rep in new_ranks_reconstructed_parties.into_iter(){
                vaba_context.asks_reconstruction_list.remove(&rep);
            }
        }    
        if vaba_context.asks_reconstruction_list.is_empty() && vaba_context.asks_reconstruction_started && vaba_context.elected_leader.is_none(){
            // Compute party with maximum rank
            let mut max_rank = LargeField::from(0);
            let mut party_with_max_rank = 0 as usize;
            // All ranks have been computed. Check the party with the maximum rank

            for rep in 0..self.num_nodes{
                if vaba_context.ranks_parties.contains_key(&rep){
                    let rank_party = vaba_context.ranks_parties.get(&rep).clone().unwrap().clone();
                    if rank_party > max_rank{
                        max_rank = rank_party;
                        party_with_max_rank = rep;
                    }
                }
            }
            // Rank and Leader elected with rank
            log::info!("Party with maximum rank {}, maximum rank {}", party_with_max_rank, max_rank);
            vaba_context.elected_leader = Some(party_with_max_rank.clone());
            // Start voting phase
            self.start_vote_phase(instance, party_with_max_rank).await;
            //self.terminate("Terminate".to_string()).await;   
        }
    }
}