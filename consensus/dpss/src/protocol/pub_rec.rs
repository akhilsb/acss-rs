use std::collections::{HashSet};

use types::Replica;
use crate::Context;

pub struct BAState{
    pub ba_started: HashSet<Replica>,
    pub mvba_started: HashSet<Replica>,

    pub secrets_reconstructed: bool,
    pub shares_generated: bool,
    
    pub ba_term_status: HashSet<Replica>,
    pub mvba_term_status: HashSet<Replica>,
    pub pub_rec_term_parties: HashSet<Replica>,
    pub pub_rec_status: HashSet<Replica>,

    pub acs_output_sorted: Vec<Replica>,
}

impl BAState{
    pub fn new() -> BAState {
        let vec_reps = vec![0];
        BAState {
            ba_started: HashSet::default(),
            mvba_started: HashSet::default(),

            secrets_reconstructed: false,
            shares_generated: false,
            
            ba_term_status: HashSet::default(),
            mvba_term_status: HashSet::default(),
            pub_rec_term_parties: HashSet::default(),
            pub_rec_status: HashSet::from_iter(vec_reps.into_iter()),

            acs_output_sorted: Vec::new(),
        }
    }
}

impl Context{
    pub async fn verify_start_binary_ba(&mut self){
        if self.ba_state.acs_output_sorted.len() > 0 &&
            self.ba_state.pub_rec_term_parties.len() != self.ba_state.pub_rec_status.len(){
                for party in self.ba_state.pub_rec_term_parties.iter(){
                    let instance_id = self.ba_state.acs_output_sorted.len() - self.ba_state.acs_output_sorted.iter().position(|&rep| &rep == party ).unwrap();
                    self.ba_state.pub_rec_status.insert(instance_id);
                }
            }
        for instance_id in 1..self.num_faults{
            if !self.ba_state.ba_term_status.contains(&instance_id) && 
                self.ba_state.pub_rec_status.contains(&(instance_id-1)){
                // Start this BA instance first
                self.init_binary_ba(2,instance_id).await;
                break;
            }
            else{
                self.init_binary_ba(2, instance_id).await;
                if !self.ba_state.mvba_term_status.contains(&instance_id){
                    // Start MVBA instance
                    self.init_fin_mvba(instance_id).await;
                    break;
                }
                else{
                    self.init_fin_mvba(instance_id).await;
                }
            }
        }
    }

    pub async fn init_binary_ba(&mut self, inp: usize, instance: usize){
        if self.ba_state.ba_started.contains(&instance){
            return;
        }
        if !self.ba_state.secrets_reconstructed || 
            !self.ba_state.shares_generated || 
            self.coin_shares.len() < 5 {
            log::info!("Cannot start binary BA instance {}, prerequisites not met", instance);
            return;
        }
        log::info!("Initializing binary BA for instance {} with inp {}", instance, inp);
        let mut coin_vals = Vec::new();
        for _ in 0..5{
            coin_vals.push(self.coin_shares.pop_front().unwrap().to_bytes_be());
        }
        
        let _status = self.bin_aa_req.send((instance, inp as i64, coin_vals)).await;
        self.ba_state.ba_started.insert(instance);
    }

    pub async fn init_fin_mvba(&mut self, instance_id: usize){
        if self.ba_state.mvba_started.contains(&instance_id) {
            return;
        }
        if !self.ba_state.secrets_reconstructed || 
            !self.ba_state.shares_generated || 
            self.coin_shares.len() < 5 ||
            self.dpss_state.acs_output.len() == 0{
            log::info!("Cannot start FIN MVBA instance {}, prerequisites not met", instance_id);
            return;
        }

        let acs_output_set = &self.ba_state.acs_output_sorted;
        let corrupted_party = acs_output_set[acs_output_set.len() - instance_id];

        log::info!("Initializing FIN MVBA for instance {} with corrupted party {}", instance_id, corrupted_party);
        let mut coin_vals = Vec::new();
        for _ in 0..5{
            coin_vals.push(self.coin_shares.pop_front().unwrap().to_bytes_be());
        }
        
        let _status = self.fin_mvba_req_send.send((instance_id, corrupted_party, coin_vals)).await;
        self.ba_state.mvba_started.insert(instance_id);
    }

    pub async fn process_bin_aa_output(&mut self, instance_id: usize, output: i64){
        log::info!("Received binary AA output for instance {}: {}", instance_id, output);
        // Run FIN MVBA for iteration 1
        // Consume randomness
        self.ba_state.ba_term_status.insert(instance_id);
        self.verify_start_binary_ba().await;
    }

    pub async fn process_fin_mvba_output(&mut self, instance_id: usize, corrupted_party: usize){
        log::info!("Received FIN MVBA output for instance {}: corrupted party {}", instance_id, corrupted_party);
        log::info!("Starting public reconstruction for party {}", corrupted_party);

        if self.ba_state.pub_rec_term_parties.contains(&corrupted_party){
            log::info!("Public reconstruction for party {} already completed", corrupted_party);
            self.ba_state.pub_rec_status.insert(instance_id);
            self.verify_start_binary_ba().await;
            return;
        }
        else{
            let _status = self.pub_rec_req_send_channel.send((1, corrupted_party)).await;
        }
    }

    pub async fn process_acss_pubrec_output(&mut self, corrupted_party: usize){
        log::info!("Received public reconstruction output for corrupted party {}", corrupted_party);
        
        self.ba_state.pub_rec_term_parties.insert(corrupted_party);
        if self.ba_state.acs_output_sorted.len() > 0{
            // Find instance id
            let instance_id = self.ba_state.acs_output_sorted.len() - self.ba_state.acs_output_sorted.iter().position(|&x| x == corrupted_party).unwrap();
            self.ba_state.pub_rec_status.insert(instance_id);
        }
        self.verify_start_binary_ba().await;
    }
}