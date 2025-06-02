use std::collections::HashSet;

use types::Replica;

use crate::Context;

pub struct BAState{
    pub ba_started: bool,
    pub secrets_reconstructed: bool,
    pub shares_generated: bool,
    
    pub ba_term_status: HashSet<Replica>,
    pub mvba_term_status: HashSet<Replica>,
    pub pub_rec_status: HashSet<Replica>
}

impl BAState{
    pub fn new() -> BAState {
        BAState {
            ba_started: false,

            secrets_reconstructed: false,
            shares_generated: false,
            
            ba_term_status: HashSet::new(),
            mvba_term_status: HashSet::new(),
            pub_rec_status: HashSet::new(),
        }
    }
}

impl Context{
    pub async fn verify_start_binary_ba(&mut self){
        if self.coin_shares.len() > 0 && 
            !self.ba_state.ba_started && 
            self.ba_state.secrets_reconstructed &&
            self.ba_state.shares_generated{
            log::info!("Starting binary BA after public reconstruction");
            self.init_binary_ba(2, 1).await;
            self.ba_state.ba_started = true;
        }
    }

    pub async fn init_binary_ba(&mut self, inp: usize, instance: usize){
        log::info!("Initializing binary BA for instance {} with inp {}", instance, inp);
        
        let mut coin_vals = Vec::new();
        for _ in 0..5{
            coin_vals.push(self.coin_shares.pop_front().unwrap().to_bytes_be());
        }
        
        let _status = self.bin_aa_req.send((instance, inp as i64, coin_vals)).await;
    }

    pub async fn process_bin_aa_output(&mut self, instance_id: usize, output: i64){
        log::info!("Received binary AA output for instance {}: {}", instance_id, output);
        // Run FIN MVBA for iteration 1
        // Consume randomness

        let mut coin_vals = Vec::new();
        for _ in 0..10{
            coin_vals.push(self.coin_shares.pop_front().unwrap().to_bytes_be());
        }
        let _status = self.fin_mvba_req_send.send((instance_id, self.num_nodes-instance_id, coin_vals)).await;
    }
}