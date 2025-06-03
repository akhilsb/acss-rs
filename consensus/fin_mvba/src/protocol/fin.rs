use std::collections::HashSet;

use consensus::{LargeFieldSer, LargeField};
use lambdaworks_math::{traits::ByteConversion, polynomial::Polynomial};

use rand::{Rng, rngs::StdRng};

use rand::SeedableRng;
use types::Replica;

use crate::{Context, protocol::{MVBAExecState, MVBARoundState}, msg::ProtMsg};

impl Context{
    pub async fn start_fin_mvba(&mut self, 
        instance_id: usize,
        round: usize,
        rbc_value: Option<usize>,
    ){
        log::info!("Starting FIN MVBA for instance {} in round {} with value {:?}", instance_id, round, rbc_value);
        if !self.round_state.contains_key(&instance_id){
            let mvba_round_state = MVBAExecState::new(instance_id);
            self.round_state.insert(instance_id, mvba_round_state);
        }

        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if mvba_exec_state.inp_value.is_none() && rbc_value.is_some(){
            mvba_exec_state.inp_value = Some(rbc_value.unwrap());
        }

        if !mvba_exec_state.mvbas.contains_key(&round){
            let mvba_round_state = MVBARoundState::new(
                instance_id,
                1,
                self.num_faults,
                self.num_nodes
            );
            mvba_exec_state.add_mvba_round(mvba_round_state);
        }

        if mvba_exec_state.inp_value.is_none(){
            log::error!("Did not receive input value for instance {} in round {}. Cannot start MVBA.", instance_id, round);
            return;
        }

        let rbc_value = mvba_exec_state.inp_value.unwrap();
        
        let ctrbc_msg = (instance_id, round as usize, 1 as usize, vec![rbc_value]);
        let ser_msg = bincode::serialize(&ctrbc_msg).unwrap();
        
        let _status = self.ctrbc_req.send(ser_msg).await;
    }

    pub async fn process_l1_rbc_termination(&mut self, 
        instance_id: usize, 
        round: usize, 
        rbc_broadcaster: usize,
        broadcast_val: usize
    ){
        log::info!("Received l1 RBC termination for instance {} and round {} from broadcaster {}",instance_id, round, rbc_broadcaster);
        if !self.round_state.contains_key(&instance_id){
            let mvba_round_state = MVBAExecState::new(instance_id);
            self.round_state.insert(instance_id, mvba_round_state);
        }

        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if mvba_exec_state.terminated_mvbas.contains(&round){
            return;
        }

        if !mvba_exec_state.mvbas.contains_key(&round){
            let mvba_round_state = MVBARoundState::new(
                instance_id,
                round,
                self.num_faults,
                self.num_nodes
            );
            mvba_exec_state.add_mvba_round(mvba_round_state);
        }
        let mvba_round_state = mvba_exec_state.mvbas.get_mut(&round).unwrap();
        let status = mvba_round_state.add_l1_rbc(rbc_broadcaster, broadcast_val);
        
        if status{
            // Initiate L2 RBC
            let mut l2_rbc_vec = Vec::new();
            for party in 0..self.num_nodes{
                if mvba_round_state.l1_rbcs.contains_key(&party){
                    l2_rbc_vec.push(party);
                }
            }

            log::info!("Initializing L2 RBC for instance {} and round {}, vec: {:?}", instance_id, round, l2_rbc_vec);
            

            let ctrbc_msg = (instance_id, round, 2 as usize, l2_rbc_vec);
            let ser_msg = bincode::serialize(&ctrbc_msg).unwrap();
            let _status = self.ctrbc_req.send(ser_msg).await;
        }
        // Also check change in l2/final agreement status because of l1 delivery
        self.verify_l2_rbc_status_check(instance_id, round, Some((rbc_broadcaster,broadcast_val)), None).await;
    }

    pub async fn process_l2_rbc_termination(&mut self,
        instance_id: usize,
        round: usize,
        rbc_broadcaster: usize,
        broadcast_indices: Vec<usize>
    ){
        log::info!("Received l2 RBC termination for instance {} and round {} from broadcaster {}",instance_id, round, rbc_broadcaster);
        if !self.round_state.contains_key(&instance_id){
            let mvba_round_state = MVBAExecState::new(instance_id);
            self.round_state.insert(instance_id, mvba_round_state);
        }

        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if mvba_exec_state.terminated_mvbas.contains(&round){
            return;
        }

        if !mvba_exec_state.mvbas.contains_key(&round){
            let mvba_round_state = MVBARoundState::new(
                instance_id,
                round,
                self.num_faults,
                self.num_nodes
            );
            mvba_exec_state.add_mvba_round(mvba_round_state);
        }
        let mvba_round_state = mvba_exec_state.mvbas.get_mut(&round).unwrap();
        let collection = HashSet::from_iter(broadcast_indices.clone().into_iter());
        mvba_round_state.l2_rbcs.insert(rbc_broadcaster, collection);
        mvba_round_state.l2_rbc_vecs.insert(rbc_broadcaster , broadcast_indices);
        // Check l2 RBCs and their completion
        self.verify_l2_rbc_status_check(
            instance_id, 
            round, 
            None,
            Some(rbc_broadcaster) 
        ).await;
        self.verify_l3_witness_termination(
            instance_id, 
            round, 
            Some(rbc_broadcaster),
            None 
        ).await;
    }

    pub async fn verify_l2_rbc_status_check(&mut self, 
        instance_id: usize,
        round: usize,
        new_l1_rbc: Option<(usize, usize)>,
        
        new_l2_rbc: Option<usize>
    ){
        if !self.round_state.contains_key(&instance_id){
            return;
        }
        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if !mvba_exec_state.mvbas.contains_key(&round){
            return;
        }

        let mvba_round_state = mvba_exec_state.mvbas.get_mut(&round).unwrap();

        if new_l1_rbc.is_some(){
            let l1_rbc_sender = new_l1_rbc.unwrap().0;
            // Iterate through l2 RBCs and check if the l1 list is empty
            for rep in 0..self.num_nodes{
                if mvba_round_state.l2_rbcs.contains_key(&rep){
                    let party_set = mvba_round_state.l2_rbcs.get_mut(&rep).unwrap();
                    party_set.remove(&l1_rbc_sender);

                    if party_set.is_empty(){
                        mvba_round_state.l2_approved_rbcs.insert(rep);
                    }
                }
            }
        }
        if new_l2_rbc.is_some(){
            let l2_rbc_broadcaster = new_l2_rbc.unwrap();
            
            let party_set_bcast = mvba_round_state.l2_rbcs.get_mut(&l2_rbc_broadcaster).unwrap();
            for rep in 0..self.num_nodes{
                if mvba_round_state.l1_rbcs.contains_key(&rep){
                    party_set_bcast.remove(&rep);
                }
            }
            if party_set_bcast.is_empty(){
                mvba_round_state.l2_approved_rbcs.insert(l2_rbc_broadcaster);
            }
        }

        if mvba_round_state.l2_approved_rbcs.len() >= self.num_nodes - self.num_faults && !mvba_round_state.l3_witness_sent{
            // Craft an L3 witness message
            log::info!("Broadcasting L3 witness for instance {} and round {}", instance_id, round);
            let witness_parties: Vec<usize> = mvba_round_state.l2_approved_rbcs.clone().into_iter().collect();

            let witness_msg = ProtMsg::L3Witness(instance_id, round, witness_parties, self.myid);
            mvba_round_state.l3_witness_sent = true;

            self.broadcast(witness_msg).await;            
        }
        self.verify_round_termination(instance_id, round).await;
    }

    pub async fn process_incoming_l3_witness(&mut self,
        instance_id: usize, 
        round: usize, 
        witnesses: Vec<Replica>,
        share_sender: usize,
    ){
        log::info!("Received L3 witness for instance {} and round {} from sender {}", instance_id, round, share_sender);
        if !self.round_state.contains_key(&instance_id){
            let mvba_round_state = MVBAExecState::new(instance_id);
            self.round_state.insert(instance_id, mvba_round_state);
        }

        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if !mvba_exec_state.mvbas.contains_key(&round){
            let mvba_round_state = MVBARoundState::new(
                instance_id,
                round,
                self.num_faults,
                self.num_nodes
            );
            mvba_exec_state.add_mvba_round(mvba_round_state);
        }
        let mvba_round_state = mvba_exec_state.mvbas.get_mut(&round).unwrap();
        mvba_round_state.l3_witnesses.insert(share_sender, HashSet::from_iter(witnesses.into_iter()));
        
        self.verify_l3_witness_termination(instance_id, round, None, Some(share_sender)).await;
    }

    pub async fn verify_l3_witness_termination(&mut self,
        instance_id: usize,
        round: usize,
        l2_rbc: Option<usize>,
        l3_witness: Option<usize>,
    ){
        if !self.round_state.contains_key(&instance_id){
            return;
        }
        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if !mvba_exec_state.mvbas.contains_key(&round){
            return;
        }

        let mvba_round_state = mvba_exec_state.mvbas.get_mut(&round).unwrap();

        if l2_rbc.is_some(){
            let l2_rbc_sender = l2_rbc.unwrap();
            // Iterate through l2 RBCs and check if the l1 list is empty
            for rep in 0..self.num_nodes{
                if mvba_round_state.l3_witnesses.contains_key(&rep){
                    let party_set = mvba_round_state.l3_witnesses.get_mut(&rep).unwrap();
                    party_set.remove(&l2_rbc_sender);

                    if party_set.is_empty(){
                        mvba_round_state.l3_approved_witnesses.insert(rep);
                    }
                }
            }
        }
        if l3_witness.is_some(){
            let l3_witness_broadcaster = l3_witness.unwrap();
            
            let party_set_bcast = mvba_round_state.l3_witnesses.get_mut(&l3_witness_broadcaster).unwrap();
            for rep in 0..self.num_nodes{
                if mvba_round_state.l2_rbcs.contains_key(&rep){
                    party_set_bcast.remove(&rep);
                }
            }
            if party_set_bcast.is_empty(){
                mvba_round_state.l3_approved_witnesses.insert(l3_witness_broadcaster);
            }
        }

        if mvba_round_state.l3_approved_witnesses.len() >= self.num_nodes - self.num_faults && !mvba_round_state.coin_broadcasted{
            // // Create and broadcast coin message
            if !self.coin_shares.contains_key(&instance_id){
                log::error!("Error in coin tossing: Coin shares not found for instance {}", instance_id);
                return;
            }
            let instance_coin_shares = self.coin_shares.get_mut(&instance_id).unwrap();
            if instance_coin_shares.is_empty(){
                log::error!("Error in coin tossing: Coin shares are empty for instance {}", instance_id);
                return;
            }
            log::info!("Broadcasting coin for instance {} and round {}", instance_id, round);
            mvba_round_state.coin_broadcasted = true;

            let coin_share = instance_coin_shares.pop_front().unwrap();
            
            let coin_msg = ProtMsg::LeaderCoin(
                instance_id, 
                round, 
                coin_share, 
                self.myid
            );
            self.broadcast(coin_msg).await;
        }
        self.verify_round_termination(instance_id, round).await;
    }

    pub async fn process_incoming_leader_coin(&mut self, 
        instance_id: usize, 
        round: usize, 
        coin_share: LargeFieldSer,
        share_sender: usize,
    ){
        log::info!("Received leader coin for instance {} and round {} from sender {}", instance_id, round, share_sender);
        
        if !self.round_state.contains_key(&instance_id){
            let mvba_round_state = MVBAExecState::new(instance_id);
            self.round_state.insert(instance_id, mvba_round_state);
        }

        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if !mvba_exec_state.mvbas.contains_key(&round){
            let mvba_round_state = MVBARoundState::new(
                instance_id,
                round,
                self.num_faults,
                self.num_nodes
            );
            mvba_exec_state.add_mvba_round(mvba_round_state);
        }
        let mvba_round_state = mvba_exec_state.mvbas.get_mut(&round).unwrap();
        
        if mvba_round_state.leader_id.is_some(){
            // Leader already elected, ignore this coin share
            return;
        }
        
        let coin_share = LargeField::from_bytes_be(coin_share.as_slice()).unwrap();
        mvba_round_state.coin_shares.insert(share_sender, coin_share);

        if mvba_round_state.coin_shares.len() == self.num_faults + 1{
            // Reconstruct the coin
            let mut evaluation_points = Vec::new();
            let mut poly_shares = Vec::new();
            for party in 0..self.num_nodes{
                if mvba_round_state.coin_shares.contains_key(&party){
                    evaluation_points.push(LargeField::from(party as u64));
                    poly_shares.push(mvba_round_state.coin_shares.get(&party).unwrap().clone());
                }
            }

            let polynomial = Polynomial::interpolate(&evaluation_points, &poly_shares).unwrap();

            let coin = polynomial.evaluate(&LargeField::from(0 as u64)).to_bytes_be();

            // Elect leader from this seed
            let mut rng = StdRng::from_seed(coin);
            let leader_id = rng.gen_range(0, self.num_nodes);
            
            log::info!("Leader elected for instance {} and round {}: {}", instance_id, round, leader_id);
            mvba_round_state.leader_id = Some(leader_id);

            let mut coin_shares_ba = Vec::new();
            if !self.coin_shares.contains_key(&instance_id){
                log::error!("Error in coin tossing: Coin shares not found for instance {}", instance_id);
                return;
            }
            let coin_shares = self.coin_shares.get_mut(&instance_id).unwrap();
            for _ in 0..5{
                if coin_shares.len() == 0{
                    log::error!("Error in coin tossing: Not enough coins left for instance {}", instance_id);
                    return;
                }
                coin_shares_ba.push(coin_shares.pop_front().unwrap());
            }

            let bin_aa_instance = 100*instance_id + round;
            if mvba_round_state.l2_approved_rbcs.contains(&leader_id){
                log::info!("Leader approved for Binary BA in instance {}", instance_id);
                // Input this to BA
                // Compile coin shares
                let _ra_status  = self.ra_aa_req.send((0, 2, bin_aa_instance)).await;
                let _status = self.bin_aa_req.send((bin_aa_instance, 2, coin_shares_ba)).await;
            }
            else{
                log::info!("Leader not approved for Binary BA in instance {}", instance_id);
                let _status = self.ra_aa_req.send((0, 0, bin_aa_instance)).await;
                let _status = self.bin_aa_req.send((bin_aa_instance, 0, coin_shares_ba)).await;
            }
        }
        self.verify_round_termination(instance_id, round).await;
    }

    pub async fn process_bba_termination(&mut self, 
        bin_aa_instance_id: usize,
        output_val: usize,
    ){
        log::info!("Received BBA termination for instance {} with output value {}", bin_aa_instance_id, output_val);
        let instance_id = bin_aa_instance_id/100;
        let round = bin_aa_instance_id % 100;

        if !self.round_state.contains_key(&instance_id){
            let mvba_round_state = MVBAExecState::new(instance_id);
            self.round_state.insert(instance_id, mvba_round_state);
        }
        
        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if !mvba_exec_state.mvbas.contains_key(&round){
            let mvba_round_state = MVBARoundState::new(
                instance_id,
                round,
                self.num_faults,
                self.num_nodes
            );
            mvba_exec_state.add_mvba_round(mvba_round_state);
        }

        let mvba_round_state = mvba_exec_state.mvbas.get_mut(&round).unwrap();
        
        if mvba_round_state.bba_output.is_none(){
            mvba_round_state.bba_output = Some(output_val);
    
            self.verify_round_termination(instance_id, round).await
        }
    }

    pub async fn process_ra_termination(&mut self, 
        ra_instance_id: usize,
        output_val: usize,
    ){
        log::info!("Received RA termination for instance {} with output value {}", ra_instance_id, output_val);
        let instance_id = ra_instance_id/100;
        let round = ra_instance_id % 100;

        if !self.round_state.contains_key(&instance_id){
            let mvba_round_state = MVBAExecState::new(instance_id);
            self.round_state.insert(instance_id, mvba_round_state);
        }
        
        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if !mvba_exec_state.mvbas.contains_key(&round){
            let mvba_round_state = MVBARoundState::new(
                instance_id,
                round,
                self.num_faults,
                self.num_nodes
            );
            mvba_exec_state.add_mvba_round(mvba_round_state);
        }

        let mvba_round_state = mvba_exec_state.mvbas.get_mut(&round).unwrap();
        mvba_round_state.bba_output = Some(output_val);
        self.verify_round_termination(instance_id, round).await;
    }


    pub async fn verify_round_termination(&mut self, instance_id: usize, round: usize){
        if !self.round_state.contains_key(&instance_id){
            let mvba_round_state = MVBAExecState::new(instance_id);
            self.round_state.insert(instance_id, mvba_round_state);
        }
        
        let mvba_exec_state = self.round_state.get_mut(&instance_id).unwrap();
        if !mvba_exec_state.mvbas.contains_key(&round){
            let mvba_round_state = MVBARoundState::new(
                instance_id,
                round,
                self.num_faults,
                self.num_nodes
            );
            mvba_exec_state.add_mvba_round(mvba_round_state);
        }

        let mvba_round_state = mvba_exec_state.mvbas.get_mut(&round).unwrap();
        if mvba_round_state.bba_output.is_some() && mvba_round_state.leader_id.is_some() && mvba_exec_state.output.is_none(){
            // Round is terminated
            log::info!("Round {} for instance {} is terminated with output {}", round, instance_id, mvba_round_state.bba_output.unwrap());
            let bba_output = mvba_round_state.bba_output.unwrap();
            if bba_output == 2{
                let leader_id = mvba_round_state.leader_id.unwrap();
                if mvba_round_state.l2_rbc_vecs.contains_key(&leader_id){
                    let l2_rbc_vec = mvba_round_state.l2_rbc_vecs.get(&leader_id).unwrap();
                    let mut rbc_outputs = Vec::new();
                    for party in l2_rbc_vec{
                        if mvba_round_state.l1_rbcs.contains_key(party){
                            let l1_rbc = mvba_round_state.l1_rbcs.get(party).unwrap();
                            rbc_outputs.push(l1_rbc.clone());
                        }
                        else{
                            log::info!("Did not receive RBC of party {} yet, waiting for it in instance id {}", party, instance_id);
                            return;
                        }
                    }
                    log::info!("Consensus output in instance {} is {:?}", instance_id, rbc_outputs);
                    mvba_exec_state.output = Some(rbc_outputs.clone());
                    let _status = self.out_mvba_values.send((instance_id, rbc_outputs)).await;
                }
                else{
                    log::info!("Did not terminate leader's RBC yet in instance id {}, waiting for it", instance_id);
                    return;
                }
            }
            else{
                // Start new round
                log::info!("No leader elected in instance {} for round {}, starting new round", instance_id, round);
                self.start_fin_mvba(instance_id, round+1, None).await;
            }
        }
    }
}