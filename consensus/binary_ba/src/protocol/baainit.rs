use std::collections::{HashMap, HashSet};

use consensus::{LargeField, LargeFieldSer};
use types::{Replica, Val};

use lambdaworks_math::{traits::ByteConversion};
use crate::{context::Context, msg::ProtMsg, protocol::RoundStateBin};

/**
 * We use Abraham, Ben-David, and Yandamuri's Binary Byzantine Agreement protocol as the BBA protocol in FIN. 
 * FIN uses a RABA protocol with a higher round complexity. We replace this RABA protocol with Gather and Abraham, Ben-David, and Yandamuri's BBA protocol to achieve BBA within 5 rounds in the best case.
 * Overall, this protocol has a lesser round complexity than FIN and essentially terminates faster because of Gather's higher probability of encountering a stable proposal.  
 * Refer to both protocols for a detailed protocol description. 
 */
impl Context{
    
    pub async fn process_baa_echo(self: &mut Context, msg:Val, echo_sender:Replica, instance_id:usize,baa_round:usize){
        if self.terminated_rounds.contains(&instance_id){
            return;
        }
        log::info!("Received ECHO1 message from node {} with content {:?} for leader round {}, baa round {}",echo_sender,msg,instance_id,baa_round);
        let val = msg.clone();
        let mut terminate = None;
        // To avoid mutable borrow
        let mut msgs_to_send = Vec::new();
        if self.round_state.contains_key(&instance_id){
            let baa_rnd_state_tup = self.round_state.get_mut(&instance_id).unwrap();
            if baa_rnd_state_tup.1.contains(&baa_round){
                return;
            }
            
            let baa_rnd_state = &mut baa_rnd_state_tup.0;
            
            if baa_rnd_state.contains_key(&baa_round){
                let round_state = baa_rnd_state.get_mut(&baa_round).unwrap();
                let (echo1,echo2,echo3) = round_state.add_echo(
                    val,  
                    echo_sender
                );
                
                if echo1.is_some(){
                    msgs_to_send.push(ProtMsg::FinBinAAEcho(echo1.unwrap(), self.myid,instance_id, baa_round));
                    let (_e1,e2,e3) = round_state.add_echo(
                        echo1.unwrap(), 
                        self.myid
                    );
                    if e2.is_some(){
                        log::info!("Sending echo2 message {} for lround {},bround {}",e2.unwrap(),instance_id,baa_round);
                        msgs_to_send.push(ProtMsg::FinBinAAEcho2(e2.unwrap(), self.myid, instance_id,baa_round));    
                    }
                    if e3.is_some(){
                        log::info!("Sending echo3 message {} for lround {},bround {}",e3.unwrap(),instance_id,baa_round);
                        msgs_to_send.push(ProtMsg::FinBinAAEcho3(e3.unwrap(), self.myid, instance_id,baa_round));
                    }
                }
                
                if echo2.is_some(){
                    msgs_to_send.push(ProtMsg::FinBinAAEcho2(echo2.unwrap(), self.myid, instance_id,baa_round));
                    let echo3 = round_state.add_echo2(echo2.unwrap(), self.myid);
                    if echo3.is_some(){
                        msgs_to_send.push(ProtMsg::FinBinAAEcho3(echo3.unwrap(), self.myid, instance_id,baa_round));
                    }
                }
                
                if echo3.is_some(){
                    msgs_to_send.push(ProtMsg::FinBinAAEcho3(echo3.unwrap(), self.myid, instance_id,baa_round));
                    let term = round_state.add_echo3(echo3.unwrap(), self.myid);
                    if term && !round_state.contains_coin(self.myid) && self.coin_shares.contains_key(&instance_id){
                        // Create partial signature and broadcast
                        if !self.coin_shares.contains_key(&instance_id){
                            return;
                        }
                        let coin_shares = self.coin_shares.get_mut(&instance_id).unwrap();
                        if coin_shares.len() <= baa_round{
                            log::error!("Coins unavailable, abandoning BBA round {} for instance {}", baa_round, instance_id);
                            return;
                        }
                        else{
                            let coin_share = coin_shares[baa_round].clone();
                            log::info!("Sending coin share {:?} for lround {}, bround {}",coin_share,instance_id,baa_round);
                            let prot_msg = ProtMsg::BBACoin(instance_id, baa_round, coin_share, self.myid);
                            round_state.add_partial_coin(self.myid, LargeField::from_bytes_be(&coin_share).unwrap());
                            msgs_to_send.push(prot_msg);
                            terminate = round_state.aggregate_p_coins();
                        }
                    }
                }
            }
            else {
                let round_state = RoundStateBin::new_with_echo(msg, 
                    echo_sender, 
                    self.num_faults, 
                    self.num_nodes
                );
                baa_rnd_state.insert(baa_round, round_state);             
            }
        }
        else {
            
            let round_state = RoundStateBin::new_with_echo(
                msg, 
                echo_sender,
                self.num_faults,
                self.num_nodes
            );
            let mut baa_rnd_state = HashMap::default();
            baa_rnd_state.insert(baa_round, round_state);
            self.round_state.insert(instance_id, (baa_rnd_state, HashSet::default()));
        
        }
        for msg in msgs_to_send{
            self.broadcast(msg).await;
        }
        if terminate.is_some(){
            self.round_state.get_mut(&instance_id).unwrap().1.insert(baa_round);  
            self.start_baa(instance_id,baa_round+1, terminate.unwrap().1, terminate.unwrap().0).await;
        }
    }

    pub async fn process_baa_echo2(self: &mut Context, msg: Val, echo2_sender:Replica, instance_id:usize,baa_round:usize){
        if self.terminated_rounds.contains(&instance_id){
            return;
        }
        let mut terminate = None;
        let mut msgs_to_send = Vec::new();
        log::info!("Received ECHO2 message from node {} with content {:?} for lround {}, bround {}",echo2_sender,msg,instance_id,baa_round);
        if self.round_state.contains_key(&instance_id){
            let baa_rnd_state_tup = self.round_state.get_mut(&instance_id).unwrap();
            if baa_rnd_state_tup.1.contains(&baa_round){
                return;
            }
            let baa_rnd_state = &mut baa_rnd_state_tup.0;
            
            if baa_rnd_state.contains_key(&baa_round){
                let round_state = baa_rnd_state.get_mut(&baa_round).unwrap();
                let echo3 = round_state.add_echo2(msg,echo2_sender);
                if echo3.is_some(){
                    let term = round_state.add_echo3(echo3.unwrap(), self.myid);
                    msgs_to_send.push(ProtMsg::FinBinAAEcho3(echo3.unwrap(), self.myid, instance_id,baa_round));
                    log::info!("Sending echo3 message {} for lround {}, bround {}",echo3.unwrap(),instance_id,baa_round);
                    if term && !round_state.contains_coin(self.myid) && self.coin_shares.contains_key(&instance_id){
                        // Create partial signature and broadcast
                        // Create and broadcast coin
                        let coin_shares = self.coin_shares.get_mut(&instance_id).unwrap();
                        if coin_shares.len() <= baa_round{
                            log::error!("Coins unavailable, abandoning BBA round {} for instance {}", baa_round, instance_id);
                            return;
                        }
                        else{
                            let coin_share = coin_shares[baa_round].clone();
                            log::info!("Sending coin share {:?} for lround {}, bround {}",coin_share,instance_id,baa_round);
                            let prot_msg = ProtMsg::BBACoin(instance_id, baa_round, coin_share, self.myid);
                            round_state.add_partial_coin(self.myid, LargeField::from_bytes_be(&coin_share).unwrap());
                            msgs_to_send.push(prot_msg);
                            terminate = round_state.aggregate_p_coins();
                        }
                    }
                }
            }
            else {
                let round_state = RoundStateBin::new_with_echo2(
                    msg, 
                    echo2_sender,
                    self.num_faults,
                    self.num_nodes
                );
                baa_rnd_state.insert(baa_round, round_state);                
            }
        }
        else {
            let round_state = RoundStateBin::new_with_echo2(
                msg, 
                echo2_sender,
                self.num_faults,
                self.num_nodes
            );
            let mut baa_rnd_state = HashMap::default();
            baa_rnd_state.insert(baa_round, round_state);
            self.round_state.insert(instance_id, (baa_rnd_state, HashSet::default()));
        }
        for msg in msgs_to_send{
            self.broadcast(msg).await;
        }
        if terminate.is_some(){
            self.round_state.get_mut(&instance_id).unwrap().1.insert(baa_round);
            self.start_baa(instance_id,baa_round+1, terminate.unwrap().1, terminate.unwrap().0).await;
        }
    }

    pub async fn process_baa_echo3(self: &mut Context, msg: Val, echo3_sender:Replica, instance_id:usize,baa_round:usize){
        if self.terminated_rounds.contains(&instance_id){
            return;
        }
        
        let mut terminate = None;
        log::info!("Received ECHO3 message from node {} with content {:?} for lround {}, bround {}",echo3_sender,msg,instance_id,baa_round);
        if self.round_state.contains_key(&instance_id){
            let baa_rnd_state_tup = self.round_state.get_mut(&instance_id).unwrap();
            if baa_rnd_state_tup.1.contains(&baa_round){
                return;
            }
            let baa_rnd_state = &mut baa_rnd_state_tup.0;
            
            if baa_rnd_state.contains_key(&baa_round){
                let round_state = baa_rnd_state.get_mut(&baa_round).unwrap();
                // term variable signifies whether coin is ready for broadcasting
                let term = round_state.add_echo3(
                    msg,
                    echo3_sender
                );
                if term && !round_state.contains_coin(self.myid) && self.coin_shares.contains_key(&instance_id){
                    // TODO: Broadcasting common coin
                    let coin_shares = self.coin_shares.get_mut(&instance_id).unwrap();
                    if coin_shares.len() <= baa_round{
                        log::error!("Coins unavailable, abandoning BBA round {} for instance {}", baa_round, instance_id);
                        return;
                    }
                    else{
                        let coin_share = coin_shares[baa_round].clone();
                        log::info!("Sending coin share {:?} for lround {}, bround {}",coin_share,instance_id,baa_round);
                        let prot_msg = ProtMsg::BBACoin(instance_id, baa_round, coin_share, self.myid);
                        round_state.coin_shares_vec.insert(self.myid,LargeField::from_bytes_be(&coin_share).unwrap());
                        terminate = round_state.aggregate_p_coins();

                        self.broadcast(prot_msg).await;
                    }
                }
            }
            else {
                let round_state = RoundStateBin::new_with_echo3(
                    msg, 
                    echo3_sender,
                    self.num_faults,
                    self.num_nodes
                );
                baa_rnd_state.insert(baa_round, round_state);                
            }
        }
        else {
            let round_state = RoundStateBin::new_with_echo3(
                msg, 
                echo3_sender,
                self.num_faults,
                self.num_nodes
            );
            let mut baa_rnd_state = HashMap::default();
            baa_rnd_state.insert(baa_round, round_state);
            self.round_state.insert(instance_id, (baa_rnd_state, HashSet::default()));
        }
        if terminate.is_some(){
            self.round_state.get_mut(&instance_id).unwrap().1.insert(baa_round);
            self.start_baa(instance_id,baa_round+1, terminate.unwrap().1, terminate.unwrap().0).await;
        }
    }

    pub async fn process_coin_share(self:&mut Context, share: LargeFieldSer,share_sender:Replica,instance_id:usize,baa_round:usize){
        if self.terminated_rounds.contains(&instance_id){
            return;
        }
        
        log::info!("Received partial signature message from node {} with lround {}, bround: {}",share_sender,instance_id,baa_round);
        let share: LargeField = LargeField::from_bytes_be(share.as_slice()).unwrap();
        let mut terminate = None;
        if self.round_state.contains_key(&instance_id){
            
            let baa_rnd_state_tup = self.round_state.get_mut(&instance_id).unwrap();
            if baa_rnd_state_tup.1.contains(&baa_round){
                return;
            }

            let baa_rnd_state = &mut baa_rnd_state_tup.0;
            if baa_rnd_state.contains_key(&baa_round){
                let rnd_state = baa_rnd_state.get_mut(&baa_round).unwrap();
                if rnd_state.coin_shares_vec.len() < self.num_faults +1{
                    rnd_state.add_partial_coin(share_sender, share);
                    terminate = rnd_state.aggregate_p_coins();
                }
            }
            else {
                let rnd_state = RoundStateBin::new_with_pcoin(
                    share,
                    share_sender,
                    self.num_faults,
                    self.num_nodes
                );
                baa_rnd_state.insert(baa_round, rnd_state);
            }
        }
        else {
            let rnd_state = RoundStateBin::new_with_pcoin(
                share,
                share_sender,
                self.num_faults,
                self.num_nodes
            );
            let mut baa_rnd_state = HashMap::default();
            baa_rnd_state.insert(baa_round, rnd_state);
            self.round_state.insert(instance_id, (baa_rnd_state, HashSet::default()));
        }
        if terminate.is_some(){
            self.round_state.get_mut(&instance_id).unwrap().1.insert(baa_round);
            self.start_baa(instance_id,baa_round+1, terminate.unwrap().1, terminate.unwrap().0).await;
        }
    }

    pub async fn start_baa(self: &mut Context,instance_id:usize, baa_round:usize, term_val: Val, terminate: bool){
        if self.terminated_rounds.contains(&instance_id){
            return;
        }
        if !terminate{
            log::info!("Received request to start new round instance_id {} bround {}",instance_id,baa_round);
            // Restart next round with updated value
            self.broadcast(ProtMsg::FinBinAAEcho(term_val, self.myid, instance_id,baa_round)).await;
        }
        else {
            // Find target proposal that was elected
            self.terminated_rounds.insert(instance_id);
            log::info!("Terminating BAA round {} for instance {}, broadcasting value {:?}",baa_round,instance_id,term_val);
            let _status = self.out_bin_ba_values.send((instance_id, term_val)).await;
            if _status.is_err(){
                log::error!("Failed to send BAA value for instance {}",instance_id);
            }
        }
    }
}