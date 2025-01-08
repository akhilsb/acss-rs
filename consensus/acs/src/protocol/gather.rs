impl Context{
    pub async fn process_gatherecho(self: &mut Context,wss_indices:Vec<Replica>, echo_sender:Replica,round: u32){
        let now = SystemTime::now();
        if !self.round_state.contains_key(&round){
            let rbc_new_state = CTRBCState::new(BigUint::from_u16(0u16).unwrap(),self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        log::info!("Received gather echo message {:?} from node {} for round {}",wss_indices.clone(),echo_sender,round);
        if rbc_state.send_w2{
            log::warn!("Ignoring echo1 because protocol moved forward to echo2s");
            return;
        }
        else {
            rbc_state.witness1.insert(echo_sender, wss_indices);
            self.add_benchmark(String::from("process_gatherecho"), now.elapsed().unwrap().as_nanos());
            self.witness_check(round).await;
        }
    }

    pub async fn process_gatherecho2(self: &mut Context,wss_indices:Vec<Replica>, echo_sender:Replica,round: u32){
        let now = SystemTime::now();
        if !self.round_state.contains_key(&round){
            let rbc_new_state = CTRBCState::new(BigUint::from_u16(0u16).unwrap(),self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        log::info!("Received gather echo2 message {:?} from node {} for round {}",wss_indices.clone(),echo_sender,round);
        rbc_state.witness2.insert(echo_sender, wss_indices);
        self.add_benchmark(String::from("process_gatherecho"), now.elapsed().unwrap().as_nanos());
        self.witness_check(round).await;
    }
    
    #[async_recursion]
    pub async fn witness_check(self: &mut Context,round:Round){
        let _now = SystemTime::now();
        if !self.round_state.contains_key(&round){
            return;
        }
        //let mut appxcon_vals_fin = HashMap::default();
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        let mut i = 0;
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        if !rbc_state.send_w2{
            for (_replica,ss_inst) in rbc_state.witness1.clone().into_iter(){
                let check = ss_inst.iter().all(|item| rbc_state.terminated_secrets.contains(item));
                if check {
                    i = i+1;
                }
            }
            if i >= self.num_nodes-self.num_faults{
                // echo2 need to be sent? If the round does not have secret sharing, gather2 is not necessary, can just move forward. 
                // echo2 only needs to be sent when the round has secret sharing. 
                if round%self.frequency == 0{
                    // Send out ECHO2 messages
                    log::info!("Accepted n-f witnesses, sending ECHO2 messages for Gather from node {}",self.myid);
                    rbc_state.send_w2 = true;
                    msgs_to_be_sent.push(CoinMsg::GatherEcho2(
                        GatherMsg{nodes: rbc_state.terminated_secrets.clone().into_iter().collect()},
                        self.myid,
                        round)
                    );
                }
                else{
                    if !rbc_state.started_baa && self.bin_bun_aa{
                        rbc_state.started_baa = true;
                        // Begin next round by updating Approximate Consensus values
                        // begin next round
                        // Bundled Approximate Agreement or Binary Approximate Agreement?
                        self.check_begin_next_round(round).await;
                    }
                }
            }
        }
        else{
            for (_replica,ss_inst) in rbc_state.witness2.clone().into_iter(){
                let check = ss_inst.iter().all(|item| rbc_state.terminated_secrets.contains(item));
                if check {
                    i = i+1;
                }
            }    
            if i >= self.num_nodes-self.num_faults && !rbc_state.started_baa{
                // Received n-f witness2s. Start approximate agreement from here. 
                log::error!("Accepted n-f witness2 for node {} with set {:?}",self.myid,rbc_state.terminated_secrets.clone());
                rbc_state.started_baa = true;
                // First beacon should have terminated. 
                if round >= self.rounds_aa+3{
                    let closest_finished = round-self.rounds_aa-3;
                    let fin_freq = (closest_finished/self.frequency)*self.frequency;
                    log::error!("Requesting beacon for committee election  for round {:?} with coin from round {}",round,fin_freq);
                    if rbc_state.committee.len()<self.num_nodes{
                        // If the committee is already elected, no need for beacon reconstruction
                        // Note that this condition can be triggered multiple times. Hence, do not reconstruct beacon again and again, only for the first time
                        self.check_begin_next_round(round).await;
                    }
                    else {
                        self.reconstruct_beacon(fin_freq, 0).await;   
                    }
                }
                else{
                    self.check_begin_next_round(round).await;
                }

                // let terminated_secrets = rbc_state.terminated_secrets.clone();
                // let mut transmit_vector:Vec<(Replica,BigInt)> = Vec::new();
                // let rounds = self.rounds_aa;
                // for i in 0..self.num_nodes{
                //     if !terminated_secrets.contains(&i) {
                //         let zero = BigInt::from(0);
                //         transmit_vector.push((i,zero));
                //     }
                //     else {
                //         let max = BigInt::from(2);
                //         let max_power = pow(max, rounds as usize);
                //         transmit_vector.push((i,max_power));
                //     }
                // }
                // Start Approximate Agreement with this protocol
                //self.start_baa(transmit_vector,0).await;
            }
        }
        for prot_msg in msgs_to_be_sent.iter(){
            self.broadcast(prot_msg.clone(),round.clone()).await;
            match prot_msg {
                CoinMsg::GatherEcho2(gather, echo_sender,round) =>{
                    self.process_gatherecho2(gather.nodes.clone(), echo_sender.clone(), round.clone()).await;
                },
                _ => {}
            }
        }
        
    }

    pub async fn check_begin_next_round(&mut self,round: u32){
        let appxcon_vals_fin:HashMap<Round,Vec<(Replica,BigUint)>> = self.next_round_vals(round).await;
        //appxcon_vals_fin.clone_from();
        if !appxcon_vals_fin.is_empty(){
            // Bundled Approximate Agreement
            if self.bin_bun_aa{
                //let appxcon_vals = self.next_round_vals(round).await;
                // serialization important. HashMap serialization is problematic.
                let mut vec_round_vals = Vec::new();
                for (round,values) in appxcon_vals_fin.into_iter(){
                    vec_round_vals.push((round,values));
                }
                self.start_new_round(round,vec_round_vals).await;
            }
            // Binary Approximate Agreement
            else{
                for (round_iter,values) in appxcon_vals_fin.into_iter(){
                    let rbc_state_iter = self.round_state.get_mut(&round_iter).unwrap();
                    // Create new roundstate object
                    let mut round_state = RoundState::new_with_echo(Vec::new(), self.myid);
                    for (rep,value) in values.into_iter(){
                        round_state.term_vals.insert(rep, value);
                    }
                    rbc_state_iter.round_state.insert(round, round_state);
                }
                self.next_round_begin(round).await;
            }
        }
    }
}