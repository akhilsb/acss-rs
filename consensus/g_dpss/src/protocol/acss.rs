use std::collections::{HashMap, HashSet};

use consensus::LargeFieldSSS;
use crypto::{LargeField, LargeFieldSer, hash::{Hash}, rand_field_element};
use lambdaworks_math::traits::ByteConversion;
use types::Replica;

use crate::{Context, msg::{ProtMsg}};

impl Context{
    pub async fn start_acss(&mut self, num_points: usize){
        // Sample num_points random points
        let mut random_points = Vec::new();
        for _ in 0..num_points{
            let rand_int = rand_field_element();
            random_points.push(rand_int);
        }
        let id = self.max_id;
        let _status = self.acss_req.send((id, random_points.clone())).await;
        let _status = self.acss_req.send((id+1, random_points)).await;

    }

    pub async fn process_acss_event(&mut self, inst: usize, sender: usize, root_comm: Hash, shares_deser: Option<Vec<LargeField>>){
        if shares_deser.is_none(){
            log::error!("Received ACSS terminated event for instance {}, dealer: {}, but shares are None", inst, sender);
            return;
        }
        let shares_deser = shares_deser.unwrap();
        log::info!("Received ACSS terminated event for instance {}, dealer: {}, with shares: {}", inst, sender, shares_deser.len());
        
        let inst_key = (inst+1)/2;
        let first_or_second = inst%2;

        if !self.dpss_state.acss_map.contains_key(&sender){
            let hash_map = HashMap::default();
            self.dpss_state.acss_map.insert(sender, hash_map);
        }
        
        let party_share_map = self.dpss_state.acss_map.get_mut(&sender).unwrap();
        if !party_share_map.contains_key(&inst_key){
            party_share_map.insert(inst_key, (None,None));
        }

        let party_share_map_entry = party_share_map.get_mut(&inst_key).unwrap();
        if first_or_second == 1{
            party_share_map_entry.0 = Some((shares_deser,root_comm));
        }
        else{
            party_share_map_entry.1 = Some((shares_deser,root_comm));
        }
        
        if party_share_map_entry.0.is_some() && party_share_map_entry.1.is_some(){
            // Initiate share equivalence protocol
            log::info!("Sending equivalence message for instance {}", inst_key);
            let party_shares_clone = party_share_map_entry.clone();
            let first_comm_shares = party_shares_clone.0.unwrap();
            let second_comm_shares = party_shares_clone.1.unwrap();
            let root_1 = first_comm_shares.1;
            let root_2 = second_comm_shares.1;

            let core_root = self.hash_context.hash_two(root_1, root_2);
            let root_comm_lf = LargeField::from_bytes_be(core_root.as_slice()).unwrap();

            // Construct aggregated shares and broadcast them within committee
            let mut root_comm_mul = root_comm_lf.clone();
            let mut agg_share_c1 = LargeField::from(0);
            let mut agg_share_c2 = LargeField::from(0);

            for (f_share, s_share) in first_comm_shares.0.into_iter().zip(second_comm_shares.0.into_iter()){
                agg_share_c1 += &root_comm_mul*f_share;
                agg_share_c2 += &root_comm_mul*s_share;

                root_comm_mul = &root_comm_mul*&root_comm_lf;
            }

            // Send both shares individually
            // craft message
            let sec_eq_c1 = ProtMsg::SecEq(inst_key, sender, 1, agg_share_c1.to_bytes_be());
            let sec_eq_c2 = ProtMsg::SecEq(inst_key, sender, 2, agg_share_c2.to_bytes_be());

            self.broadcast(sec_eq_c1).await;
            self.broadcast(sec_eq_c2).await;

            self.check_acss_and_secret_equivalence_termination(sender).await;
        }
        if !self.ba_state.shares_generated{
            self.gen_rand_shares().await;
        }
    }

    pub async fn process_sec_equivalence_msg(&mut self, inst_key: usize,origin: Replica, sender: Replica, c1_c2: u8, eval_point: LargeFieldSer){
        log::info!("Received sec_equivalence message from party {} for origin {} in instance key {}",sender, origin, inst_key);
        if self.acs_input_set.contains(&origin){
            return;
        }
        let eval_point_lf = LargeField::from_bytes_be(eval_point.as_slice()).unwrap();
        if !self.dpss_state.sec_equivalence.contains_key(&origin){
            self.dpss_state.sec_equivalence.insert(origin, HashMap::default());
        }

        let sec_eq_map = self.dpss_state.sec_equivalence.get_mut(&origin).unwrap();
        if !sec_eq_map.contains_key(&inst_key){
            sec_eq_map.insert(inst_key, (HashMap::default(),HashMap::default()));
        }

        let (c1_val_map, c2_val_map) = sec_eq_map.get_mut(&inst_key).unwrap();
        
        if c1_c2 == 1{
            c1_val_map.insert(sender, eval_point_lf);
            if c1_val_map.contains_key(&(self.num_nodes+1)){
                return;
            }
            if c1_val_map.len() >= 2*self.num_faults+1{
                // Reconstruct degree-t polynomial
                let mut eval_points = Vec::new();
                let mut evaluations = Vec::new();
                for rep in 0..self.num_nodes{
                    if c1_val_map.contains_key(&rep){
                        eval_points.push(LargeField::from((rep+1) as u64));
                        evaluations.push(c1_val_map.get(&rep).unwrap().clone());
                    }
                }

                let (verf, poly) = LargeFieldSSS::check_if_all_points_lie_on_degree_x_polynomial(
                    eval_points.clone(), 
                    vec![evaluations], 
                    self.num_faults+1);
                assert!(verf);

                // reconstruct point
                let secret = poly.unwrap()[0].evaluate(&LargeField::zero());

                log::info!("Reconstructed secret {:?} for instance id {} and origin {} in c_1", secret, inst_key, origin);
                c1_val_map.insert(self.num_nodes+1, secret);
            }
        }
        else {
            c2_val_map.insert(sender, eval_point_lf);
            if c2_val_map.contains_key(&(self.num_nodes+1)){
                return;
            }
            if c2_val_map.len() >= 2*self.num_faults+1{
                // Reconstruct degree-t polynomial
                let mut eval_points = Vec::new();
                let mut evaluations = Vec::new();
                for rep in 0..self.num_nodes{
                    if c2_val_map.contains_key(&rep){
                        eval_points.push(LargeField::from((rep+1) as u64));
                        evaluations.push(c1_val_map.get(&rep).unwrap().clone());
                    }
                }

                let (verf, poly) = LargeFieldSSS::check_if_all_points_lie_on_degree_x_polynomial(
                    eval_points.clone(), 
                    vec![evaluations], 
                    self.num_faults+1);
                assert!(verf);

                // reconstruct point
                let secret = poly.unwrap()[0].evaluate(&LargeField::zero());
                log::info!("Reconstructed secret {:?} for instance id {} and origin {} in c_2", secret, inst_key, origin);
                c2_val_map.insert(self.num_nodes+1, secret);
            }

            if c1_val_map.contains_key(&(self.num_nodes+1)) && 
                c2_val_map.contains_key(&(self.num_nodes+1)) &&
                c1_val_map.get(&(self.num_nodes+1)).unwrap() == c2_val_map.get(&(self.num_nodes+1)).unwrap(){
                // Add this instance to completed sharings
                log::info!("Secret equivalence for instance {} and origin {} completed", inst_key, origin);
                if !self.completed_batches.contains_key(&origin){
                    self.completed_batches.insert(origin, HashSet::default());
                }
                self.completed_batches.get_mut(&origin).unwrap().insert(inst_key);
                self.check_acss_and_secret_equivalence_termination(origin).await;
            }
        }
    }

    pub async fn check_acss_and_secret_equivalence_termination(&mut self, origin: Replica){
        if !self.dpss_state.acss_map.contains_key(&origin) {
            return;
        }
        let acss_share_map = self.dpss_state.acss_map.get(&origin).unwrap();

        if acss_share_map.len()< self.num_batches{
            return;
        }

        if !self.completed_batches.contains_key(&origin){
            return;
        }

        let mut all_instances_term = true;
        for batch in 1..self.num_batches+1{
            if !acss_share_map.contains_key(&batch){
                all_instances_term = false;
                continue;
            }
            let (c1,c2) = acss_share_map.get(&batch).unwrap();
            if c1.is_some() && c2.is_some(){
                all_instances_term = all_instances_term && true;
            }
            else{
                all_instances_term = all_instances_term && false;
            }
        }

        if all_instances_term && self.completed_batches.get_mut(&origin).unwrap().len() >= self.num_batches && !self.acs_input_set.contains(&origin){
            self.acs_input_set.insert(origin);
            log::info!("Sending instance {} to ACS for consensus", origin);
            let _status = self.acs_term_event.send((1,origin, vec![])).await;
            // Check if ACS already output shares
            self.gen_rand_shares().await;
        }
    }
}