use std::collections::{HashMap, HashSet};

use crypto::{LargeField, LargeFieldSer, hash::{Hash}};
use num_bigint_dig::RandBigInt;
//use num_bigint_dig::RandBigInt;
use types::Replica;

use crate::{Context, msg::{ProtMsg, CTRBCInterface}};

impl Context{
    pub async fn start_acss(&mut self, num_points: usize){
        // Sample num_points random points
        let mut random_points = Vec::new();
        let zero = LargeField::from(0);
        for _ in 0..num_points{
            let rand_int = rand::thread_rng().gen_bigint_range(&zero, &self.large_field_prime);
            random_points.push(rand_int.to_signed_bytes_be());
        }
        let id = self.max_id;
        let _status = self.acss_req.send((id, random_points.clone())).await;
        let _status = self.acss_req.send((id+1, random_points)).await;

        self.max_id = id+2;
    }

    pub async fn process_acss_event(&mut self, inst: usize, sender: usize, root_comm: Hash, shares_ser: Vec<LargeFieldSer>){
        log::info!("Received ACSS terminated event for instance {}, dealer: {}, with shares: {}", inst, sender, shares_ser.len());
        let shares_deser = shares_ser.into_iter().map(|x| LargeField::from_signed_bytes_be(x.as_slice())).collect(); 
        

        let inst_key = (inst+1)/2;
        let first_or_second = inst%2;

        if !self.acss_map.contains_key(&sender){
            let hash_map = HashMap::default();
            self.acss_map.insert(sender, hash_map);
        }
        
        let party_share_map = self.acss_map.get_mut(&sender).unwrap();
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
            let mut root_comm_lf = LargeField::from_signed_bytes_be(core_root.as_slice())%&self.large_field_prime;
            if root_comm_lf < LargeField::from(0){
                root_comm_lf += &self.large_field_prime;
            }

            // Construct aggregated shares and broadcast them within committee
            let mut root_comm_mul = root_comm_lf.clone();
            let mut agg_share_c1 = LargeField::from(0);
            let mut agg_share_c2 = LargeField::from(0);

            for (f_share, s_share) in first_comm_shares.0.into_iter().zip(second_comm_shares.0.into_iter()){
                agg_share_c1 += (&root_comm_mul*f_share)%&self.large_field_prime;
                agg_share_c2 += (&root_comm_mul*s_share)%&self.large_field_prime;

                root_comm_mul = (&root_comm_mul*&root_comm_lf)%&self.large_field_prime;
            }

            // Send both shares individually
            // craft message
            let sec_eq_c1 = ProtMsg::SecEq(inst_key, sender, 1, agg_share_c1.to_signed_bytes_be());
            let sec_eq_c2 = ProtMsg::SecEq(inst_key, sender, 2, agg_share_c2.to_signed_bytes_be());

            self.broadcast(sec_eq_c1).await;
            self.broadcast(sec_eq_c2).await;

            self.check_acss_and_secret_equivalence_termination(sender).await;
        }
    }

    pub async fn process_sec_equivalence_msg(&mut self, inst_key: usize,origin: Replica, sender: Replica, c1_c2: u8, eval_point: LargeFieldSer){
        if self.acs_input_set.contains(&origin){
            return;
        }
        let eval_point_lf = LargeField::from_signed_bytes_be(eval_point.as_slice());
        if !self.sec_equivalence.contains_key(&origin){
            self.sec_equivalence.insert(origin, HashMap::default());
        }

        let sec_eq_map = self.sec_equivalence.get_mut(&origin).unwrap();
        if !sec_eq_map.contains_key(&inst_key){
            sec_eq_map.insert(inst_key, (HashMap::default(),HashMap::default()));
        }

        let (c1_val_map, c2_val_map) = sec_eq_map.get_mut(&inst_key).unwrap();
        
        if c1_c2 == 1{
            c1_val_map.insert(sender, eval_point_lf);
            if c1_val_map.contains_key(&(self.num_nodes+1)){
                return;
            }
            if c1_val_map.len() == self.num_faults+1{
                // Reconstruct degree-t polynomial
                let mut eval_points = Vec::new();
                for rep in 0..self.num_nodes{
                    if c1_val_map.contains_key(&rep){
                        eval_points.push(((rep+1), c1_val_map.get(&rep).unwrap().clone()));
                    }
                }
                // reconstruct point
                let secret = self.large_field_shamir_ss.recover(eval_points.as_slice());

                log::info!("Reconstructed secret {:?} for instance id {} and origin {} in c_1", secret, inst_key, origin);
                c1_val_map.insert(self.num_nodes+1, secret);
            }
        }
        else {
            c2_val_map.insert(sender, eval_point_lf);
            if c2_val_map.contains_key(&(self.num_nodes+1)){
                return;
            }
            if c2_val_map.len() == self.num_faults+1{
                // Reconstruct degree-t polynomial
                let mut eval_points = Vec::new();
                for rep in 0..self.num_nodes{
                    if c2_val_map.contains_key(&rep){
                        eval_points.push(((rep+1), c2_val_map.get(&rep).unwrap().clone()));
                    }   
                }
                // reconstruct point
                let secret = self.large_field_shamir_ss.recover(eval_points.as_slice());
                log::info!("Reconstructed secret {:?} for instance id {} and origin {} in c_2", secret, inst_key, origin);
                c2_val_map.insert(self.num_nodes+1, secret);
            }

            if c1_val_map.contains_key(&(self.num_nodes+1)) && 
                c2_val_map.contains_key(&(self.num_nodes+1)) &&
                c1_val_map.get(&(self.num_nodes+1)).unwrap() == c2_val_map.get(&(self.num_nodes+1)).unwrap(){
                // Add this instance to completed sharings
                if !self.completed_batches.contains_key(&origin){
                    self.completed_batches.insert(origin, HashSet::default());
                }
                self.completed_batches.get_mut(&origin).unwrap().insert(inst_key);
                self.check_acss_and_secret_equivalence_termination(origin).await;
            }
        }
    }

    pub async fn check_acss_and_secret_equivalence_termination(&mut self, origin: Replica){
        if !self.acss_map.contains_key(&origin) {
            return;
        }
        let acss_share_map = self.acss_map.get(&origin).unwrap();

        if acss_share_map.len()< self.num_batches{
            return;
        }

        if !self.completed_batches.contains_key(&origin){
            return;
        }

        let mut all_instances_term = true;
        for batch in 1..self.num_batches+1{
            let (c1,c2) = acss_share_map.get(&batch).unwrap();
            if c1.is_some() && c2.is_some(){
                all_instances_term = all_instances_term && true;
            }
            else{
                all_instances_term = all_instances_term && false;
            }
        }

        if all_instances_term && self.completed_batches.get_mut(&origin).unwrap().len() == self.num_batches{
            self.acs_input_set.insert(origin);
            log::info!("Completed sharing process for secrets originated by {}, adding to acs_set", origin);
            let ctrbc_msg = CTRBCInterface{
                id: 1,
                msg: Vec::new()
            };
            let ser_msg = bincode::serialize(&ctrbc_msg).unwrap();
            self.process_ctrbc_event(origin, 1, ser_msg).await;
            // Check if ACS already output shares
            self.gen_rand_shares().await;
        }
    }
}