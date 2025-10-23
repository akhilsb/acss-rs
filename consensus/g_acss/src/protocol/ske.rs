use std::collections::HashMap;

use consensus::{expand_sharing_to_n_evaluation_points, interpolate_shares, LargeField};
use crypto::{decrypt};
use types::Replica;

use crate::{Context, msg::AcssSKEShares};

impl Context{
    pub async fn interpolate_shares(&mut self, sender_rep: Replica, instance_id: usize){
        if !self.acss_ab_state.contains_key(&instance_id){
            return;
        }
        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        
        if acss_ab_state.shares.contains_key(&sender_rep){
            log::info!("Shares already interpolated for sender {} in instance_id {}", sender_rep, instance_id);
            return;
        }
        if !acss_ab_state.commitments.contains_key(&sender_rep) ||
            !self.symmetric_keys_avid.keys_to_me.contains_key(&sender_rep) {
                log::info!("No commitments or keys found for sender {} in instance_id {}", sender_rep, instance_id);
                return;
        }
        
        let comm_dzk_vals = acss_ab_state.commitments.get(&sender_rep).unwrap().clone();
        
        if !acss_ab_state.batch_wise_shares.contains_key(&sender_rep){
            acss_ab_state.batch_wise_shares.insert(sender_rep.clone(), HashMap::default());
        }
        let batch_wise_shares_map = acss_ab_state.batch_wise_shares.get_mut(&sender_rep).unwrap();
        // Interpolate shares here for first t parties
        if !self.use_fft && self.myid < self.num_faults{
            // Interpolate your shares in this case
            let secret_key = self.symmetric_keys_avid.keys_to_me.get(&sender_rep).clone().unwrap().clone();
            let shares: Vec<LargeField> = interpolate_shares(secret_key.clone(), comm_dzk_vals.tot_shares, false, 1).into_iter().map(|el| el).collect();
            
            let shares_grouped = shares.chunks(self.num_faults+1).map(|chunk| chunk.to_vec()).collect::<Vec<Vec<LargeField>>>();
            let expanded_shares = expand_sharing_to_n_evaluation_points(
                shares_grouped, 
                self.num_faults, 
                self.num_nodes
            ).await.0;

            let mut batch_wise_shares = vec![vec![]; self.num_nodes];

            for poly_evaluation in expanded_shares.into_iter(){
                for (i, share) in poly_evaluation.into_iter().enumerate(){
                    batch_wise_shares[i].push(share.to_bytes_be());
                }
            }

            let nonce_shares = vec![interpolate_shares(secret_key.clone(),self.num_faults, true, 1u8)];
            
            let expanded_nonce_shares = expand_sharing_to_n_evaluation_points(
                nonce_shares, 
                self.num_faults, 
                self.num_nodes
            ).await.0;

            let blinding_shares = vec![interpolate_shares(secret_key.clone(), self.num_faults, true, 2u8)];
            let expanded_blinding_shares = expand_sharing_to_n_evaluation_points(
                blinding_shares,
                self.num_faults,
                self.num_nodes
            ).await.0;

            let blinding_nonce_shares = vec![interpolate_shares(secret_key, self.num_faults, true, 3u8)];
            let expanded_blinding_nonce_shares = expand_sharing_to_n_evaluation_points(
                blinding_nonce_shares,
                self.num_faults,
                self.num_nodes
            ).await.0;
            
            for batch in 0..self.num_nodes{
                let acss_ske_shares = AcssSKEShares{
                    evaluations: (batch_wise_shares[batch].clone(),expanded_nonce_shares[0][batch].to_bytes_be()),
                    blinding_evaluations: (expanded_blinding_shares[0][batch].to_bytes_be(), expanded_blinding_nonce_shares[0][batch].to_bytes_be()),
                    rep: sender_rep,
                    batch: batch
                };
                batch_wise_shares_map.insert(batch, acss_ske_shares);
            }
        }
        self.verify_shares(sender_rep,instance_id).await;
    }

    pub async fn decrypt_shares(&mut self, sender_rep: Replica, instance_id: usize) {
        if self.myid < self.num_faults{
            self.interpolate_shares(sender_rep, instance_id).await;
            return;
        }
        if !self.acss_ab_state.contains_key(&instance_id) {
            return;
        }
        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        
        if !acss_ab_state.enc_shares.contains_key(&sender_rep) ||
            !self.symmetric_keys_avid.keys_to_me.contains_key(&sender_rep){
            return;
        }
        
        let sec_key = self.symmetric_keys_avid.keys_to_me.get(&sender_rep).unwrap().clone();
        let enc_shares = acss_ab_state.enc_shares.get_mut(&sender_rep).unwrap();
        
        if !acss_ab_state.batch_wise_shares.contains_key(&sender_rep){
            acss_ab_state.batch_wise_shares.insert(sender_rep, HashMap::default());
        }

        let batch_wise_shares = acss_ab_state.batch_wise_shares.get_mut(&sender_rep).unwrap();
        for (batch, encrypted_shares) in enc_shares.clone().into_iter(){
            let dec_shares = decrypt(sec_key.as_slice(), encrypted_shares.clone());
            let shares : AcssSKEShares = bincode::deserialize(dec_shares.as_slice()).unwrap();
            batch_wise_shares.insert(batch, shares);

            enc_shares.remove(&batch);
        }
        
        self.verify_shares(sender_rep, instance_id).await;
    }

    pub async fn decrypt_shares_all_instances(&mut self, party: Replica){
        let mut encrypted_instances = Vec::new();
        for (instance_id, acss_ab_state) in self.acss_ab_state.iter_mut() {
            if acss_ab_state.enc_shares.contains_key(&party) && !acss_ab_state.shares.contains_key(&party) {
                encrypted_instances.push(instance_id.clone());
            }
        }
        for instance_id in encrypted_instances {
            self.decrypt_shares(party, instance_id).await;
        }
    }
}