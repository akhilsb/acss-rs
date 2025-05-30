use consensus::{interpolate_shares};
use crypto::{decrypt};
use types::Replica;

use crate::{Context, msg::AcssSKEShares};

impl Context{
    pub async fn interpolate_shares(&mut self, sender_rep: Replica, instance_id: usize){
        if !self.acss_ab_state.contains_key(&instance_id){
            return;
        }
        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        
        if !acss_ab_state.shares.contains_key(&sender_rep){
            log::info!("No shares found for sender {} in instance_id {}", sender_rep, instance_id);
            return;
        }
        if !acss_ab_state.shares.get(&sender_rep).unwrap().evaluations.0.is_empty(){
            log::info!("Shares already generated for sender {} in instance_id {}", sender_rep, instance_id);
            return;
        }
        if !acss_ab_state.commitments.contains_key(&sender_rep) ||
            !self.symmetric_keys_avid.keys_to_me.contains_key(&sender_rep) {
            log::info!("No commitments or keys found for sender {} in instance_id {}", sender_rep, instance_id);
            return;
        }
            
        let comm_dzk_vals = acss_ab_state.commitments.get(&sender_rep).unwrap().clone();
        // Interpolate shares here for first t parties
        if !self.use_fft && self.myid < self.num_faults{
            // Interpolate your shares in this case
            let secret_key = self.symmetric_keys_avid.keys_to_me.get(&sender_rep).clone().unwrap().clone();
            let shares = interpolate_shares(secret_key.clone(), comm_dzk_vals.tot_shares, false, 1).into_iter().map(|el| el.to_bytes_be()).collect();
            let nonce_shares = interpolate_shares(secret_key.clone(),self.num_nodes, true, 1u8).into_iter().map(|el| el.to_bytes_be()).collect();
            let blinding_shares = interpolate_shares(secret_key.clone(), self.num_nodes, true, 2u8).into_iter().map(|el| el.to_bytes_be()).collect();
            let blinding_nonce_shares = interpolate_shares(secret_key, self.num_nodes, true, 3u8).into_iter().map(|el| el.to_bytes_be()).collect();
            
            let acss_shares = acss_ab_state.shares.get_mut(&sender_rep).unwrap();
            acss_shares.evaluations = (shares, nonce_shares, acss_shares.evaluations.2.clone());
            acss_shares.blinding_evaluations = (blinding_shares,blinding_nonce_shares, acss_shares.blinding_evaluations.2.clone());
        }
        self.verify_shares(sender_rep,instance_id).await;
    }

    pub async fn decrypt_shares(&mut self, sender_rep: Replica, instance_id: usize) {
        if !self.acss_ab_state.contains_key(&instance_id) {
            return;
        }
        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        if acss_ab_state.shares.contains_key(&sender_rep){
            return;
        }
        if !acss_ab_state.enc_shares.contains_key(&sender_rep) ||
            !self.symmetric_keys_avid.keys_to_me.contains_key(&sender_rep){
            return;
        }
        
        let sec_key = self.symmetric_keys_avid.keys_to_me.get(&sender_rep).unwrap().clone();
        let shares = acss_ab_state.enc_shares.get(&sender_rep).unwrap().clone();
        
        let dec_shares = decrypt(sec_key.as_slice(), shares);
        let shares : AcssSKEShares = bincode::deserialize(dec_shares.as_slice()).unwrap();
        // Decrypt shares here
        // Assuming decrypt function is defined elsewhere
        log::info!("Decrypted shares for sender {} in instance_id {}", sender_rep, instance_id);
        acss_ab_state.shares.insert(sender_rep, shares);
        if self.myid < self.num_faults{
            self.interpolate_shares(sender_rep, instance_id).await;
        }
        else{
            self.verify_shares(sender_rep, instance_id).await;
        }
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