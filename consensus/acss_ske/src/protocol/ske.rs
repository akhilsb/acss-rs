use consensus::{interpolate_shares, LargeFieldSer};
use crypto::{decrypt};
use types::Replica;

use crate::Context;

impl Context{
    pub async fn interpolate_shares(&mut self, sender_rep: Replica, instance_id: usize){
        if !self.acss_ab_state.contains_key(&instance_id){
            return;
        }
        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        if !acss_ab_state.commitments.contains_key(&sender_rep) ||
            !self.symmetric_keys_avid.keys_to_me.contains_key(&sender_rep) || 
            acss_ab_state.shares.contains_key(&sender_rep){
            log::info!("Shares already generated for sender {} in instance_id {}", sender_rep, instance_id);
            return;
        }
        let comm_dzk_vals = acss_ab_state.commitments.get(&sender_rep).unwrap().clone();
        // Interpolate shares here for first t parties
        if !self.use_fft && self.myid < self.num_faults{
            // Interpolate your shares in this case
            let secret_key = self.symmetric_keys_avid.keys_to_me.get(&sender_rep).clone().unwrap().clone();
            let shares = interpolate_shares(secret_key.clone(), comm_dzk_vals.3, false, 1).into_iter().map(|el| el.to_bytes_be()).collect();
            let nonce_share = interpolate_shares(secret_key.clone(),1, true, 1u8)[0].to_bytes_be();
            let blinding_nonce_share = interpolate_shares(secret_key, 1, true, 3u8)[0].to_bytes_be();
            acss_ab_state.shares.insert(sender_rep, (shares,nonce_share,blinding_nonce_share));
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
        let (instance_id,shares) : (usize,(Vec<LargeFieldSer>,LargeFieldSer,LargeFieldSer)) = bincode::deserialize(dec_shares.as_slice()).unwrap();
        // Decrypt shares here
        // Assuming decrypt function is defined elsewhere
        log::info!("Decrypted shares for sender {} in instance_id {}", sender_rep, instance_id);
        acss_ab_state.shares.insert(sender_rep, shares);
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