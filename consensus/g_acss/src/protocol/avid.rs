use std::collections::HashMap;

use crate::{Context, protocol::ACSSABState};

impl Context{
    pub async fn handle_avid_termination(&mut self, sender: usize, content: Option<Vec<u8>>){
        log::info!("Received AVID termination message from sender {}",sender);
        if content.is_some(){
            // Decryption necessary here
            let (instance_id, batch,enc_shares) : (usize, usize, Vec<u8>) = bincode::deserialize(content.unwrap().as_slice()).unwrap();
            
            if !self.acss_ab_state.contains_key(&instance_id) {
                let acss_state = ACSSABState::new();
                self.acss_ab_state.insert(instance_id, acss_state);
            }
            let acss_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
            // Deserialize message
            log::info!("Deserialization successful in AVID for sender {}",sender);
            
            if !acss_state.enc_shares.contains_key(&sender){
                acss_state.enc_shares.insert(sender, HashMap::default());
            }
            let share_map = acss_state.enc_shares.get_mut(&sender).unwrap();
            share_map.insert(batch, enc_shares);

            self.decrypt_shares(sender, instance_id).await;
        }
    }
}