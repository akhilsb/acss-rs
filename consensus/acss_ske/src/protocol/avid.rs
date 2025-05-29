use crate::{Context, protocol::ACSSABState};

impl Context{
    pub async fn handle_avid_termination(&mut self, instance_id: usize, sender: usize, content: Option<Vec<u8>>){
        log::info!("Received AVID termination message from sender {}",sender);
        if content.is_some(){
            // Decryption necessary here

            //let (instance_id,shares) : (usize,(Vec<LargeFieldSer>,LargeFieldSer,LargeFieldSer)) = bincode::deserialize(content.unwrap().as_slice()).unwrap();
            
            if !self.acss_ab_state.contains_key(&instance_id) {
                let acss_state = ACSSABState::new();
                self.acss_ab_state.insert(instance_id, acss_state);
            }
            let acss_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
            // Deserialize message
            log::info!("Deserialization successful in AVID for sender {}",sender);
            
            acss_state.enc_shares.insert(sender, content.unwrap());
            self.decrypt_shares(sender, instance_id).await;
        }
    }
}