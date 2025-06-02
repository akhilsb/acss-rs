use std::{sync::Arc};

use crypto::hash::verf_mac;
use types::WrapperMsg;

use crate::{context::Context, msg::ProtMsg};

impl Context{
    pub fn check_proposal(&self,wrapper_msg: Arc<WrapperMsg<ProtMsg>>) -> bool {
        // validate MAC
        let byte_val = bincode::serialize(&wrapper_msg.protmsg).expect("Failed to serialize object");
        let sec_key = match self.sec_key_map.get(&wrapper_msg.clone().sender) {
            Some(val) => {val},
            None => {panic!("Secret key not available, this shouldn't happen")},
        };
        if !verf_mac(&byte_val,&sec_key.as_slice(),&wrapper_msg.mac){
            log::warn!("MAC Verification failed.");
            return false;
        }
        true
    }
    /**
     * Message deserialization happens here. Message is deserialized and passed to the appropriate handling function. 
     */
    pub(crate) async fn process_msg(&mut self, wrapper_msg: WrapperMsg<ProtMsg>){
        log::debug!("Received protocol msg: {:?}",wrapper_msg);
        let msg = Arc::new(wrapper_msg.clone());
        if self.check_proposal(msg){
            match wrapper_msg.clone().protmsg {
                
                ProtMsg::LeaderCoin(instance_id,round, coin_share, share_sender) =>{
                    self.process_incoming_leader_coin(instance_id, round, coin_share, share_sender).await;
                },
                ProtMsg::L3Witness(instance_id, round, witnesses, share_sender) => {
                    self.process_incoming_l3_witness(instance_id, round, witnesses, share_sender).await;
                },
            }
        }
        else {
            log::warn!("MAC Verification failed for message {:?}",wrapper_msg.protmsg);
        }
    }
}