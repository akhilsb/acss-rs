use std::sync::Arc;

use crate::{context::Context, msg::ProtMsg};
use crypto::hash::verf_mac;
use types::{WrapperMsg};

impl Context {
    // This function verifies the Message Authentication Code (MAC) of a sent message
    // A node cannot impersonate as another node because of MACs
    pub fn check_proposal(&self, wrapper_msg: Arc<WrapperMsg<ProtMsg>>) -> bool {
        // validate MAC
        let byte_val =
            bincode::serialize(&wrapper_msg.protmsg).expect("Failed to serialize object");
        let sec_key = match self.sec_key_map.get(&wrapper_msg.clone().sender) {
            Some(val) => val,
            None => {
                panic!("Secret key not available, this shouldn't happen")
            }
        };
        if !verf_mac(&byte_val, &sec_key.as_slice(), &wrapper_msg.mac) {
            log::warn!("MAC Verification failed.");
            return false;
        }
        true
    }

    pub(crate) async fn process_msg(&mut self, wrapper_msg: WrapperMsg<ProtMsg>) {
        log::trace!("Received protocol msg: {:?}", wrapper_msg);
        let msg = Arc::new(wrapper_msg.clone());

        // Verify the message's authenticity before proceeding
        if self.check_proposal(msg) {
            match wrapper_msg.clone().protmsg {
                ProtMsg::Echo(main_msg, rec_to_all, instance_id) => {
                    // RBC initialized
                    log::debug!("Received Echo for instance id {} from node : {}", instance_id, main_msg.origin);
                    self.process_asks_echo(main_msg,  wrapper_msg.sender,rec_to_all,instance_id).await;
                }
                ProtMsg::Ready(main_msg,rec_to_all, instance_id) => {
                    // RBC initialized
                    log::debug!("Received Ready for instance id {} from node : {}", instance_id, main_msg.origin);
                    self.process_asks_ready(main_msg,  wrapper_msg.sender, rec_to_all,instance_id).await;
                }
                ProtMsg::Init(enc_msg,  instance_id) => {
                    // RBC initialized
                    log::debug!("Received Init for instance id {} from node {}", instance_id, wrapper_msg.sender);
                    self.process_init_asks(enc_msg,  wrapper_msg.sender,instance_id).await;
                },
                ProtMsg::Reconstruct(share, instance_id) => {
                    
                    log::debug!("Received Secret Reconstruct for instance id {} from party : {}", instance_id, wrapper_msg.sender);
                    self.process_asks_reconstruct(share, wrapper_msg.sender, instance_id).await;
                }
            }
        } else {
            log::warn!(
                "MAC Verification failed for message {:?}",
                wrapper_msg.protmsg
            );
        }
    }

    // Invoke this function once you terminate the protocol
}
