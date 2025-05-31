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
                ProtMsg::PubRecL1(instance_id, acss_msg_ske) => {
                    // RBC initialized
                    log::debug!("Received PubRecL1 message for instance id {} from node : {}", instance_id, wrapper_msg.sender);
                    self.process_pub_rec_l1_msg(instance_id, acss_msg_ske,wrapper_msg.sender).await;
                }
                ProtMsg::PubRecL2(instance_id, source_party, shares) => {
                    // RBC initialized
                    log::debug!("Received PubRecL2 message for instance id {} from node : {}", instance_id, wrapper_msg.sender);
                    self.process_pub_rec_l2_msg(instance_id, source_party, shares, wrapper_msg.sender).await;
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
