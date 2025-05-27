use std::sync::Arc;

use super::{ProtMsg};
use crate::{context::Context};
use crypto::hash::verf_mac;
//use network::{plaintcp::CancelHandler, Acknowledgement};
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
                // ProtMsg::Init(enc_shares, num_secrets, comm, polynomial, dealer, instance_id) => {
                //     // RBC initialized
                //     log::debug!("Received Init for instance id {} from node : {}", instance_id, dealer);
                //     self.process_acss_init(enc_shares,num_secrets,comm,polynomial, dealer, instance_id).await;
                // },
                ProtMsg::ACSSTerm(instance_id, party) => {
                    // RBC initialized
                    log::debug!("Received Init for instance id {} from node : {}", instance_id, wrapper_msg.sender);
                    self.process_acss_termination(instance_id, party, wrapper_msg.sender).await;
                },
            }
        } else {
            log::warn!(
                "MAC Verification failed for message {:?}",
                wrapper_msg.protmsg
            );
        }
    }
}
