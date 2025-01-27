use std::sync::Arc;

use crate::context::Context;
use crypto::hash::verf_mac;
use types::{
    SyncMsg, SyncState, {ProtMsg, WrapperMsg},
};
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
                ProtMsg::Ping(main_msg, rep) => {
                    // RBC initialized
                    log::info!(
                        "Received Ping for instance id {} from node : {:?}",
                        rep,
                        main_msg.origin
                    );
                    self.handle_ping(main_msg).await;
                }
                ProtMsg::Echo(main_msg, rep) => {
                    // RBC initialized
                    log::info!(
                        "Received Echo for instance id {} from node : {:?}",
                        rep,
                        main_msg.origin
                    );
                    self.handle_echo(main_msg, rep).await;
                }
                ProtMsg::Output(main_msg, rep) => {
                    // RBC initialized
                    log::info!(
                        "Received Output for instance id {} from node : {:?}",
                        rep,
                        main_msg.origin
                    );
                    self.handle_ping(main_msg).await;
                }
                ProtMsg::Ready(main_msg, rep) => {
                    log::info!(
                        "Received Ready for instance id {} from node : {:?}",
                        rep,
                        main_msg.origin
                    );
                    self.handle_ready(main_msg, rep).await;
                }
                ProtMsg::Sendall(main_msg, rep) => {
                    // RBC initialized
                    log::info!(
                        "Received Sendall for instance id {} from node : {:?}",
                        rep,
                        main_msg.origin
                    );
                    self.handle_init(main_msg, rep).await;
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
    pub async fn terminate(&mut self, data: Vec<u8>) {
        let cancel_handler = self
            .sync_send
            .send(
                0,
                SyncMsg {
                    sender: self.myid,
                    state: SyncState::COMPLETED,
                    value: data,
                },
            )
            .await;
        self.add_cancel_handler(cancel_handler);
    }
}
