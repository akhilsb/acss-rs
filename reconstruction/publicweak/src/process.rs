use std::{sync::Arc};

use crypto::hash::{verf_mac};
use types::{{WrapperMsg, ProtMsg}, SyncMsg, SyncState};
use crate::context::Context;

impl Context{
    // This function verifies the Message Authentication Code (MAC) of a sent message
    // A node cannot impersonate as another node because of MACs
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
    
    pub(crate) async fn process_msg(&mut self, wrapper_msg: WrapperMsg<ProtMsg>){
        log::debug!("Received protocol msg: {:?}",wrapper_msg);
        let msg = Arc::new(wrapper_msg.clone());
        if self.check_proposal(msg){
            match wrapper_msg.clone().protmsg {
                // Handle each message type appropriately and write functions to evaluate each type of message

                ProtMsg::DistributeSharingOfShare(main_msg,rep)=> {
                    log::info!("Received DistributeSharingOfShare from node : {:?}",rep);
                    self.handle_distribute_sharing_of_share_message(main_msg).await;
                }

                ProtMsg::ReconstructedShare(main_msg,rep)=> {
                    log::info!("Received ReconstructedShare from node : {:?}",rep);
                    self.handle_reconstructed_share(main_msg).await;
                }

                _ => todo!("Handle the rest of the message types")
            }
        }
        else {
            log::warn!("MAC Verification failed for message {:?}",wrapper_msg.protmsg);
        }
    }

    // Invoke this function once you terminate the protocol
    // pub async fn terminate(&mut self, data:String){
    //     let cancel_handler = self.sync_send.send(0,
    //         SyncMsg { sender: self.myid, state: SyncState::COMPLETED,value:data.into_bytes()}
    //     ).await;
    //     self.add_cancel_handler(cancel_handler);
    // }

    // Invoke this function once you terminate the protocol
    pub async fn terminate(&mut self, data:Vec<u8>){
        // Note: can use deserialize_hashmap_results function in protocol.rs to deserialize the data back to a HashMap
        let cancel_handler = self.sync_send.send(0,
            SyncMsg { sender: self.myid, state: SyncState::COMPLETED, value:data}
        ).await;
        self.add_cancel_handler(cancel_handler);
    }
}