use std::sync::Arc;

use crate::{context::Context, msg::ProtMsg};
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
                ProtMsg::GatherEcho(instance, witnesses) => {
                    // RBC initialized
                    log::debug!("Received Gather Echo for instance id {} from node : {}", instance, wrapper_msg.sender);
                    self.process_gather_echo(witnesses, wrapper_msg.sender, instance).await;
                },
                ProtMsg::GatherEcho2(instance, witnesses) => {
                    // RBC initialized
                    log::debug!("Received Gather Echo2 for instance id {} from node : {}", instance, wrapper_msg.sender);
                    self.process_gather_echo2(witnesses, wrapper_msg.sender, instance).await;
                },
                ProtMsg::SecEq(instance, origin, c1_c2, eval_ser) => {
                    log::debug!("Received Gather Echo2 for instance id {} from node : {}", instance, wrapper_msg.sender);
                    self.process_sec_equivalence_msg(instance, origin, wrapper_msg.sender, c1_c2, eval_ser).await;
                }
                ProtMsg::PubRecEcho1(shares_ser) => {
                    log::debug!("Received PubRecEcho1 from node : {}", wrapper_msg.sender);
                    self.process_pub_rec_echo1_msg(shares_ser, wrapper_msg.sender).await;
                }
                ProtMsg::PubRecEcho2(shares_ser) => {
                    log::debug!("Received PubRecEcho2 from node : {}", wrapper_msg.sender);
                    self.process_pub_rec_echo2_msg(shares_ser, wrapper_msg.sender).await;
                }
                // ProtMsg::Deliver(avid_shard, origin, instance_id) => {
                    
                //     log::debug!("Received Deliver for instance id {} from node : {}", instance_id, origin);
                //     self.handle_deliver(avid_shard, origin, wrapper_msg.sender, instance_id).await;
                // }
            }
        } else {
            log::warn!(
                "MAC Verification failed for message {:?}",
                wrapper_msg.protmsg
            );
        }
    }

    // Invoke this function once you terminate the protocol
    // pub async fn terminate(&mut self, avid_opt:Option<AVIDMsg>, instance_id: usize) {
    //     //let fragment = avid_context.fragments.clone();
    //     //let avid_msg = fragment.unwrap();
    //     if avid_opt.is_some(){
    //         let avid_msg= avid_opt.unwrap();
    //         for avid_shard in avid_msg.shards{    
    //             let recipient = avid_shard.recipient.clone();
    //             if recipient == self.myid{
    //                 self.handle_deliver(avid_shard, avid_msg.origin, self.myid, instance_id).await;
    //             }
    //             else{
    
    //                 let sec_key = self.sec_key_map.get(&recipient).unwrap().clone();
    //                 let protocol_msg = ProtMsg::Deliver(avid_shard, avid_msg.origin, instance_id);
    //                 let wrapper_msg = WrapperMsg::new(protocol_msg.clone(),self.myid,&sec_key);
    //                 let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(recipient, wrapper_msg).await;
    //                 self.add_cancel_handler(cancel_handler);
                
    //             }
    //         }
    //     }
    // }
}
