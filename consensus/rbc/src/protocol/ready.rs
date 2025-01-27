use async_recursion::async_recursion;
use types::{Msg, ProtMsg};

use crate::Context;

impl Context {
    pub async fn start_ready(self: &mut Context, msg_content: Vec<u8>, instance_id: usize) {
        // Draft a message
        let msg = Msg {
            content: msg_content.clone(),
            origin: self.myid,
        };
        // Wrap the message in a type
        // Use different types of messages like INIT, ECHO, .... for the Bracha's RBC implementation
        let protocol_msg = ProtMsg::Ready(msg, instance_id);
        // Broadcast the message to everyone
        self.broadcast(protocol_msg).await;
        self.ready_self(msg_content.clone(), instance_id).await;
    }

    #[async_recursion]
    pub async fn ready_self(&mut self, msg_content: Vec<u8>, instance_id: usize) {
        let msg = Msg {
            content: msg_content,
            origin: self.myid,
        };
        self.handle_ready(msg, instance_id).await;
    }
    pub async fn handle_ready(self: &mut Context, msg: Msg, instance_id: usize) {
        // *self.received_echo_count.entry(msg).or_insert(0) += 1;
        let rbc_context = self.rbc_context.entry(instance_id).or_default();

        if rbc_context.terminated {
            // RBC Already terminated, skip processing this message
            return;
        }

        let senders = rbc_context
            .ready_senders
            .entry(msg.content.clone())
            .or_default();

        // Only count if we haven't seen a ready from this sender for this message
        if senders.insert(msg.origin) {
            *rbc_context
                .received_ready_count
                .entry(msg.content.clone())
                .or_default() += 1;

            log::info!(
                "Received Ready message {:?} from node {}. num faults: {}",
                msg.content,
                msg.origin,
                self.num_faults
            );

            // let count = self.received_ready_count.get(&msg.content).unwrap();
            let mut mode_content: Option<Vec<u8>> = None;
            let mut max_count = 0;

            for (content, &count) in rbc_context.received_ready_count.iter() {
                if count > max_count {
                    max_count = count;
                    mode_content = Some(content.clone());
                }
            }

            // on t + 1 readys
            if max_count == self.num_faults + 1 && !rbc_context.second_ready {
                if let Some(hash) = mode_content {
                    log::info!("On t + 1 readys, sending READY with content {:?}", hash);
                    rbc_context.second_ready = true;
                }
            }

            // Drop the borrow of `rbc_context` before calling methods on `self`
            let _ = rbc_context;
            // on 2t + 1 readys
            if max_count == 2 * self.num_faults + 1 {
                let should_terminate = {
                    let rbc_context = self.rbc_context.entry(instance_id).or_default();
                    if !rbc_context.terminated {
                        log::info!("Outputting {:?}", msg.content.clone());
                        rbc_context.terminated = true;
                        true
                    } else {
                        false
                    }
                }; // rbc_context goes out of scope here

                if should_terminate {
                    self.terminate(msg.content.clone()).await;
                }
            }
        }
    }
}
