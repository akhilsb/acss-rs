use types::{Msg, ProtMsg};

use crate::Context;

impl Context {
    pub async fn start_echo(self: &mut Context, msg_content: Vec<u8>, instance_id: usize) {
        // Draft a message
        let msg = Msg {
            content: msg_content.clone(),
            origin: self.myid,
        };
        // Wrap the message in a type
        // Use different types of messages like INIT, ECHO, .... for the Bracha's RBC implementation
        let protocol_msg = ProtMsg::Echo(msg, instance_id);
        // Broadcast the message to everyone
        self.broadcast(protocol_msg).await;
        self.echo_self(msg_content.clone(), instance_id).await;
    }

    pub async fn handle_echo(self: &mut Context, msg: Msg, instance_id: usize) {
        let rbc_context = self.rbc_context.entry(instance_id).or_default();

        if rbc_context.terminated {
            // RBC Already terminated, skip processing this message
            return;
        }

        let senders = rbc_context
            .echo_senders
            .entry(msg.content.clone())
            .or_default();

        // Only count if we haven't seen an echo from this sender for this message
        if senders.insert(msg.origin) {
            *rbc_context
                .received_echo_count
                .entry(msg.content.clone())
                .or_default() += 1;

            log::info!(
                "Received Echo message {:?} from node {}",
                msg.content,
                msg.origin
            );

            // let count = self.received_echo_count.get(&msg.content).unwrap();
            let mut mode_content: Option<Vec<u8>> = None;
            let mut max_count = 0;

            for (content, &count) in rbc_context.received_echo_count.iter() {
                if count > max_count {
                    max_count = count;
                    mode_content = Some(content.clone());
                }
            }

            // Check if we've received 2t + 1 echoes for this message
            if max_count == 2 * self.num_faults + 1 && !rbc_context.first_ready {
                if let Some(hash) = mode_content {
                    log::info!(
                        "On 2t + 1 echos, sending READY with content {:?}. t = {}",
                        hash,
                        self.num_faults
                    );
                    rbc_context.first_ready = true;

                    self.start_ready(msg.content.clone(), instance_id).await;
                }
            }
        }
    }
    pub async fn echo_self(&mut self, msg_content: Vec<u8>, instance_id: usize) {
        let msg = Msg {
            content: msg_content,
            origin: self.myid,
        };
        self.handle_echo(msg, instance_id).await;
    }
}
