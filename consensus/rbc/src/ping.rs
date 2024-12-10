use async_recursion::async_recursion;
use types::{Msg, ProtMsg};

use super::Context;

impl Context {
    // A function's input parameter needs to be borrowed as mutable only when
    // we intend to modify the variable in the function. Otherwise, it need not be borrowed as mutable.
    // In this example, the mut can (and must) be removed because we are not modifying the Context inside
    // the function.

    pub async fn echo_self(&mut self, msg_content: Vec<u8>) {
        let msg = Msg {
            content: msg_content,
            origin: self.myid,
        };
        self.handle_echo(msg).await;
    }

    #[async_recursion]
    pub async fn ready_self(&mut self, msg_content: Vec<u8>) {
        let msg = Msg {
            content: msg_content,
            origin: self.myid,
        };
        self.handle_ready(msg).await;
    }

    pub async fn start_ping(self: &mut Context) {
        // Draft a message
        let msg = Msg {
            content: self.inp_message.clone(),
            origin: self.myid,
        };
        // Wrap the message in a type
        // Use different types of messages like INIT, ECHO, .... for the Bracha's RBC implementation
        let protocol_msg = ProtMsg::Sendall(msg, self.myid);
        // Broadcast the message to everyone
        self.broadcast(protocol_msg).await;
    }

    pub async fn start_echo(self: &mut Context, msg_content: Vec<u8>) {
        // Draft a message
        let msg = Msg {
            content: msg_content.clone(),
            origin: self.myid,
        };
        // Wrap the message in a type
        // Use different types of messages like INIT, ECHO, .... for the Bracha's RBC implementation
        let protocol_msg = ProtMsg::Echo(msg, self.myid);
        // Broadcast the message to everyone
        self.broadcast(protocol_msg).await;
        self.echo_self(msg_content.clone()).await;
    }

    pub async fn start_ready(self: &mut Context, msg_content: Vec<u8>) {
        // Draft a message
        let msg = Msg {
            content: msg_content.clone(),
            origin: self.myid,
        };
        // Wrap the message in a type
        // Use different types of messages like INIT, ECHO, .... for the Bracha's RBC implementation
        let protocol_msg = ProtMsg::Ready(msg, self.myid);
        // Broadcast the message to everyone
        self.broadcast(protocol_msg).await;
        self.ready_self(msg_content.clone()).await;
    }

    pub async fn handle_ping(self: &mut Context, msg: Msg) {
        log::info!(
            "Received ping message {:?} from node {}",
            msg.content,
            msg.origin
        );
        // Invoke this function after terminating the protocol.
        //self.terminate("1".to_string()).await;
    }

    pub async fn handle_sendall(self: &mut Context, msg: Msg) {
        //send echo
        self.start_echo(msg.content.clone()).await;

        log::info!(
            "Received Sendall message {:?} from node {}.",
            msg.content,
            msg.origin,
        );
        // Invoke this function after terminating the protocol.
        //self.terminate("1".to_string()).await;
    }

    pub async fn handle_echo(self: &mut Context, msg: Msg) {
        let senders = self.echo_senders.entry(msg.content.clone()).or_default();

        // Only count if we haven't seen an echo from this sender for this message
        if senders.insert(msg.origin) {
            *self
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

            for (content, &count) in self.received_echo_count.iter() {
                if count > max_count {
                    max_count = count;
                    mode_content = Some(content.clone());
                }
            }

            // Check if we've received 2t + 1 echoes for this message
            if max_count == 2 * self.num_faults + 1 {
                if let Some(hash) = mode_content {
                    log::info!(
                        "On 2t + 1 echos, sending READY with content {:?}. t = {}",
                        hash,
                        self.num_faults
                    );
                    self.start_ready(msg.content.clone()).await;
                }
            }
        }

        // Invoke this function after terminating the protocol.
        //self.terminate("1".to_string()).await;
    }

    pub async fn handle_ready(self: &mut Context, msg: Msg) {
        // *self.received_echo_count.entry(msg).or_insert(0) += 1;
        let senders = self.ready_senders.entry(msg.content.clone()).or_default();

        // Only count if we haven't seen a ready from this sender for this message
        if senders.insert(msg.origin) {
            *self
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

            for (content, &count) in self.received_ready_count.iter() {
                if count > max_count {
                    max_count = count;
                    mode_content = Some(content.clone());
                }
            }

            // on t + 1 readys
            if max_count == self.num_faults + 1 {
                if let Some(hash) = mode_content {
                    log::info!(
                        "On t + 1 readys, sending READY with content {:?}",
                        hash,
                    );
                    self.start_ready(msg.content.clone()).await;
                }
            }

            // on 2t + 1 readys
            if max_count == 2 * self.num_faults + 1 {
                log::info!("Outputting {:?}", msg.content);
                self.terminate("1".to_string()).await;
            }
        }
        // Invoke this function after terminating the protocol.
        //self.terminate("1".to_string()).await;
    }
}
