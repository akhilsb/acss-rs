use types::{Msg, ProtMsg};

use crate::Context;

impl Context {
    pub async fn start_init(self: &mut Context, input_msg: Vec<u8>, instance_id: usize) {
        log::info!(
            "Starting RBC Init for instance id {} with msg {:?}",
            instance_id,
            input_msg
        );
        // Draft a message
        let msg = Msg {
            content: input_msg.clone(),
            origin: self.myid,
        };
        self.handle_init(msg.clone(), instance_id).await;

        // Wrap the message in a type
        // Use different types of messages like INIT, ECHO, .... for the Bracha's RBC implementation
        let protocol_msg = ProtMsg::Sendall(msg, instance_id);
        // Broadcast the message to everyone
        self.broadcast(protocol_msg).await;
    }

    pub async fn handle_init(self: &mut Context, msg: Msg, instance_id: usize) {
        //send echo
        self.start_echo(msg.content.clone(), instance_id).await;

        log::info!(
            "Received Sendall message {:?} from node {}.",
            msg.content,
            msg.origin,
        );
    }
}
