use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg {
    // Create your custom types of messages'
    Echo(usize, usize),
    Ready(usize, usize),
    // Example type is a ping message, which takes a Message and the sender replica
    // Ping(Msg, Replica),
}