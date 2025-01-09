use serde::{Serialize, Deserialize};
use types::Replica;


#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg{
    // Gather Echo
    GatherEcho(usize, Vec<Replica>),
    // Gather Echo2
    GatherEcho2(usize, Vec<Replica>)
}