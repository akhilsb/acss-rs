use crypto::LargeFieldSer;
use serde::{Serialize, Deserialize};
use types::Replica;


#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg{
    // SecEq
    // instance_id, secret_origin, c1_c2, aggregated_challenge_point
    SecEq(usize, Replica, u8, LargeFieldSer),
    // PubRec
    PubRecEcho1(Vec<LargeFieldSer>),
    PubRecEcho2(Vec<LargeFieldSer>)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CTRBCInterface{
    pub id: usize,
    pub msg: Vec<u8>
}