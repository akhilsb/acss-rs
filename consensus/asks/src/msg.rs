use crypto::{LargeField, hash::{Hash, do_hash}, LargeFieldSer, aes_hash::Proof};
use ctrbc::CTRBCMsg;
use lambdaworks_math::traits::ByteConversion;
use serde::{Serialize, Deserialize};
use types::Replica;

pub struct WSSMsg{
    pub shares: Vec<LargeField>,
    pub nonce_shares: Vec<LargeField>,
    pub merkle_proofs: Vec<Proof>,
    pub reconstruct_to_all: bool,
    pub origin: Replica,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WSSMsgSer{
    pub shares: Vec<LargeFieldSer>,
    pub nonce_shares: Vec<LargeFieldSer>,
    pub merkle_proofs: Vec<Proof>,
    pub reconstruct_to_all: bool,
    pub origin: Replica
}

impl WSSMsgSer {
    pub fn from_unser(wss_msg: &WSSMsg) -> WSSMsgSer{
        WSSMsgSer { 
            shares: wss_msg.shares.iter().map(|x| x.to_bytes_be()).collect(), 
            nonce_shares: wss_msg.nonce_shares.iter().map(|x| x.to_bytes_be()).collect(), 
            merkle_proofs: wss_msg.merkle_proofs.clone(),
            reconstruct_to_all: wss_msg.reconstruct_to_all,
            origin: wss_msg.origin
        }
    }

    pub fn to_unser(&self) -> WSSMsg{
        WSSMsg { 
            shares: self.shares.iter().map(|x| LargeField::from_bytes_be(x).unwrap()).collect::<Vec<LargeField>>(), 
            nonce_shares: self.nonce_shares.iter().map(|x| LargeField::from_bytes_be(x).unwrap()).collect::<Vec<LargeField>>(), 
            merkle_proofs: self.merkle_proofs.clone(),
            reconstruct_to_all: self.reconstruct_to_all,
            origin: self.origin 
        }
    }

    pub fn compute_commitments(&self) -> Vec<Hash>{
        let mut comm_vector = Vec::new();
        for (share,nonce) in self.shares.iter().zip(self.nonce_shares.iter()){
            let mut appended_vec = Vec::new();
            appended_vec.extend(share.clone());
            appended_vec.extend(nonce.clone());
            comm_vector.push(do_hash(appended_vec.as_slice()));
        }
        comm_vector
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg{
    // Create your custom types of messages'
    Init(Vec<u8>, usize), // Init
    // ECHO contains only indices and roots. 
    Echo(CTRBCMsg, bool,usize),
    // READY contains only indices and roots.
    Ready(CTRBCMsg, bool,usize),
    // Reconstruct message
    Reconstruct(WSSMsgSer, usize)
}