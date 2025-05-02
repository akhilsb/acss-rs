use crypto::{LargeField, hash::{Hash, do_hash}, LargeFieldSer};
use ctrbc::CTRBCMsg;
use lambdaworks_math::traits::ByteConversion;
use serde::{Serialize, Deserialize};
use types::Replica;


pub struct WSSMsg{
    pub share: LargeField,
    pub nonce_share: LargeField,
    pub origin: Replica,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WSSMsgSer{
    pub share: LargeFieldSer,
    pub nonce_share: LargeFieldSer,
    pub origin: Replica
}

impl WSSMsgSer {
    pub fn from_unser(wss_msg: &WSSMsg) -> WSSMsgSer{
        WSSMsgSer { 
            share: wss_msg.share.to_bytes_be(), 
            nonce_share: wss_msg.nonce_share.to_bytes_be(), 
            origin: wss_msg.origin
        }
    }

    pub fn to_unser(&self) -> WSSMsg{
        WSSMsg { 
            share: LargeField::from_bytes_be(&self.share).unwrap(), 
            nonce_share: LargeField::from_bytes_be(&self.nonce_share).unwrap(), 
            origin: self.origin 
        }
    }

    pub fn compute_commitment(&self) -> Hash{
        let mut appended_msg = Vec::new();
        appended_msg.extend(self.share.clone());
        appended_msg.extend(self.nonce_share.clone());
        do_hash(appended_msg.as_slice())
    }
}

pub type Commitment = Vec<Hash>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg{
    // Create your custom types of messages'
    Init(Vec<u8>, Commitment, usize), // Init
    // ECHO contains only indices and roots. 
    Echo(CTRBCMsg,usize),
    // READY contains only indices and roots.
    Ready(CTRBCMsg,usize),
    // Reconstruct message
    Reconstruct(WSSMsgSer, usize)
}