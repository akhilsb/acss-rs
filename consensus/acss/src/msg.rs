use crypto::{hash::Hash, LargeFieldSer};
use ctrbc::CTRBCMsg;
use serde::{Serialize, Deserialize};
use types::Replica;

pub type Polynomial<T> = Vec<T>;

pub type Commitment = Vec<Hash>;
pub type VSSCommitments = (Commitment,Commitment);

pub type Sig = Vec<(usize,Hash)>;
pub type SigOpening = (usize,Hash);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Shares{
    pub poly_shares: Option<Vec<LargeFieldSer>>, // Shares of polynomials
    pub nonce_shares: Option<(LargeFieldSer,LargeFieldSer)>, // Nonce and Blinding nonce shares
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg{
    Init(
        Vec<u8>, // Encrypted shares
        usize, // Number of secrets
        VSSCommitments,
        Polynomial<LargeFieldSer>, // dZK polynomial
        Replica, // Dealer
        usize // ACSS Instance ID (For PRF and share generation)
    ),
    Echo(
        CTRBCMsg,
        usize // ACSS Instance ID 
    ),
    Ready(
        CTRBCMsg,
        usize // ACSS Instance ID
    )
}