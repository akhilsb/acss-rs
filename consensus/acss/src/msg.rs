use crypto::{hash::Hash, LargeFieldSer, aes_hash::Proof};
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

// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub enum ProtMsg{
//     Init(
//         Vec<u8>, // Encrypted shares
//         usize, // Number of secrets
//         VSSCommitments,
//         Polynomial<LargeFieldSer>, // dZK polynomial
//         Replica, // Dealer
//         usize // ACSS Instance ID (For PRF and share generation)
//     ),
//     Echo(
//         CTRBCMsg,
//         usize // ACSS Instance ID 
//     ),
//     Ready(
//         CTRBCMsg,
//         usize // ACSS Instance ID
//     )
// }

// Verifiable Abort
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VACommitment{
    pub roots: Vec<Vec<Hash>>,
    pub polys: Vec<Vec<LargeFieldSer>>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DZKProof{
    pub g_0_x: Vec<LargeFieldSer>,
    pub g_1_x: Vec<LargeFieldSer>,
    pub proof: Vec<Proof>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VAShare{
    // Share and Nonce
    pub row_poly: Vec<(LargeFieldSer,LargeFieldSer, Proof)>,
    // Share and Nonce
    pub column_poly: Vec<(LargeFieldSer,LargeFieldSer)>,
    pub dzk_iters: Vec<DZKProof>,
    pub rep: Replica
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg{
    Init(
        Vec<u8>, // Encrypted shares
        VACommitment, // dZK polynomial
        Replica, // Dealer
        usize // ACSS Instance ID (For PRF and share generation)
    ),
    Echo(
        CTRBCMsg,
        Vec<u8>, // Encrypted shares on row and column
        usize // ACSS Instance ID 
    ),
    Ready(
        CTRBCMsg,
        Vec<u8>, // Encrypted shares on row and column
        usize // ACSS Instance ID
    )
}