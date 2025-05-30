use consensus::{LargeFieldSer, DZKProof};
use crypto::aes_hash::Proof;
use serde::{Serialize, Deserialize};
use types::Replica;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcssSKEShares{
    // Share and Nonce
    pub evaluations: (Vec<LargeFieldSer>,Vec<LargeFieldSer>, Vec<Proof>),
    pub blinding_evaluations: (Vec<LargeFieldSer>, Vec<LargeFieldSer>, Vec<Proof>),
    pub dzk_iters: Vec<DZKProof>,
    pub rep: Replica
}