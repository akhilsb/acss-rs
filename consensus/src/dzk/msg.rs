use crypto::{hash::Hash, aes_hash::Proof};
use serde::{Serialize, Deserialize};
use types::Replica;

use crate::{LargeFieldSer, DZKProof};


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VACommitment{
    pub column_roots: Vec<Hash>,
    pub blinding_column_roots: Vec<Hash>,
    pub dzk_roots: Vec<Vec<Hash>>,
    pub polys: Vec<Vec<LargeFieldSer>>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VAShare{
    // Share and Nonce
    pub row_poly: (Vec<Vec<LargeFieldSer>>,Vec<LargeFieldSer>, Vec<Proof>),
    pub blinding_row_poly: Vec<(LargeFieldSer, LargeFieldSer, Proof)>,
    // Share and Nonce
    pub column_poly: (Vec<Vec<LargeFieldSer>>,Vec<LargeFieldSer>),
    pub blinding_column_poly: Vec<(LargeFieldSer, LargeFieldSer)>,
    pub dzk_iters: Vec<DZKProof>,
    pub rep: Replica
}