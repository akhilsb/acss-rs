// Verifiable Abort

use crypto::{LargeFieldSer, aes_hash::Proof};
use serde::{Deserialize, Serialize};

pub type PointBV = ((LargeFieldSer, LargeFieldSer, Proof), (LargeFieldSer,LargeFieldSer, Proof), DZKProof);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DZKProof{
    pub g_0_x: Vec<LargeFieldSer>,
    pub g_1_x: Vec<LargeFieldSer>,
    pub proof: Vec<Proof>
}