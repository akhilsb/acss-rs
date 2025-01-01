use crypto::{aes_hash::HashState};

use crate::LargeFieldSSS;

pub struct LinDZKContext{
    pub large_field_uv_sss: LargeFieldSSS,
    pub hash_context: HashState,
    pub evaluation_points: Vec<usize>,
    pub recon_threshold: usize,
}

impl LinDZKContext{
    // Linear sized Distributed ZK proof 

    // pub fn gen_dzk_proof(
    //     &self,
    //     root: Hash,

    // )
}