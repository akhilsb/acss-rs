use std::collections::HashMap;

use crypto::{LargeField, hash::Hash, aes_hash::Proof};
use ctrbc::RBCState;
use types::Replica;

pub struct ASKSState {
    pub reconstruct_to_all: bool,
    pub origin: Replica,

    pub shares: Option<Vec<LargeField>>,
    pub nonce_shares: Option<Vec<LargeField>>,
    pub merkle_proofs: Option<Vec<Proof>>,

    pub roots: Option<Vec<Hash>>,

    pub secret_shares: Vec<HashMap<Replica, (LargeField, LargeField)>>,

    pub secret: Option<Vec<LargeField>>,
    
    pub verified_hash: Option<Hash>,

    pub echo_sent: bool,
    pub ready_sent: bool,
    pub terminated: bool,

    pub rbc_state: RBCState
}

impl ASKSState{
    pub fn new(origin: Replica, reconstruct_to_all: bool) -> ASKSState{
        ASKSState {
            reconstruct_to_all: reconstruct_to_all,
            origin: origin, 
            shares: None, 
            nonce_shares: None, 

            merkle_proofs: None,
            roots: None,

            secret: None, 
            
            secret_shares: Vec::new(), 

            verified_hash: None, 
            echo_sent: false, 
            ready_sent: false, 
            terminated: false,
            
            rbc_state: RBCState::new(origin)
        }
    }
}