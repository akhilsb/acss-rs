use std::collections::HashMap;

use crypto::{LargeField, hash::Hash};
use ctrbc::RBCState;
use types::Replica;

pub struct ASKSState {
    pub origin: Replica,

    pub share: Option<LargeField>,
    pub nonce_share: Option<LargeField>,

    pub secret_shares: HashMap<Replica, (LargeField, LargeField)>,

    pub secret: Option<LargeField>,
    
    pub verified_hash: Option<Hash>,

    pub echo_sent: bool,
    pub ready_sent: bool,
    pub terminated: bool,

    pub rbc_state: RBCState
}

impl ASKSState{
    pub fn new(origin: Replica) -> ASKSState{
        ASKSState { 
            origin: origin, 
            share: None, 
            nonce_share: None, 
            secret: None, 
            
            secret_shares: HashMap::default(), 

            verified_hash: None, 
            echo_sent: false, 
            ready_sent: false, 
            terminated: false,
            
            rbc_state: RBCState::new(origin)
        }
    }
}