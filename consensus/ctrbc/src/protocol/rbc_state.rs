use std::collections::HashMap;

use crypto::{aes_hash::{Proof}, hash::Hash};

pub struct RBCState{
    pub echos: HashMap<Hash, HashMap<usize,Vec<u8>>>,
    pub echo_root: Option<Hash>,

    pub readys: HashMap<Hash, HashMap<usize,Vec<u8>>>,
    
    pub fragment: Option<(Vec<u8>, Proof)>,
    pub message: Option<Vec<u8>>,

    pub terminated: bool
}

impl RBCState{
    
    pub fn new()-> RBCState{
        RBCState { 
            echos: HashMap::default(), 
            echo_root: None, 
            
            readys: HashMap::default(), 
            
            fragment: None, 
            message: None,

            terminated:false
        }
    }
}

impl Default for RBCState {
    fn default() -> Self {
        Self::new()
    }
}