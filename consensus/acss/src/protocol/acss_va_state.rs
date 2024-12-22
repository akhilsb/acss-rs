use std::collections::HashMap;

use crypto::{LargeField, hash::Hash, LargeFieldSer};
use ctrbc::RBCState;
use types::Replica;

pub struct ACSSVAState{
    pub origin: Replica,

    pub row_shares: Vec<LargeField>,
    pub blinding_row_shares: Vec<LargeField>,
    
    pub column_shares: HashMap<Replica,(LargeField,LargeField)>,
    pub bcolumn_shares: HashMap<Replica,(LargeField, LargeField)>,

    // Merkle Roots
    pub column_roots: Vec<Hash>,
    pub blinding_column_roots: Vec<Hash>,
    pub dzk_polynomial_roots: Vec<Vec<Hash>>,
    pub dzk_polynomials: Vec<Vec<LargeFieldSer>>,
    
    pub rbc_state: RBCState
}

impl ACSSVAState{
    pub fn new(origin: Replica)-> ACSSVAState{
        ACSSVAState {
            origin: origin, 
            
            row_shares: Vec::new(), 
            blinding_row_shares: Vec::new(), 
            
            column_shares: HashMap::default(),
            bcolumn_shares: HashMap::default(),

            column_roots: Vec::new(),
            blinding_column_roots: Vec::new(),
            dzk_polynomial_roots: Vec::new(),
            dzk_polynomials: Vec::new(),

            rbc_state: RBCState::new(origin)
        }
    }
}