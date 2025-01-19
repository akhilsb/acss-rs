use std::collections::HashMap;

use crypto::{LargeField, hash::Hash, LargeFieldSer};
use ctrbc::RBCState;
use types::Replica;

use consensus::PointBV;

pub struct ACSSVAState{
    pub origin: Replica,

    pub row_shares: Vec<Vec<LargeField>>,
    pub blinding_row_shares: Vec<LargeField>,
    
    pub column_shares: HashMap<Replica,(Vec<LargeField>,LargeField)>,
    pub bcolumn_shares: HashMap<Replica,(LargeField, LargeField)>,

    // Merkle Roots
    pub column_roots: Vec<Hash>,
    pub blinding_column_roots: Vec<Hash>,
    pub dzk_polynomial_roots: Vec<Vec<Hash>>,
    pub dzk_polynomials: Vec<Vec<LargeFieldSer>>,

    pub secret_shares: Option<Vec<LargeField>>,
    pub row_secret_shares: Option<Vec<LargeField>>,

    pub verified_hash: Option<Hash>,

    // Points received during ECHO phase from other nodes
    pub bv_echo_points: HashMap<Replica, PointBV>,
    pub bv_ready_points: HashMap<Replica, PointBV>,

    // Encrypted row polynomial shares
    pub encrypted_shares: Vec<(Replica, Vec<u8>)>,
    
    pub rbc_state: RBCState,
    pub terminated: bool,
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

            bv_echo_points: HashMap::default(),
            bv_ready_points: HashMap::default(),

            encrypted_shares: Vec::new(),

            secret_shares: None,
            row_secret_shares: None,

            verified_hash: None,

            rbc_state: RBCState::new(origin),

            terminated: false,
        }
    }
}