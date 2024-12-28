use std::collections::HashMap;

use crypto::{LargeField, hash::Hash, LargeFieldSer};
use ctrbc::RBCState;
use types::Replica;

use crate::msg::PointsBV;

pub struct BatchACSSState{
    pub origin: Replica,

    pub row_coefficients: Vec<Vec<Vec<LargeField>>>,
    pub nonce_coefficients: Vec<Vec<LargeField>>,
    
    pub blinding_row_shares: Vec<LargeField>,
    pub blinding_nonce_shares: Vec<LargeField>,

    pub column_shares: HashMap<Replica,Vec<Vec<LargeField>>>,

    // Merkle Roots
    pub share_roots: Vec<Vec<Hash>>,
    pub blinding_commitments: Vec<Vec<Hash>>,
    
    // DZK polynomials
    pub dzk_polynomials: Vec<Vec<LargeField>>,

    pub secret: Option<Vec<LargeField>>,

    pub verified_hash: Option<Hash>,

    pub rows_reconstructed: bool,
    pub cols_reconstructed: bool,

    // Points received during ECHO phase from other nodes
    pub bv_echo_points: HashMap<Replica, PointsBV>,
    pub bv_ready_points: HashMap<Replica, PointsBV>,

    // Encrypted row polynomial shares
    pub encrypted_shares: Vec<(Replica, Vec<u8>)>,
    
    pub rbc_state: RBCState,
    pub terminated: bool,
}

impl BatchACSSState{
    pub fn new(origin: Replica)-> BatchACSSState{
        BatchACSSState {
            origin: origin, 
            
            row_coefficients: Vec::new(), 
            nonce_coefficients: Vec::new(),

            blinding_row_shares: Vec::new(), 
            blinding_nonce_shares: Vec::new(),

            column_shares: HashMap::default(),

            share_roots: Vec::new(),
            blinding_commitments: Vec::new(),

            dzk_polynomials: Vec::new(),

            rows_reconstructed: false,
            cols_reconstructed: false,

            bv_echo_points: HashMap::default(),
            bv_ready_points: HashMap::default(),

            encrypted_shares: Vec::new(),

            secret: None,
            verified_hash: None,

            rbc_state: RBCState::new(origin),

            terminated: false,
        }
    }
}