use std::collections::HashMap;

use ha_crypto::{LargeField, hash::Hash, aes_hash::MerkleTree};
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

    pub shares: Option<Vec<LargeField>>,

    pub verified_hash: Option<Hash>,

    pub rows_reconstructed: bool,
    pub cols_reconstructed: bool,

    pub echo_sent: bool,
    pub ready_sent: bool, 

    // Points received during ECHO phase from other nodes
    pub bv_echo_points: HashMap<Replica, PointsBV>,
    pub bv_ready_points: HashMap<Replica, PointsBV>,

    pub col_share_map: Vec<(Vec<Vec<LargeField>>, Vec<LargeField>)>,
    pub col_merkle_trees: Option<Vec<MerkleTree>>,

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

            echo_sent: false,
            ready_sent: false,

            rows_reconstructed: false,
            cols_reconstructed: false,

            bv_echo_points: HashMap::default(),
            bv_ready_points: HashMap::default(),

            col_share_map: Vec::new(),
            col_merkle_trees: None,

            encrypted_shares: Vec::new(),

            shares: None,
            verified_hash: None,

            rbc_state: RBCState::new(origin),

            terminated: false,
        }
    }
}