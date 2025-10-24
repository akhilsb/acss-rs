use std::collections::{HashMap, HashSet, VecDeque};

use crypto::hash::Hash;
use lambdaworks_math::polynomial::Polynomial;
use consensus::{LargeField};
use types::Replica;

use crate::{msg::AcssSKEShares, CommDZKMsg};

#[derive(Clone, Debug)]
pub struct ACSSABState{
    pub enc_shares: HashMap<Replica, HashMap<usize,Vec<u8>>>,
    
    // Shares, Nonce, Blinding nonce share in each tuple
    pub batch_wise_shares: HashMap<Replica, HashMap<usize, AcssSKEShares>>,
    pub shares: HashMap<Replica, Vec<LargeField>>,

    // Commitments to shares, commitments to blinding polynomial, and DZK polynomial
    pub commitments: HashMap<Replica, CommDZKMsg>,

    // AVID Throttling for bandwidth management
    pub avid_instances: VecDeque<Vec<(Replica,Option<Vec<u8>>)>>,
    
    // Reliable Agreement
    pub ra_outputs: HashSet<Replica>,
    
    // Verification status for each party
    pub verification_status: HashMap<Replica, bool>,
    pub acss_status: HashSet<Replica>,

    // L1 Shares and L2 Shares
    pub public_reconstruction_quad_shares: HashMap<Replica, HashMap<Replica, Vec<LargeField>>>,
    pub public_reconstruction_quad_status: HashSet<Replica>,
    pub public_reconstruction_l1_shares: HashMap<Replica, HashMap<Replica, Vec<LargeField>>>,
    pub public_reconstruction_l1_status: HashSet<Replica>,
    pub public_reconstruction_l2_shares: HashMap<Replica, HashMap<Replica, Vec<LargeField>>>,
    pub public_reconstruction_l2_status: HashSet<Replica>,

    pub dzk_poly: HashMap<Replica,Polynomial<LargeField>>,
    pub commitment_root_fe: HashMap<Replica, Hash>,
}

impl ACSSABState{
    pub fn new() -> Self{
        Self{
            enc_shares: HashMap::default(),
            batch_wise_shares: HashMap::default(),
            shares: HashMap::default(),

            avid_instances: VecDeque::new(),
            commitments: HashMap::default(),
            ra_outputs: HashSet::default(),
            verification_status: HashMap::default(),
            acss_status: HashSet::default(),

            public_reconstruction_quad_shares: HashMap::default(),
            public_reconstruction_quad_status: HashSet::default(),
            public_reconstruction_l1_shares: HashMap::default(),
            public_reconstruction_l1_status: HashSet::default(),
            public_reconstruction_l2_shares: HashMap::default(),
            public_reconstruction_l2_status: HashSet::default(),

            dzk_poly: HashMap::default(),
            commitment_root_fe: HashMap::default(),
        }
    }
}

pub struct SymmetricKeyState{
    pub keys_from_me: HashMap<Replica, Vec<u8>>,
    pub keys_to_me: HashMap<Replica, Vec<u8>>,
    pub term_asks_sharing: HashSet<Replica>,
    pub term_asks_recon: HashSet<Replica>,
}

impl SymmetricKeyState {
    pub fn new() -> Self {
        Self {
            keys_from_me: HashMap::default(),
            keys_to_me: HashMap::default(),
            term_asks_sharing: HashSet::default(),
            term_asks_recon: HashSet::default(),
        }
    }
}