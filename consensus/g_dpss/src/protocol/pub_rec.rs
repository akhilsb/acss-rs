use std::collections::{HashSet};

use types::Replica;
pub struct BAState{
    pub ba_started: HashSet<Replica>,
    pub mvba_started: HashSet<Replica>,

    pub secrets_reconstructed: bool,
    pub shares_generated: bool,
    pub quad_pub_rec_started: bool,
    
    pub ba_term_status: HashSet<Replica>,
    pub mvba_term_status: HashSet<Replica>,
    pub pub_rec_term_parties: HashSet<Replica>,
    pub pub_rec_status: HashSet<Replica>,

    pub acs_output_sorted: Vec<Replica>,
}

impl BAState{
    pub fn new() -> BAState {
        let vec_reps = vec![0];
        BAState {
            ba_started: HashSet::default(),
            mvba_started: HashSet::default(),

            secrets_reconstructed: false,
            shares_generated: false,
            quad_pub_rec_started: false,
            
            ba_term_status: HashSet::default(),
            mvba_term_status: HashSet::default(),
            pub_rec_term_parties: HashSet::default(),
            pub_rec_status: HashSet::from_iter(vec_reps.into_iter()),

            acs_output_sorted: Vec::new(),
        }
    }
}