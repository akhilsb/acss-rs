use std::collections::{HashMap, HashSet};

use types::Replica;

pub struct IBFTState{
    // ACSS party and the corresponding number of parties that terminated this party's ACSS. 
    pub termination_map: HashMap<Replica, usize>,
    pub consensus_inp_set: HashSet<Replica>,
    pub broadcast_started: bool,

    pub consensus_out_set: Vec<Replica>
}

impl IBFTState{
    pub fn new() -> Self {
        Self {
            termination_map: HashMap::new(),
            consensus_inp_set: HashSet::new(),

            broadcast_started: false,
            consensus_out_set: Vec::new()
        }
    }

    pub fn add_termination(&mut self, party: Replica) {
        let count = self.termination_map.entry(party).or_insert(0);
        *count += 1;
    }

    pub fn add_consensus_inp(&mut self, party: Replica) {
        self.consensus_inp_set.insert(party);
    }

    pub fn add_consensus_out(&mut self, parties: Vec<Replica>) {
        self.consensus_out_set.extend(parties);
    }
}