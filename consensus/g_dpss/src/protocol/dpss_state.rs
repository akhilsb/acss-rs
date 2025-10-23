use std::collections::{HashMap, HashSet};

use crypto::{LargeField, hash::Hash};
use types::Replica;

pub struct DPSSState{
    pub acss_map: HashMap<Replica, 
        HashMap<usize, 
        (
            Option<(Vec<LargeField>, Hash)>,
            Option<(Vec<LargeField>, Hash)>)>
        >,
    
    pub sec_equivalence: HashMap<Replica, 
        HashMap<usize, (
                        HashMap<usize, LargeField>, 
                        HashMap<usize, LargeField>
                        )>
                >,
    

    pub pub_rec_echo1s: HashMap<Replica, Vec<LargeField>>,
    pub pub_rec_echo2s: HashMap<Replica, Vec<LargeField>>,

    pub acs_output: HashSet<Replica>,
}

impl DPSSState{
    pub fn new()-> DPSSState{
        DPSSState {
            acss_map: HashMap::default(),
            sec_equivalence: HashMap::default(),
            pub_rec_echo1s: HashMap::default(),
            pub_rec_echo2s: HashMap::default(),
            acs_output: HashSet::default(),
        }
    }
}