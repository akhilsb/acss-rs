use std::collections::{HashSet, HashMap};

use crypto::{LargeField};
use types::Replica;

pub struct ACSState{
    pub broadcast_messages: HashMap<Replica, Vec<Replica>>,
    
    pub re_broadcast_messages: HashMap<Replica, Vec<Replica>>,
    pub broadcasts_left_to_be_accepted: HashMap<Replica, HashSet<Replica>>,
    pub accepted_witnesses: HashSet<Replica>,

    pub vaba_states: HashMap<usize, VABAState>,
    pub ra_value: Option<Replica>,
}

impl ACSState{
    pub fn new()-> ACSState{
        ACSState { 
            broadcast_messages: HashMap::default(),

            re_broadcast_messages: HashMap::default(),
            broadcasts_left_to_be_accepted: HashMap::default(),
            accepted_witnesses: HashSet::default(),

            vaba_states: HashMap::default(), 
            ra_value: None
        }
    }
}

pub struct VABAState{

    pub pre: Option<Replica>,
    pub justify: Option<Vec<(Replica, Replica)>>,
    
    pub term_asks_instances: Vec<Replica>,
    pub pre_justify_votes: HashMap<Replica, (Replica, Vec<(Replica,Replica)>)>,
    pub validated_pre_justify_votes: HashSet<Replica>,

    pub gather_state: GatherState,
    pub votes: HashMap<Replica, Vec<Replica>>,
    
    pub reconstructed_values: HashMap<Replica, LargeField>,
    pub elected_leader: Option<Replica>,
}

impl VABAState{
    pub fn new(pre: Replica, justify: Vec<(Replica, Replica)>)-> VABAState{
        VABAState {
            pre: Some(pre),
            justify: Some(justify),

            term_asks_instances: Vec::new(), 
            pre_justify_votes: HashMap::default(), 
            validated_pre_justify_votes: HashSet::default(), 

            gather_state: GatherState::new(), 
            votes: HashMap::default(),

            reconstructed_values: HashMap::default(),
            elected_leader: None
        }
    }

    pub fn new_without_pre_justify()-> VABAState{
        VABAState {
            pre: None,
            justify: None,

            term_asks_instances: Vec::new(), 
            pre_justify_votes: HashMap::default(), 
            validated_pre_justify_votes: HashSet::default(),

            gather_state: GatherState::new(), 
            votes: HashMap::default(),

            reconstructed_values: HashMap::default(),
            elected_leader: None
        }
    }
}

pub struct GatherState{
    
    // Each replica and its corresponding ASKS instances
    pub terminated_rbcs: HashMap<Replica, Vec<Replica>>,
    pub validated_rbcs: HashSet<Replica>,

    pub reliable_agreement: HashSet<Replica>,

    pub received_gather_echos: HashMap<Replica, Vec<Replica>>,
    pub unvalidated_gather_echos: HashMap<Replica, HashSet<Replica>>,
    pub validated_gather_echos: HashSet<Replica>,

    pub received_gather_echo2s: HashMap<Replica, Vec<Replica>>,
    pub unvalidated_gather_echo2s: HashMap<Replica, HashSet<Replica>>,
    pub validated_gather_echo2s: HashSet<Replica>,
}

impl GatherState{
    pub fn new()-> GatherState{
        GatherState { 
            terminated_rbcs: HashMap::default(),
            validated_rbcs: HashSet::default(),

            reliable_agreement: HashSet::default(),
            
            received_gather_echos: HashMap::default(), 
            unvalidated_gather_echos: HashMap::default(), 
            validated_gather_echos: HashSet::default(),

            received_gather_echo2s: HashMap::default(),
            unvalidated_gather_echo2s: HashMap::default(),
            validated_gather_echo2s: HashSet::default(),
        }
    }
}