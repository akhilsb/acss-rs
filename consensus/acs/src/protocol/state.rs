use std::collections::{HashSet, HashMap};

use crypto::{LargeField};
use types::Replica;

pub struct ACSState{
    pub broadcast_messages: HashMap<Replica, Vec<Replica>>,
    
    pub re_broadcast_messages: HashMap<Replica, Vec<Replica>>,
    pub broadcasts_left_to_be_accepted: HashMap<Replica, HashSet<Replica>>,
    pub accepted_witnesses: HashSet<Replica>,

    pub vaba_started: bool,
    pub vaba_states: HashMap<usize, VABAState>,
    pub ra_value: Option<Replica>,

    pub acs_output: HashSet<Replica>,
}

impl ACSState{
    pub fn new()-> ACSState{
        ACSState { 
            broadcast_messages: HashMap::default(),

            re_broadcast_messages: HashMap::default(),
            broadcasts_left_to_be_accepted: HashMap::default(),
            accepted_witnesses: HashSet::default(),

            vaba_started: false,
            vaba_states: HashMap::default(), 
            ra_value: None,

            acs_output: HashSet::default(),
        }
    }
}

pub struct VABAState{

    pub pre: Option<Replica>,
    pub justify: Option<Vec<(Replica, Replica)>>,
    
    pub term_asks_instances: HashSet<Replica>,
    pub pre_broadcast: bool,
    
    // Pre, ASKS instances terminated, Justify values
    pub pre_justify_votes: HashMap<Replica, (Replica, Vec<Replica>, Vec<(Replica,Replica)>)>,
    // If Pre has been validated, remaining ASKS instances left to be terminated, Justify values remaining
    pub unvalidated_pre_justify_votes: HashMap<Replica, (Option<Replica>, HashSet<Replica>, HashMap<Replica, Replica>)>,
    pub validated_pre_justify_votes: HashSet<Replica>,

    pub reliable_agreement: HashSet<Replica>,

    pub gather_started: bool, 
    pub gather_state: GatherState,
    
    pub asks_reconstruction_started: bool,
    pub asks_reconstruction_list: HashMap<Replica, HashSet<Replica>>,
    pub asks_reconstructed_values: HashMap<Replica, LargeField>,
    pub ranks_parties: HashMap<Replica, LargeField>, 
    
    pub reconstructed_values: HashMap<Replica, LargeField>,
    pub elected_leader: Option<Replica>,

    pub vote_broadcasted: bool,
    pub votes: HashMap<Replica, HashSet<Replica>>,
    pub termination_gadget: bool,
}

impl VABAState{
    pub fn new(pre: Replica, justify: Vec<(Replica, Replica)>)-> VABAState{
        VABAState {
            pre: Some(pre),
            justify: Some(justify),

            term_asks_instances: HashSet::default(), 
            pre_broadcast: false,

            pre_justify_votes: HashMap::default(),
            unvalidated_pre_justify_votes: HashMap::default(), 
            validated_pre_justify_votes: HashSet::default(), 

            reliable_agreement: HashSet::default(),

            gather_started: false,
            gather_state: GatherState::new(), 
            
            asks_reconstruction_started: false,
            asks_reconstruction_list: HashMap::default(),
            asks_reconstructed_values: HashMap::default(),
            ranks_parties: HashMap::default(),
            
            votes: HashMap::default(),
            vote_broadcasted: false,
            termination_gadget: false,

            reconstructed_values: HashMap::default(),
            elected_leader: None
        }
    }

    pub fn new_without_pre_justify()-> VABAState{
        VABAState {
            pre: None,
            justify: None,

            term_asks_instances: HashSet::default(), 
            pre_broadcast: false,

            pre_justify_votes: HashMap::default(),
            unvalidated_pre_justify_votes: HashMap::default(),
            validated_pre_justify_votes: HashSet::default(),

            reliable_agreement: HashSet::default(),

            gather_started: false,
            gather_state: GatherState::new(), 

            asks_reconstruction_started: false,
            asks_reconstruction_list: HashMap::default(),
            asks_reconstructed_values: HashMap::default(),
            ranks_parties: HashMap::default(),

            votes: HashMap::default(),
            vote_broadcasted: false,
            termination_gadget: false,

            reconstructed_values: HashMap::default(),
            elected_leader: None
        }
    }
}

pub struct GatherState{
    pub received_gather_echos: HashMap<Replica, Vec<Replica>>,
    pub unvalidated_gather_echos: HashMap<Replica, HashSet<Replica>>,
    pub validated_gather_echos: HashSet<Replica>,

    pub gather2_started: bool,
    pub received_gather_echo2s: HashMap<Replica, Vec<Replica>>,
    pub unvalidated_gather_echo2s: HashMap<Replica, HashSet<Replica>>,
    pub validated_gather_echo2s: HashSet<Replica>,
}

impl GatherState{
    pub fn new()-> GatherState{
        GatherState {            
            received_gather_echos: HashMap::default(), 
            unvalidated_gather_echos: HashMap::default(), 
            validated_gather_echos: HashSet::default(),

            gather2_started: false, 
            received_gather_echo2s: HashMap::default(),
            unvalidated_gather_echo2s: HashMap::default(),
            validated_gather_echo2s: HashSet::default(),
        }
    }
}