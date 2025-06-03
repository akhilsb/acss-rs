use std::collections::{HashMap, HashSet};

use consensus::LargeField;
use types::Replica;

#[derive(Debug,Clone)]
pub struct MVBAExecState{
    pub instance_id: usize,
    pub inp_value: Option<usize>,

    pub mvbas: HashMap<usize, MVBARoundState>,
    pub terminated_mvbas: HashSet<usize>,

    pub output: Option<Vec<usize>>,
}

impl MVBAExecState {
    pub fn new(instance_id: usize) -> MVBAExecState {
        MVBAExecState {
            instance_id,
            inp_value: None, 
            mvbas: HashMap::new(),
            terminated_mvbas: HashSet::new(),

            output: None,
        }
    }

    pub fn add_mvba_round(&mut self, round_state: MVBARoundState) {
        self.mvbas.insert(round_state.round, round_state);
    }

    pub fn get_mvba_round(&self, round: usize) -> Option<&MVBARoundState> {
        self.mvbas.get(&round)
    }
}

#[derive(Debug,Clone)]
pub struct MVBARoundState{
    pub instance_id: usize,
    pub round: usize,
    pub l1_rbcs: HashMap<Replica, Replica>,

    pub l2_rbcs: HashMap<Replica, HashSet<Replica>>,
    pub l2_rbc_vecs: HashMap<Replica, Vec<Replica>>,
    pub l2_approved_rbcs: HashSet<Replica>,
    
    pub l3_witnesses: HashMap<Replica, HashSet<Replica>>,
    pub l3_approved_witnesses: HashSet<Replica>,
    pub l3_witness_sent: bool,
    
    pub coin_broadcasted: bool,
    pub coin_shares: HashMap<Replica, LargeField>,
    pub coin_value: Option<LargeField>,
    pub leader_id: Option<Replica>,

    pub bba_output: Option<usize>,

    pub num_faults: usize,
    pub num_nodes: usize,
}

impl MVBARoundState{
    pub fn new(instance_id: usize, round: usize, num_faults: usize, num_nodes: usize)-> MVBARoundState{
        MVBARoundState {
            instance_id,
            round,
            l1_rbcs: HashMap::new(),
            
            l2_rbcs: HashMap::new(),
            l2_rbc_vecs: HashMap::new(),
            l2_approved_rbcs: HashSet::default(),
            
            l3_witnesses: HashMap::new(),
            l3_approved_witnesses: HashSet::default(),
            l3_witness_sent: false,

            coin_broadcasted: false,
            coin_shares: HashMap::new(),
            coin_value: None,
            leader_id: None,

            bba_output: None,

            num_faults: num_faults,
            num_nodes: num_nodes
        }
    }

    pub fn add_l1_rbc(&mut self, broadcaster: Replica, l1_rbc: Replica)-> bool{
        self.l1_rbcs.insert(broadcaster, l1_rbc);
        // Init L2 RBC
        self.l1_rbcs.len() == self.num_nodes-self.num_faults
    }

    pub fn add_partial_coin(&mut self,id:Replica,partial_coin: LargeField){
        self.coin_shares.insert(id, partial_coin);
    }

    pub fn contains_coin(&self,id: Replica)->bool{
        self.coin_shares.contains_key(&id)
    }
}