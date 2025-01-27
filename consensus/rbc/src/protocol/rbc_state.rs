use std::collections::{HashMap, HashSet};

pub struct RBCState {
    pub received_echo_count: HashMap<Vec<u8>, usize>,
    pub received_ready_count: HashMap<Vec<u8>, usize>,

    pub echo_senders: HashMap<Vec<u8>, HashSet<usize>>,
    pub ready_senders: HashMap<Vec<u8>, HashSet<usize>>,

    pub first_ready: bool,
    pub second_ready: bool,
    pub terminated: bool,
}

impl RBCState {
    pub fn new() -> RBCState {
        RBCState {
            received_echo_count: HashMap::default(),
            received_ready_count: HashMap::default(),

            echo_senders: HashMap::default(),
            ready_senders: HashMap::default(),

            first_ready: false,
            second_ready: false,
            terminated: false,
        }
    }
}

impl Default for RBCState {
    fn default() -> Self {
        Self::new()
    }
}
