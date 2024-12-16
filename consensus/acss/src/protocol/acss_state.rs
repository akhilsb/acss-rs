use crypto::{SmallField, LargeField};
use ctrbc::RBCState;
use types::Replica;

use crate::{VSSCommitments};

pub struct ACSSState{
    pub origin: Replica,

    pub shares: Vec<SmallField>,
    pub nonce_shares: (LargeField, LargeField),

    pub commitments: VSSCommitments,
    pub rbc_state: RBCState
}

// impl ACSSState{
//     pub fn new()-> ACSSState{
//         ACSSState { 
//             shares: (), 
//             nonce_shares: (), 
//             commitments: (), 
//             rbc_state: () 
//         }
//     }
// }