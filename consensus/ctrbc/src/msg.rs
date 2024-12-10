use crypto::aes_hash::{HashState, Proof};

use crypto::hash::{do_hash};
use serde::{Deserialize, Serialize};

use types::{Replica};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CTRBCMsg {
    pub shard: Vec<u8>,
    pub mp: Proof,
    pub origin: Replica,
}

impl CTRBCMsg {
    pub fn verify_mr_proof(&self, hf: &HashState) -> bool {
        // 2. Validate Merkle Proof
        let hash_of_shard: [u8; 32] = do_hash(&self.shard.as_slice());
        let state: bool = hash_of_shard == self.mp.item().clone() && self.mp.validate(hf);
        return state;
    }
}
/*
this is how the rbc protocol works
1. <sendall, m> (this is broadcast)
2. <echo, m>
3. on (2t+1 <echo, m>) <Ready, m>
4. on (t+1 <ready, m>) <ready, m>
5. on (2t+1 <ready, m>) output m, terminate
*/

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg {
    // Create your custom types of messages'
    Init(CTRBCMsg, usize), // Init
    Echo(CTRBCMsg, usize),
    Ready(CTRBCMsg, usize),
}