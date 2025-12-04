use lambdaworks_math::field::{fields::{fft_friendly::stark_252_prime_field::{MontgomeryConfigStark252PrimeField}, montgomery_backed_prime_fields::MontgomeryBackendPrimeField}, element::FieldElement};

pub type LargeField = FieldElement<MontgomeryBackendPrimeField<MontgomeryConfigStark252PrimeField, 4>>;
pub type FieldType = MontgomeryBackendPrimeField<MontgomeryConfigStark252PrimeField, 4>;

//pub type LargeField = Secp256k1PrimeField;
//pub type FieldType = Secp256k1PrimeField;

pub type LargeFieldSer = [u8;32];

// Shares, nonce polynomial, blinding_nonce polynomial
pub type AvssShare =  (Vec<LargeFieldSer>, LargeFieldSer, LargeFieldSer);
use ha_crypto::aes_hash::{HashState, Proof};

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
        let hash_of_shard: [u8; 32] = hf.do_hash_aes(&self.shard.as_slice());
        let state: bool = hash_of_shard == self.mp.item().clone() && self.mp.validate(hf);
        return state;
    }
}

use std::collections::HashMap;

use ha_crypto::{hash::Hash};

pub struct RBCState{
    pub origin: Replica,

    pub echos: HashMap<Hash, HashMap<usize,Vec<u8>>>,
    pub echo_root: Option<Hash>,

    pub readys: HashMap<Hash, HashMap<usize,Vec<u8>>>,
    
    pub fragment: Option<(Vec<u8>, Proof)>,
    pub message: Option<Vec<u8>>,

    pub terminated: bool
}

impl RBCState{
    
    pub fn new(origin: Replica)-> RBCState{
        RBCState {
            origin: origin,

            echos: HashMap::default(), 
            echo_root: None, 
            
            readys: HashMap::default(), 
            
            fragment: None, 
            message: None,

            terminated:false
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct RBCSyncMsg {
    pub id: usize,
    pub msg: String,
}