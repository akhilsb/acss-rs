use std::convert::TryInto;

use rand::{rngs::OsRng,RngCore};
use serde::{Serialize, Deserialize};


pub const SECRET_KEY_SIZE: usize = 32;

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct SecretKey([u8; SECRET_KEY_SIZE]);

impl SecretKey{
    pub fn new() -> SecretKey{
        let mut data = [0u8;32];
        OsRng.fill_bytes(&mut data);
        SecretKey(data)
    }

    pub fn from_vec(secret:Vec<u8>) -> SecretKey{
        let sec_arr: [u8;SECRET_KEY_SIZE] = secret.try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", 32, v.len()));
        SecretKey(sec_arr)
    }

    pub fn to_vec(&self) -> Vec<u8>{
        self.0.to_vec()
    }
}