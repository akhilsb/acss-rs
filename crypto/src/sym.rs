use std::convert::TryInto;

use aes_gcm::{Key, Aes256Gcm, KeyInit, aead::AeadMut, Nonce};
use rand::{rngs::OsRng,RngCore};
use serde::{Serialize, Deserialize};


pub const SECRET_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;

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

// AES Encryption
pub fn encrypt(secret: &[u8], message: Vec<u8>)-> Vec<u8>{
    let key = Key::<Aes256Gcm>::from_slice(secret);
    
    let mut nonce: [u8;NONCE_SIZE] = [0;NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    
    let mut cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from(nonce);

    let ciphertext = cipher.encrypt(&nonce, message.as_slice()).expect("FATAL: Error encrypting data");

    let mut encrypted_data = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);
    encrypted_data
}

// AES Decryption
pub fn decrypt(secret: &[u8], ciphertext: Vec<u8>) -> Vec<u8>{
    let key = Key::<Aes256Gcm>::from_slice(secret);

    let (nonce, cipher_slice) = ciphertext.split_at(NONCE_SIZE);

    let nonce = Nonce::from_slice(nonce);

    let mut cipher = Aes256Gcm::new(key);

    let message = cipher.decrypt(nonce,cipher_slice).expect("FATAL: Failed to decrypt data");
    message
}