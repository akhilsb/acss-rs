use sha2::{Digest, Sha256};
use serde::Serialize;
use hmac::{Hmac,Mac,NewMac};

pub const HASH_SIZE:usize = 32;

pub type Hash = [u8; HASH_SIZE];

pub const EMPTY_HASH:Hash = [0 as u8; 32];

type HmacSha256 = Hmac<Sha256>;

pub fn do_hash(bytes: &[u8]) -> Hash {
    let hash = Sha256::digest(bytes);
    return hash.into();
} 

pub fn do_hash_merkle(bytes: &[u8])-> Hash{
    let mut sha256 = Sha256::new();
    sha256.update(&[0x00]);
    sha256.update(bytes);
    sha256.clone().finalize().into()
}

pub fn ser_and_hash(obj: &impl Serialize) -> Hash {
    let serialized_bytes = bincode::serialize(obj).unwrap();
    return do_hash(&serialized_bytes);
}

pub fn do_mac(bytes: &[u8], secret_key:&[u8])-> Hash{
    let mut mac = HmacSha256::new_varkey(secret_key)
        .expect("HMAC can take secret key of any size");
    mac.update(bytes);
    let result = mac.finalize();
    // is an array copy necessary?
    result.into_bytes().into()
}

pub fn verf_mac(bytes: &[u8], secret_key:&[u8], mac_v:&[u8])-> bool{
    let mut mac = HmacSha256::new_varkey(secret_key)
        .expect("HMAC can take secret key of any size");
    
    mac.update(bytes);

    let err_c = mac.verify(mac_v);
    match err_c {
        Ok(_)=>{
            true
        },
        Err(_)=>{
            false
        }
    }
}