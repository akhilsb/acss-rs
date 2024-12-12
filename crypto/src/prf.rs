use num_bigint_dig::{Sign, BigInt};
use rand::{SeedableRng, RngCore};
use rand_chacha::ChaCha20Rng;

use crate::{hash::do_hash, aes_hash::HASH_SIZE};

pub type SmallField = u64;
pub type LargeFieldSer = Vec<u8>;
pub type LargeField = BigInt;


pub fn pseudorandom_sf(rng_seed: &[u8], num: usize)->Vec<SmallField>{
    let mut rng = ChaCha20Rng::from_seed(do_hash(rng_seed));

    let mut random_numbers: Vec<SmallField> = Vec::new();
    for _i in 0..num{
        let rand_num = rng.next_u64();
        random_numbers.push(rand_num);
    }
    random_numbers
}

pub fn pseudorandom_lf( rng_seed: &[u8], num: usize)->Vec<LargeField>{
    let mut rng = ChaCha20Rng::from_seed(do_hash(rng_seed));
    let mut random_numbers: Vec<LargeField> = Vec::new();
    for _i in 0..num{
        let mut rnd_bytes = [0u8;HASH_SIZE];
        rng.fill_bytes(&mut rnd_bytes);
        let bigint_rand = BigInt::from_bytes_be(Sign::Plus, &rnd_bytes);
        random_numbers.push(bigint_rand);
    }
    random_numbers
}