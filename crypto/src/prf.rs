use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use rand::{SeedableRng, RngCore, random};
use rand_chacha::ChaCha20Rng;

use lambdaworks_math::field::{element::FieldElement, fields::montgomery_backed_prime_fields::MontgomeryBackendPrimeField};
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::{MontgomeryConfigStark252PrimeField};

use crate::{hash::do_hash};

pub type LargeField = FieldElement<MontgomeryBackendPrimeField<MontgomeryConfigStark252PrimeField, 4>>;
pub type FieldType = MontgomeryBackendPrimeField<MontgomeryConfigStark252PrimeField, 4>;

//pub type LargeField = Secp256k1PrimeField;
//pub type FieldType = Secp256k1PrimeField;

pub type LargeFieldSer = [u8;32];

pub fn pseudorandom_lf(rng_seed: &[u8], num: usize)->Vec<LargeField>{
    let mut rng = ChaCha20Rng::from_seed(do_hash(rng_seed));
    let mut random_numbers: Vec<LargeField> = Vec::new();
    for _i in 0..num{
        let mut limbs = [0u64;4];
        for j in 0..4{
            limbs[j] = rng.next_u64();
        }
        let bigint_rand = UnsignedInteger{ 
            limbs: limbs
        };
        random_numbers.push(LargeField::new( bigint_rand));
    }
    random_numbers
}

pub fn rand_field_element() -> LargeField {
    let rand_big = UnsignedInteger { limbs: random() };
    LargeField::new(rand_big)
}