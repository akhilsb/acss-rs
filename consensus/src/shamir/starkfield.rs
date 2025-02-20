use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::polynomial::Polynomial;
use lambdaworks_math::traits::ByteConversion;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use num_bigint_dig::BigInt;
use rand;
use rand::random;

pub type LargeField = FieldElement<Stark252PrimeField>;

#[derive(Clone, Debug)]
pub struct ShamirSecretSharing {
    /// the threshold of shares to recover the secret.
    pub threshold: usize,
    /// the total number of shares to generate from the secret.
    pub share_amount: usize,
}

impl ShamirSecretSharing {
    pub fn new(threshold: usize, share_amount: usize) -> Self {
        ShamirSecretSharing {
            threshold,
            share_amount,
        }
    }
    pub fn rand_field_element() -> LargeField {
        let rand_big = UnsignedInteger { limbs: random() };
        LargeField::new(rand_big)
    }

    /// Generates coefficients for a polynomial of degree `threshold - 1` such that the constant term is the secret.
    pub fn sample_polynomial(&self, secret: LargeField) -> Polynomial<LargeField> {
        let threshold = self.threshold;
        let mut coefficients: Vec<LargeField> = Vec::new();
        // first element is the secret
        coefficients.push(secret);
        for _ in 0..threshold - 1 {
            coefficients.push(Self::rand_field_element());
        }

        Polynomial::new(&coefficients[..])
    }

    // Generating vector of starkfield elements rather than shares for now since we aren't generating random X values
    pub fn generating_shares(&self, polynomial: &Polynomial<LargeField>) -> Vec<LargeField> {
        let mut shares: Vec<LargeField> = Vec::new();

        for i in 1..self.share_amount + 1 {
            let x = LargeField::from(i as u64);
            let y = polynomial.evaluate(&x);
            shares.push(y);
        }
        shares
    }

    pub fn reconstructing(
        &self,
        x: &Vec<LargeField>,
        y: &Vec<LargeField>,
    ) -> Polynomial<LargeField> {
        Polynomial::interpolate(&x, &y).unwrap()
    }

    pub fn recover(&self, polynomial: &Polynomial<LargeField>) -> LargeField {
        polynomial.coefficients()[0].clone()
    }

    /// Temporary functions to convert a large field element to a BigInt. Get rid of this once the whole library is using Lambdaworks Math.
    pub fn lf_to_bigint(field_elem: &LargeField) -> BigInt {
        let bytes = field_elem.to_bytes_be();
        BigInt::from_signed_bytes_be(&bytes)
    }

    pub fn bigint_to_lf(bigint: &BigInt) -> LargeField {
        let bytes = bigint.to_signed_bytes_be();
        FieldElement::<Stark252PrimeField>::from_bytes_be(&bytes).unwrap()
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {

    use crate::ShamirSecretSharing;
    use lambdaworks_math::field::element::FieldElement;
    use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
    use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

    #[test]
    fn shamir_secret_sharing_works() {
        type LargeField = FieldElement<Stark252PrimeField>; // Alias for LargeField
        let secret = LargeField::new(UnsignedInteger::from(1234u64));

        let sss = ShamirSecretSharing {
            share_amount: 6,
            threshold: 3,
        };

        let polynomial = sss.sample_polynomial(secret);
        let shares = sss.generating_shares(&polynomial);

        let shares_to_use_x = vec![
            LargeField::new(UnsignedInteger::from(1u64)),
            LargeField::new(UnsignedInteger::from(3u64)),
            LargeField::new(UnsignedInteger::from(4u64)),
        ];
        let shares_to_use_y = vec![shares[1], shares[3], shares[4]];
        let poly_2 = sss.reconstructing(&shares_to_use_x, &shares_to_use_y);
        let secret_recovered = sss.recover(&poly_2);
        assert_eq!(secret, secret_recovered);
    }
}

// TODO: @sohamjog uncomment
// #[cfg(test)]
// mod tests {
//     use super::*;
//     #[test]
//     fn test_wikipedia_example() {
//         let sss = ShamirSecretSharing {
//             threshold: 3,
//             share_amount: 6,
//             prime: BigInt::from(1613),
//         };
//         let shares = sss.evaluate_polynomial(vec![
//             BigInt::from(1234),
//             BigInt::from(166),
//             BigInt::from(94),
//         ]);
//         assert_eq!(
//             shares,
//             [
//                 (1, BigInt::from(1494)),
//                 (2, BigInt::from(329)),
//                 (3, BigInt::from(965)),
//                 (4, BigInt::from(176)),
//                 (5, BigInt::from(1188)),
//                 (6, BigInt::from(775))
//             ]
//         );
//         assert_eq!(
//             sss.recover(&[
//                 (1, BigInt::from(1494)),
//                 (2, BigInt::from(329)),
//                 (3, BigInt::from(965))
//             ]),
//             BigInt::from(1234)
//         );
//     }
//     #[test]
//     fn test_large_prime() {
//         let sss = ShamirSecretSharing {
//             threshold: 3,
//             share_amount: 5,
//             // prime: BigInt::from(6999213259363483493573619703 as i128),
//             prime: BigInt::parse_bytes(
//                 b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
//                 16,
//             )
//             .unwrap(),
//         };
//         let secret = BigInt::parse_bytes(b"ffffffffffffffffffffffffffffffffffffff", 16).unwrap();
//         let shares = sss.split(secret.clone());
//         assert_eq!(secret, sss.recover(&shares[0..sss.threshold as usize]));
//     }
// }
