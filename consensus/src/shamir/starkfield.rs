use crypto::LargeFieldSer;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::polynomial::Polynomial;
use lambdaworks_math::traits::ByteConversion;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use num_bigint_dig::BigInt;
use rand;
use rand::random;
use std::fs::File;
use std::io::Read;

pub type LargeField = FieldElement<Stark252PrimeField>;

#[derive(Clone, Debug)]
pub struct ShamirSecretSharing {
    /// the threshold of shares to recover the secret.
    pub threshold: usize,
    /// the total number of shares to generate from the secret.
    pub share_amount: usize,
    pub vandermonde_matrix: Vec<Vec<LargeField>>,
}

impl ShamirSecretSharing {
    pub fn new(threshold: usize, share_amount: usize) -> Self {
        ShamirSecretSharing {
            threshold,
            share_amount,
            vandermonde_matrix: Vec::new(),
        }
    }

    pub fn new_with_vandermonde(
        threshold: usize,
        share_amount: usize,
        vandermonde_matrix_file: String,
        prime: LargeField,
    ) -> ShamirSecretSharing {
        let mut file = File::open(vandermonde_matrix_file).expect("Failed to open file.");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read file.");

        let loaded_matrix: Vec<Vec<LargeFieldSer>> =
            serde_json::from_str(&contents).expect("Failed to deserialize matrix.");

            let load_matrix_bigint: Vec<Vec<LargeField>> = loaded_matrix
            .into_iter()
            .map(|el| {
                el.into_iter()
                    .map(|el| LargeField::from_bytes_be(el.as_slice()).unwrap()) // Force unwrap
                    .collect()
            })
            .collect();
         

        ShamirSecretSharing {
            threshold: threshold,
            share_amount: share_amount,
            vandermonde_matrix: load_matrix_bigint,
        }
    }
}

// Conversion functions

impl ShamirSecretSharing {
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

// Functions that will be needed for HACSS (High threshold asyncronous complete secret sharing)

impl ShamirSecretSharing {
    pub fn fill_evaluation_at_all_points(&self, polynomial_evals: &mut Vec<LargeField>) {
        let mut all_values = Vec::new();

        // assert polynomial evals length = t + 1
        let mut x = Vec::new();
        for i in 0..polynomial_evals.len() {
            x.push(LargeField::from(i as u64));
        }
        let coeffs = self.reconstructing(&x, &polynomial_evals);
        all_values.push(polynomial_evals[0]);
        all_values.extend(self.generating_shares(&coeffs));
        *polynomial_evals = all_values;
    }

    pub fn add_polynomials(
        poly1: &Polynomial<LargeField>,
        poly2: &Polynomial<LargeField>,
    ) -> Polynomial<LargeField> {
        poly1 + poly2
    }

    pub fn multiply_polynomials(
        poly1: &Polynomial<LargeField>,
        poly2: &Polynomial<LargeField>,
    ) -> Polynomial<LargeField> {
        poly1 * poly2
    }
}

// Functions related to Vandermonde matrix and functions that use Vandermonde matrix to optimize for the range 0..t+1
impl ShamirSecretSharing {
    /// Constructs the Vandermonde matrix for a given set of x-values.
    pub fn vandermonde_matrix(&self, x_values: &Vec<LargeField>) -> Vec<Vec<LargeField>> {
        let n = x_values.len();
        let mut matrix = vec![vec![LargeField::zero(); n]; n];

        for (row, x) in x_values.iter().enumerate() {
            let mut value = LargeField::one();
            for col in 0..n {
                matrix[row][col] = value.clone();
                value = value * x;
            }
        }
        matrix
    }

    /// Computes the inverse of a Vandermonde matrix modulo prime using Gaussian elimination.
    pub fn inverse_vandermonde(&self, matrix: Vec<Vec<LargeField>>) -> Vec<Vec<LargeField>> {
        let n = matrix.len();
        let mut augmented = matrix.clone();

        // Extend the matrix with an identity matrix on the right
        for i in 0..n {
            augmented[i].extend((0..n).map(|j| {
                if i == j {
                    LargeField::one()
                } else {
                    LargeField::zero()
                }
            }));
        }

        // Perform Gaussian elimination
        for col in 0..n {
            // Normalize pivot row
            let inv = augmented[col][col].inv();
            for k in col..2 * n {
                augmented[col][k] = augmented[col][k] * inv;
            }

            // Eliminate other rows
            for row in 0..n {
                if row != col {
                    let factor = augmented[row][col].clone();
                    for k in col..2 * n {
                        augmented[row][k] = augmented[row][k] - (factor * augmented[col][k]);
                    }
                }
            }
        }

        // Extract the right half as the inverse
        augmented
            .into_iter()
            .map(|row| row[n..2 * n].to_vec())
            .collect()
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

        let sss = ShamirSecretSharing::new(6, 3);

        let polynomial = sss.sample_polynomial(secret);
        let shares = sss.generating_shares(&polynomial);

        let shares_to_use_x = vec![
            LargeField::new(UnsignedInteger::from(1u64)),
            LargeField::new(UnsignedInteger::from(3u64)),
            LargeField::new(UnsignedInteger::from(4u64)),
        ];
        let shares_to_use_y = vec![shares[0], shares[2], shares[3]];
        let poly_2 = sss.reconstructing(&shares_to_use_x, &shares_to_use_y);
        let secret_recovered = sss.recover(&poly_2);
        assert_eq!(secret, secret_recovered);
    }

    #[test]
    fn test_fill_evaluation_at_all_points() {
        type LargeField = FieldElement<Stark252PrimeField>; // Alias for LargeField
        let secret = LargeField::new(UnsignedInteger::from(1234u64));

        let sss = ShamirSecretSharing::new(6, 3);

        // generate polynomial, generate shares, then create a new vector with the first t+1 shares and the secret, and then verify that its equal to the shares polynomial after fill evals at all points
        let polynomial = sss.sample_polynomial(secret);
        let shares = sss.generating_shares(&polynomial);
        let mut shares_to_use = Vec::new();
        shares_to_use.push(secret);
        shares_to_use.extend(shares[0..sss.threshold + 1].to_vec());
        sss.fill_evaluation_at_all_points(&mut shares_to_use);
        // assert first element of shares_to_use is equal to secret
        assert_eq!(shares_to_use[0], secret);
        // remove shares_to_use[0]
        shares_to_use.remove(0);
        // assert shares_to_use is equal to shares
        assert_eq!(shares_to_use, shares);
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
//         )
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
