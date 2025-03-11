use lambdaworks_math::fft::cpu::roots_of_unity::get_powers_of_primitive_root;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::traits::RootsConfig;
use lambdaworks_math::polynomial::Polynomial;
use lambdaworks_math::traits::ByteConversion;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use num_bigint_dig::BigInt;
use rand;
use rand::random;
use std::fs::File;
use std::io::Read;
use rand::{SeedableRng, RngCore};

pub type LargeField = FieldElement<Stark252PrimeField>;
use std::convert::TryInto;

use crypto::{hash::do_hash, aes_hash::HASH_SIZE, LargeFieldSer};
/**
 * Shamir's Secret Sharing Scheme using Fast Fourier Transform
 * Send evaluation at P(w^i-1) to party i
 * Secret stored at P(0)
 */


#[derive(Clone, Debug)]
pub struct ShamirSecretSharing {
    /// the threshold of shares to recover the secret.
    pub threshold: usize,
    /// the total number of shares to generate from the secret.
    pub share_amount: usize,
    pub roots_of_unity: Vec<LargeField>,
    pub vandermonde_matrix: Vec<Vec<LargeField>>,
}

impl ShamirSecretSharing {
    pub fn new(threshold: usize, share_amount: usize) -> Self {
        ShamirSecretSharing {
            threshold,
            share_amount,
            roots_of_unity: Self::gen_roots_of_unity(share_amount),
            vandermonde_matrix: Vec::new(),
        }
    }
    pub fn rand_field_element() -> LargeField {
        let rand_big = UnsignedInteger { limbs: random() };
        LargeField::new(rand_big)
    }

    /// Returns the corresponding evaluation index for party x
    pub fn get_evaluation_point_from_u64(&self, x: u64) -> LargeField {

        if x == 0 {
            LargeField::zero()
        } else {
            self.roots_of_unity[(x - 1) as usize].clone()
        }
    }

    pub fn get_evaluation_point_from_lf(&self, x: &LargeField) -> LargeField {
        let bytes = x.to_bytes_be();
        let reduced_bytes: [u8; 8] = bytes[bytes.len() - 8..].try_into().unwrap();

        
        let eval_x =u64::from_be_bytes(reduced_bytes);
        if eval_x == 0 {
            LargeField::zero()
        } else {
            self.roots_of_unity[(eval_x - 1) as usize].clone()
        }
    }

    pub fn gen_roots_of_unity(n: usize) -> Vec<LargeField> {
        let len = n.next_power_of_two();
        let order = len.trailing_zeros();
        get_powers_of_primitive_root(order.into(), len, RootsConfig::Natural).unwrap()
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
        Polynomial::evaluate_fft::<Stark252PrimeField>(&polynomial, 1, Some(self.share_amount))
            .unwrap()
    }

    pub fn split(&self, secret: LargeField) -> Vec<LargeField> {
        let polynomial = self.sample_polynomial(secret);
        self.generating_shares(&polynomial)
    }

    pub fn reconstructing(
        &self,
        x: &Vec<u64>, // Parties
        y: &Vec<LargeField>,
    ) -> Polynomial<LargeField> {
        let mapped_x: Vec<LargeField> = x
            .iter()
            .map(|xi| self.get_evaluation_point_from_u64(*xi))
            .collect();

        Polynomial::interpolate(&mapped_x, &y).unwrap()
    }

    pub fn recover(&self, polynomial: &Polynomial<LargeField>) -> LargeField {
        polynomial.coefficients()[0].clone()
    }

    pub fn evaluate_at(&self, polynomial: &Polynomial<LargeField>, x: u64) -> LargeField {
        let evaluation_point = self.get_evaluation_point_from_u64(x);
        polynomial.evaluate(&evaluation_point)
    }
    pub fn evaluate_at_lf(&self, polynomial: &Polynomial<LargeField>, x: LargeField) -> LargeField {
        let evaluation_point = self.get_evaluation_point_from_lf(&x);
        polynomial.evaluate(&evaluation_point)
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
    // Note that we expect polynomial_evaluations at points 0, w^0, w^1, ... w^(t), and not 0... t like we did before
    // We return the polynomial evaluations at points 0, w^0, w^1, ... w^(n) where n is the share amount
    // Note that we can only use this function when t+1 = 2^m

    pub fn verify_degree(&self, values: &mut Vec<LargeField>) -> bool{
        let mut shares_interp = Vec::new();
        
        for rep in self.share_amount - self.threshold .. self.share_amount{
            shares_interp.push(values[rep+1].clone());
        }
        
        let secret = self.recover(&Polynomial::new(&shares_interp[..]));
        //println!("Degree verification : {:?} {:?}",secret,values[0].clone());
        secret == values[0].clone()
    }
    pub fn fill_evaluation_at_all_points_fft(&self, polynomial_evals: &mut Vec<LargeField>) {
        let mut all_values = Vec::new();
        all_values.push(polynomial_evals[0]);
        polynomial_evals.remove(0);
        let coeffs = Polynomial::interpolate_fft::<Stark252PrimeField>(&polynomial_evals).unwrap();
        let evals =
            Polynomial::evaluate_fft::<Stark252PrimeField>(&coeffs, 1, Some(self.share_amount))
                .unwrap();
        all_values.extend(evals);

        while all_values.len() > self.share_amount + 1 {
            all_values.pop();
        }
        *polynomial_evals = all_values;
    }

    pub fn fill_evaluation_at_all_points(&self, polynomial_evals: &mut Vec<LargeField>) {
        let mut all_values = Vec::new();

        // assert polynomial evals length = t + 1
        let mut x = Vec::new();
        for i in 0..polynomial_evals.len() {
            x.push(i as u64);
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

    pub fn scale_polynomial(
        poly: &Polynomial<LargeField>,
        scalar: &LargeField,
    ) -> Polynomial<LargeField> {
        poly * scalar
    }

    // TODO: Rename later
    pub fn mod_pow(base: &LargeField, exp: u64) -> LargeField {
        base.pow(exp)
    }
}

// Functions that require a Vandermonde Matrix. TODO: Add actual vandermonde functionality after you precompute vandermonde values for roots of unity
impl ShamirSecretSharing {
    pub fn new_with_vandermonde(
        threshold: usize,
        share_amount: usize,
        vandermonde_matrix_file: String,
    ) -> ShamirSecretSharing {
        let mut file = File::open(vandermonde_matrix_file).expect("Failed to open file.");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read file.");

        let loaded_matrix: Vec<Vec<LargeFieldSer>> =
            serde_json::from_str(&contents).expect("Failed to deserialize matrix.");

        let load_matrix_lf: Vec<Vec<LargeField>> = loaded_matrix
            .into_iter()
            .map(|el| {
                el.into_iter()
                    .map(|el| LargeField::from_bytes_be(el.as_slice()).unwrap())
                    .collect()
            })
            .collect();

        ShamirSecretSharing {
            threshold: threshold,
            share_amount: share_amount,
            roots_of_unity: Self::gen_roots_of_unity(share_amount),
            vandermonde_matrix: load_matrix_lf,
        }
    }



    /// Multiply a matrix by a vector in a prime field
    pub fn matrix_vector_multiply(
        matrix: &Vec<Vec<LargeField>>,
        vector: &Vec<LargeField>,
    ) -> Vec<LargeField> {
        matrix
            .iter()
            .map(|row| {
                row.iter()
                    .zip(vector)
                    .fold(LargeField::zero(), |sum, (a, b)| sum + (a* b))
            })
            .collect()
    }


    // TODO: Also take in the inverse vandrmonde when you precompute
    pub fn polynomial_coefficients_with_vandermonde_matrix(
        &self,
        matrix: &Vec<Vec<LargeField>>,
        y_values: &Vec<LargeField>,
    ) -> Polynomial<LargeField> {
        Polynomial::new(&Self::matrix_vector_multiply(matrix, y_values)[..])
    }

    pub fn polynomial_coefficients_with_precomputed_vandermonde_matrix(
        &self,
        y_values: &Vec<LargeField>,
    ) -> Polynomial<LargeField> {
        Polynomial::new( &Self::matrix_vector_multiply(&self.vandermonde_matrix, y_values)[..])
    }

    /// Constructs the Vandermonde matrix for a given set of x-values. Note that the x-values are parties and are converted to the ith root of unity for the evaluation
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

    /// Computes the inverse of a Vandermonde matrix using Gaussian elimination.
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
            let inv = augmented[col][col].inv().unwrap();
            for k in col..2 * n {
                augmented[col][k] = augmented[col][k] * inv;
            }

            // Eliminate other rows
            for row in 0..n {
                if row != col {
                    let factor = augmented[row][col].clone();
                    for k in col..2 * n {
                        augmented[row][k] = &augmented[row][k] - factor * &augmented[col][k];
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
    use std::convert::TryInto;

    #[test]
    fn shamir_secret_sharing_works() {
        type LargeField = FieldElement<Stark252PrimeField>; // Alias for LargeField
        let secret = LargeField::new(UnsignedInteger::from(1234u64));

        let sss = ShamirSecretSharing {
            share_amount: 6,
            threshold: 3,
            roots_of_unity: ShamirSecretSharing::gen_roots_of_unity(6),
            vandermonde_matrix: Vec::new(),
        };

        let polynomial = sss.sample_polynomial(secret);
        let shares = sss.generating_shares(&polynomial);

        let shares_to_use_x = vec![1u64, 3u64, 4u64];
        let shares_to_use_y = vec![shares[0], shares[2], shares[3]];
        let poly_2 = sss.reconstructing(&shares_to_use_x, &shares_to_use_y);
        let secret_recovered = sss.recover(&poly_2);
        assert_eq!(secret, secret_recovered);
    }

    #[test]
    fn test_fill_evaluation_at_all_points() {
        type LargeField = FieldElement<Stark252PrimeField>; // Alias for LargeField
        let secret = LargeField::new(UnsignedInteger::from(1234u64));

        let sss = ShamirSecretSharing {
            share_amount: 32,
            threshold: 16,
            roots_of_unity: ShamirSecretSharing::gen_roots_of_unity(32),
            vandermonde_matrix: Vec::new(),
        };

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

    #[test]
    fn test_lf_to_u64() {
        type LargeField = FieldElement<Stark252PrimeField>; // Alias for LargeField
        let sss = ShamirSecretSharing {
            share_amount: 32,
            threshold: 16,
            roots_of_unity: ShamirSecretSharing::gen_roots_of_unity(32),
            vandermonde_matrix: Vec::new(),
        };

        let lf = LargeField::new(UnsignedInteger::from(1234u64));
        let bytes = lf.to_bytes_be();
        let reduced_bytes: [u8; 8] = bytes[bytes.len() - 8..].try_into().unwrap();
        let u64_val = u64::from_be_bytes(reduced_bytes);
        assert_eq!(u64_val, 1234u64);
    }
}
