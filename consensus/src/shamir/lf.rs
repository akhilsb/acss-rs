use num_bigint_dig::BigInt;
use num_bigint_dig::RandBigInt;
/**
 * Cloned from https://github.com/bitrocks/verifiable-secret-sharing
 * Author: bitrocks: https://github.com/bitrocks
 */

use num_traits::{One, Zero};
use rand::{self};

use crypto::LargeField;

/// The `ShamirSecretSharing` stores threshold, share_amount and the prime of finite field.
#[derive(Clone, Debug)]
pub struct LargeFieldSSS {
    /// the threshold of shares to recover the secret.
    pub threshold: usize,
    /// the total number of shares to generate from the secret.
    pub share_amount: usize,
    /// the characteristic of finite field.
    pub prime: LargeField,
    /// Lagrange coefficients for points 1 through 2f
    pub lag_coeffs: Vec<Vec<LargeField>> 
}

// 64-bit variant of shamir SS mainly because of efficiency
impl LargeFieldSSS {

    pub fn new(threshold: usize, share_amount: usize, prime: LargeField)-> LargeFieldSSS{

        let lag_coeffs = Self::lagrange_coefficients(prime.clone(), threshold, share_amount);
        LargeFieldSSS { 
            threshold: threshold, 
            share_amount: share_amount, 
            prime: prime, 
            lag_coeffs: lag_coeffs 
        }
    }
    
    /// Split a secret according to the config.
    pub fn split(&self, secret: LargeField) -> Vec<(usize, LargeField)> {
        assert!(self.threshold < self.share_amount);
        let polynomial = self.sample_polynomial(secret);
        // println!("polynomial: {:?}", polynomial);
        self.evaluate_polynomial(polynomial)
    }

    pub fn fill_evaluation_at_all_points(&self, values: &mut Vec<LargeField>){
        let mut all_values = Vec::new();
        for coefficients in self.lag_coeffs.iter(){
            let mut sum: LargeField = Zero::zero();
            for (coefficient,point) in coefficients.into_iter().zip(values.clone().into_iter()){
                sum = (sum + (coefficient*point))% &self.prime;
            }
            if sum < BigInt::from(0){
                sum += &self.prime;
            }
            all_values.push(sum);
        }
        values.extend(all_values);
    }

    pub fn verify_degree(&self, values: &mut Vec<LargeField>) -> bool{
        let mut shares_interp = Vec::new();
        
        for rep in self.share_amount - self.threshold .. self.share_amount{
            shares_interp.push((rep+1,values[rep+1].clone()));
        }
        
        let secret = self.recover(&shares_interp);
        //println!("Degree verification : {:?} {:?}",secret,values[0].clone());
        secret == values[0].clone()%&self.prime
    }

    fn sample_polynomial(&self, secret: LargeField) -> Vec<LargeField> {
        let mut coefficients: Vec<LargeField> = vec![secret];
        let mut rng = rand::thread_rng();
        let low = LargeField::from(0u32);
        let high = &self.prime - LargeField::from(1u32);
        let random_coefficients: Vec<LargeField> = (0..(self.threshold - 1))
            .map(|_| rng.gen_bigint_range(&low, &high))
            .collect();
        coefficients.extend(random_coefficients);
        coefficients
    }

    fn evaluate_polynomial(&self, polynomial: Vec<LargeField>) -> Vec<(usize, LargeField)> {
        (1..=self.share_amount)
            .map(|x| (x, self.mod_evaluate_at(&polynomial, x)))
            .collect()
    }

    // Use Horner's method to evaluate polynomial points
    pub fn mod_evaluate_at(&self, polynomial: &[LargeField], x: usize) -> LargeField {
        let x_largefield = BigInt::from(x);
        let mut eval_point = polynomial.iter().rev().fold(Zero::zero(), |sum, item| {
            (&x_largefield * sum + item) % &self.prime
        });
        if eval_point < BigInt::from(0){
            eval_point += &self.prime; 
        }
        eval_point
    }

    // Use Horner's method to evaluate polynomial points
    pub fn mod_evaluate_at_lf(&self, polynomial: &[LargeField], x: LargeField) -> LargeField {
        let x_largefield = BigInt::from(x);
        let mut eval_point = polynomial.iter().rev().fold(Zero::zero(), |sum, item| {
            (&x_largefield * sum + item) % &self.prime
        });
        if eval_point < BigInt::from(0){
            eval_point += &self.prime; 
        }
        eval_point
    }

    /// Recover the secret by the shares.
    pub fn recover(&self, shares: &[(usize, LargeField)]) -> LargeField {
        assert!(shares.len() == self.threshold, "wrong shares number");
        let (xs, ys): (Vec<usize>, Vec<LargeField>) = shares.iter().cloned().unzip();
        let result = self.lagrange_interpolation(Zero::zero(), xs, ys);
        if result < Zero::zero() {
            result + &self.prime
        } else {
            result
        }
    }

    fn lagrange_interpolation(&self, x: LargeField, xs: Vec<usize>, ys: Vec<LargeField>) -> LargeField {
        let len = xs.len();
        // println!("x: {}, xs: {:?}, ys: {:?}", x, xs, ys);
        let xs_largefield: Vec<LargeField> = xs.iter().map(|x| BigInt::from(*x as u64)).collect();
        // println!("sx_LargeField: {:?}", xs_LargeField);
        (0..len).fold(Zero::zero(), |sum, item| {
            let numerator = (0..len).fold(One::one(), |product: LargeField, i| {
                if i == item {
                    product
                } else {
                    product * (&x - &xs_largefield[i]) % &self.prime
                }
            });
            let denominator = (0..len).fold(One::one(), |product: LargeField, i| {
                if i == item {
                    product
                } else {
                    product * (&xs_largefield[item] - &xs_largefield[i]) % &self.prime
                }
            });
            // println!(
            // "numerator: {}, donominator: {}, y: {}",
            // numerator, denominator, &ys[item]
            // );
            (sum + numerator * Self::mod_reverse(self.prime.clone(), denominator) * &ys[item]) % &self.prime
        })
    }

    fn mod_reverse(prime: LargeField, num: LargeField) -> LargeField {
        let num1 = if num < Zero::zero() {
            num + &prime
        } else {
            num
        };
        let (_gcd, _, inv) = Self::extend_euclid_algo(prime, num1);
        // println!("inv:{}", inv);
        inv
    }

    /**
     * https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
     *
     * a*s + b*t = gcd(a,b) a > b
     * r_0 = a*s_0 + b*t_0    s_0 = 1    t_0 = 0
     * r_1 = a*s_1 + b*t_1    s_1 = 0    t_1 = 1
     * r_2 = r_0 - r_1*q_1
     *     = a(s_0 - s_1*q_1) + b(t_0 - t_1*q_1)   s_2 = s_0 - s_1*q_1     t_2 = t_0 - t_1*q_1
     * ...
     * stop when r_k = 0
     */
    fn extend_euclid_algo(prime: LargeField, num: LargeField) -> (LargeField, LargeField, LargeField) {
        let (mut r, mut next_r, mut s, mut next_s, mut t, mut next_t) = (
            prime.clone(),
            num.clone(),
            LargeField::from(1u32),
            LargeField::from(0u32),
            LargeField::from(0u32),
            LargeField::from(1u32),
        );
        let mut quotient;
        let mut tmp;
        while next_r > Zero::zero() {
            quotient = r.clone() / next_r.clone();
            tmp = next_r.clone();
            next_r = r.clone() - next_r.clone() * quotient.clone();
            r = tmp.clone();
            tmp = next_s.clone();
            next_s = s - next_s.clone() * quotient.clone();
            s = tmp;
            tmp = next_t.clone();
            next_t = t - next_t * quotient;
            t = tmp;
        }
        // println!(
        // "{} * {} + {} * {} = {} mod {}",
        // num, t, &self.prime, s, r, &self.prime
        // );
        (r, s, t)
    }

    fn lagrange_coefficients(prime: LargeField, threshold: usize, tot_shares: usize)->Vec<Vec<LargeField>>{
        // Construct denominators first
        let mut denominators = Vec::new();
        
        let xs: Vec<u64> = (0 as u64 .. threshold as u64).into_iter().collect();
        let ys: Vec<u64> = (threshold as u64 .. tot_shares as u64+1u64).into_iter().collect();

        let xs_lf: Vec<LargeField> = xs.iter().map(|x| BigInt::from(*x as u64)).collect();
        let ys_lf: Vec<LargeField> = ys.iter().map(|x| BigInt::from(*x as u64)).collect();
        
        for i in xs_lf.iter(){
            let mut denominator_prod: LargeField = One::one();
            for j in xs_lf.clone().into_iter(){
                if j != i.clone(){
                    denominator_prod = denominator_prod * (i - j) % &prime;
                }
            }
            denominators.push(Self::mod_reverse(prime.clone(), denominator_prod));
        }
        let mut numerators = Vec::new();
        for i in ys_lf.iter(){

            let mut num_prod:LargeField = One::one();
            for j in xs_lf.iter(){
                num_prod = num_prod * (i - j) % &prime;
            }
            let mut num_vec = Vec::new();
            for j in xs_lf.iter(){
                num_vec.push((&num_prod * Self::mod_reverse(prime.clone(), i-j))% &prime);
            }

            numerators.push(num_vec);
        }
        let mut quotients = Vec::new();
        for numerator_poly in numerators.into_iter(){
            let mut poly_quo = Vec::new();
            for (n,d) in numerator_poly.into_iter().zip(denominators.clone().into_iter()){
                poly_quo.push((n*d) % &prime);
            }
            quotients.push(poly_quo);
        }
        quotients
    }

    // Code from ChatGPT on Gaussian Elimination. Needed to interpolate coefficients from polynomial evaluations

    /// Modular arithmetic helper functions for BigInt
    fn mod_sub(a: &BigInt, b: &BigInt, p: &BigInt) -> BigInt {
        ((a % p - b % p) % p + p) % p
    }

    fn mod_mul(a: &BigInt, b: &BigInt, p: &BigInt) -> BigInt {
        ((a % p) * (b % p) % p + p) % p
    }

    /// Computes modular inverse using Fermat's Little Theorem: a^(p-2) % p
    fn mod_inv(a: &BigInt, p: &BigInt) -> BigInt {
        Self::mod_pow(a, &(p - BigInt::from(2)), p)
    }

    /// Computes (base^exp) % p using binary exponentiation
    pub fn mod_pow(base: &BigInt, exp: &BigInt, p: &BigInt) -> BigInt {
        let mut result = BigInt::one();
        let mut base = base.clone() % p;
        let mut exp = exp.clone();

        while !exp.is_zero() {
            if &exp % 2 == BigInt::one() {
                result = Self::mod_mul(&result, &base, p);
            }
            base = Self::mod_mul(&base, &base, p);
            exp /= 2;
        }

        result
    }

    /// Solves for polynomial coefficients in a prime field using Gaussian elimination.
    /// Points are provided as a vector of (i, x_i).
    pub fn polynomial_coefficients(&self, points: &Vec<(BigInt, BigInt)>) -> Vec<BigInt> {
        let prime = &self.prime;
        let n = points.len(); // n = t + 1, degree of polynomial is t
        assert!(
            n > 0,
            "Need at least one point to determine the coefficients."
        );

        let mut matrix = vec![vec![BigInt::zero(); n + 1]; n];

        // Construct the augmented matrix for Vandermonde system
        for (row, (i, x_i)) in points.iter().enumerate() {
            let mut value = BigInt::one();
            for col in 0..n {
                matrix[row][col] = value.clone(); // i^col (mod prime)
                value = Self::mod_mul(&value, i, prime); // Compute next power of i
            }
            matrix[row][n] = x_i.clone() % prime; // Right-hand side: x_i
        }

        // Perform Gaussian elimination
        for col in 0..n {
            // Find the pivot row
            let mut pivot = col;
            for row in col + 1..n {
                if matrix[row][col] > matrix[pivot][col] {
                    pivot = row;
                }
            }
            matrix.swap(col, pivot);

            // Normalize pivot row
            let inv = Self::mod_inv(&matrix[col][col], prime);
            for k in col..=n {
                matrix[col][k] = Self::mod_mul(&matrix[col][k], &inv, prime);
            }

            // Eliminate below pivot
            for row in col + 1..n {
                let factor = matrix[row][col].clone();
                for k in col..=n {
                    matrix[row][k] = Self::mod_sub(
                        &matrix[row][k],
                        &Self::mod_mul(&factor, &matrix[col][k], prime),
                        prime,
                    );
                }
            }
        }

        // Back-substitution to find solution
        let mut coefficients = vec![BigInt::zero(); n];
        for row in (0..n).rev() {
            coefficients[row] = matrix[row][n].clone();
            for col in row + 1..n {
                coefficients[row] = Self::mod_sub(
                    &coefficients[row],
                    &Self::mod_mul(&matrix[row][col], &coefficients[col], prime),
                    prime,
                );
            }
        }

        coefficients
    }
}