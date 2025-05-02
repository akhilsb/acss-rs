use std::ops::{Sub, Add};
use std::{ops::Mul};

use crypto::{rand_field_element};
use lambdaworks_math::{ polynomial::Polynomial, unsigned_integer::element::UnsignedInteger};

use rayon::prelude::{ParallelIterator, IntoParallelRefIterator, IntoParallelIterator};

use crypto::LargeField;

/// The `ShamirSecretSharing` stores threshold, share_amount and the prime of finite field.
#[derive(Clone, Debug)]
pub struct LargeFieldSSS {
    /// the threshold of shares to recover the secret.
    pub threshold: usize,
    /// the total number of shares to generate from the secret.
    pub share_amount: usize,
    /// Lagrange coefficients for points 1 through 2f
    pub lag_coeffs: Vec<Vec<LargeField>>,
    /// Vandermonde inverse matrix for points -f to f
    pub vandermonde_matrix: Vec<Vec<LargeField>>
}

// 64-bit variant of shamir SS mainly because of efficiency
impl LargeFieldSSS {

    pub fn new(threshold: usize, share_amount: usize)-> LargeFieldSSS{

        let lag_coeffs = Self::lagrange_coefficients(threshold, share_amount);
        LargeFieldSSS { 
            threshold: threshold, 
            share_amount: share_amount, 
            lag_coeffs: lag_coeffs ,
            vandermonde_matrix: Vec::new()
        }
    }

    pub fn new_with_vandermonde(threshold: usize, share_amount: usize)-> LargeFieldSSS{
        let lag_coeffs = Self::lagrange_coefficients(threshold, share_amount);
        let mut x_values = Vec::new();
        for index in (1..threshold+1).into_iter(){
            x_values.push(LargeField::from(index as u64));
        }

        // Compute Vandermonde matrix
        let vandermonde = Self::vandermonde_matrix(x_values);
        let vandermonde_inverse = Self::inverse_vandermonde(vandermonde);

        LargeFieldSSS { 
            threshold: threshold, 
            share_amount: share_amount, 
            lag_coeffs: lag_coeffs,
            vandermonde_matrix: vandermonde_inverse
        }
    }
    
    /// Split a secret according to the config.
    pub fn split(&self, secret: LargeField) -> Vec<LargeField> {
        assert!(self.threshold < self.share_amount);
        let polynomial = self.sample_polynomial(secret);
        // println!("polynomial: {:?}", polynomial);
        let polynomial = Polynomial::new(polynomial.as_slice());
        
        let mut evaluation_points = Vec::new();
        
        for i in 0..self.share_amount{
            evaluation_points.push(
                polynomial.evaluate(&LargeField::new(UnsignedInteger::from((i+1) as u64)))
            );
        }

        evaluation_points
    }

    pub fn fill_evaluation_at_all_points(&self, values: &mut Vec<LargeField>){
        let mut all_values = Vec::new();
        for coefficients in self.lag_coeffs.iter(){
            let mut sum: LargeField = LargeField::zero();
            for (coefficient,point) in coefficients.into_iter().zip(values.clone().into_iter()){
                sum += coefficient*point;
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
        secret == values[0].clone()
    }

    fn sample_polynomial(&self, secret: LargeField) -> Vec<LargeField> {
        let mut coefficients: Vec<LargeField> = vec![secret];
        let random_coefficients: Vec<LargeField> = (0..(self.threshold - 1))
            .map(|_| rand_field_element())
            .collect();
        coefficients.extend(random_coefficients);
        coefficients
    }

    /// Recover the secret by the shares.
    pub fn recover(&self, shares: &[(usize, LargeField)]) -> LargeField {
        assert!(shares.len() == self.threshold, "wrong shares number");
        let (xs, ys): (Vec<usize>, Vec<LargeField>) = shares.iter().cloned().unzip();
        let result = self.lagrange_interpolation(LargeField::zero(), xs, ys);
        result
    }

    fn lagrange_interpolation(&self, x: LargeField, xs: Vec<usize>, ys: Vec<LargeField>) -> LargeField {
        let xs = xs.into_iter().map(|x| LargeField::new(UnsignedInteger::from(x as u64))).collect::<Vec<LargeField>>();
        let poly = Polynomial::interpolate(&xs, &ys).unwrap();

        poly.evaluate(&x)
    }

    pub fn mod_evaluate_at_lf(&self, polynomial: &[LargeField], x: LargeField) -> LargeField {
        let poly = Polynomial::new(polynomial);
        poly.evaluate(&x)
    }

    pub fn mod_evaluate_at(&self, polynomial: &[LargeField], x: usize) -> LargeField {
        let poly = Polynomial::new(polynomial);
        poly.evaluate(&LargeField::new(UnsignedInteger::from(x as u64)))
    }

    pub fn polynomial_coefficients_with_precomputed_vandermonde_matrix(&self, y_values: &Vec<LargeField>) -> Vec<LargeField> {
        // Multiply Vandermonde inverse by the y-values vector to solve for coefficients
        Self::matrix_vector_multiply(&self.vandermonde_matrix, y_values)
    }

    pub fn polynomial_coefficients_with_vandermonde_matrix(&self, matrix: &Vec<Vec<LargeField>>, y_values: &Vec<LargeField>) -> Vec<LargeField>{
        Self::matrix_vector_multiply(matrix, y_values)
    }

    fn lagrange_coefficients(threshold: usize, tot_shares: usize)->Vec<Vec<LargeField>>{
        // Construct denominators first
        let mut denominators = Vec::new();
        
        let xs: Vec<u64> = (0 as u64 .. threshold as u64).into_iter().collect();
        let ys: Vec<u64> = (threshold as u64 .. tot_shares as u64+1u64).into_iter().collect();

        let xs_lf: Vec<LargeField> = xs.iter().map(|x| LargeField::from(*x as u64)).collect();
        let ys_lf: Vec<LargeField> = ys.iter().map(|x| LargeField::from(*x as u64)).collect();
        
        for i in xs_lf.iter(){
            let mut denominator_prod: LargeField = LargeField::one();
            for j in xs_lf.clone().into_iter(){
                if j != i.clone(){
                    denominator_prod = denominator_prod * (i - j);
                }
            }
            denominators.push(denominator_prod.inv().unwrap());
        }
        let mut numerators = Vec::new();
        for i in ys_lf.iter(){

            let mut num_prod:LargeField = LargeField::one();
            for j in xs_lf.iter(){
                num_prod = num_prod * (i - j);
            }
            let mut num_vec = Vec::new();
            for j in xs_lf.iter(){
                num_vec.push(&num_prod * (i-j).inv().unwrap());
            }

            numerators.push(num_vec);
        }
        let mut quotients = Vec::new();
        for numerator_poly in numerators.into_iter(){
            let mut poly_quo = Vec::new();
            for (n,d) in numerator_poly.into_iter().zip(denominators.clone().into_iter()){
                poly_quo.push(n*d);
            }
            quotients.push(poly_quo);
        }
        quotients
    }

    /// Constructs the Vandermonde matrix for a given set of x-values.
    pub fn vandermonde_matrix(x_values: Vec<LargeField>) -> Vec<Vec<LargeField>> {
        let n = x_values.len();
        let mut matrix = vec![vec![LargeField::zero(); n]; n];

        for (row, x) in x_values.iter().enumerate() {
            let mut value = LargeField::one();
            for col in 0..n {
                matrix[row][col] = value.clone();
                value = value.mul(x);
            }
        }

        matrix
    }

    /// Computes the inverse of a Vandermonde matrix modulo prime using Gaussian elimination.
    pub fn inverse_vandermonde(matrix: Vec<Vec<LargeField>>) -> Vec<Vec<LargeField>> {
        let n = matrix.len();
        let mut augmented = matrix.clone();

        // Extend the matrix with an identity matrix on the right
        for i in 0..n {
            augmented[i].extend((0..n).map(|j| if i == j { LargeField::one() } else { LargeField::zero() }));
        }

        // Perform Gaussian elimination
        for col in 0..n {
            // Normalize pivot row
            let inv = &augmented[col][col].inv().unwrap();
            for k in col..2 * n {
                augmented[col][k] = augmented[col][k].mul(inv);
            }

            // Eliminate other rows
            for row in 0..n {
                if row != col {
                    let factor = augmented[row][col].clone();
                    for k in col..2 * n {
                        augmented[row][k] = augmented[row][k].sub(factor.mul(augmented[col][k]));
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

    pub fn matrix_vector_multiply(
        matrix: &Vec<Vec<LargeField>>,
        vector: &Vec<LargeField>,
    ) -> Vec<LargeField> {
        matrix
            .par_iter()
            .map(|row| {
                row.iter()
                    .zip(vector)
                    .fold(LargeField::zero(), |sum, (a, b)| sum.add(a.mul(b)))
            })
            .collect()
    }

    pub fn check_if_all_points_lie_on_degree_x_polynomial(eval_points: Vec<LargeField>, polys_vector: Vec<Vec<LargeField>>, degree: usize) -> (bool,Option<Vec<Polynomial<LargeField>>>){
        //log::info!("Checking evaluations on points :{:?}, eval_points: {:?}", eval_points, polys_vector);
        let inverse_vandermonde = Self::inverse_vandermonde(Self::vandermonde_matrix(eval_points[0..degree].to_vec()));
        let polys = polys_vector.into_par_iter().map(|points| {
            let coeffs = Self::matrix_vector_multiply(&inverse_vandermonde, &points[0..degree].to_vec());
            let polynomial = Polynomial::new(&coeffs);
            let all_points_match =  eval_points[degree..].iter().zip(points[degree..].iter()).map(|(eval_point, share)|{
                return polynomial.evaluate(eval_point) == *share;
            }).fold(true, |acc,x| acc && x);
    
            if all_points_match{
                Some(polynomial)
            }
            else{
                None
            }
        }).fold(|| Vec::new(), |mut acc_vec, vec: Option<Polynomial<LargeField>>|{
            acc_vec.push(vec);
            acc_vec
        }).reduce(|| Vec::new(), |mut acc_vec, vec: Vec<Option<Polynomial<LargeField>>>|{
            acc_vec.extend(vec);
            acc_vec
        });
        let all_polys_positive = polys.par_iter().all(|poly| poly.is_some());
        if all_polys_positive{
            let polys_vec = polys.into_iter().map(|x| x.unwrap()).collect();
            (true, Some(polys_vec))
        }
        else{
            (false, None)
        }
    }
}