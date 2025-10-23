use consensus::{inverse_vandermonde, matrix_vector_multiply, vandermonde_matrix, LargeField};
use lambdaworks_math::{polynomial::Polynomial, unsigned_integer::element::UnsignedInteger};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};

use crate::Context;

impl Context{
    // Takes a group of degree_x+1 degree-{y_degree} univariate polynomials and generates n degree-{y_degree} polynomials 
    // Signifying a bivariate polynomial of degree-{x_degree,y_degree} 
    pub fn gen_bivariate_polynomials(
        grouped_polynomials: &mut Vec<Vec<Vec<LargeField>>>,
        y_degree: usize,
        evaluation_points_expansion: Vec<LargeField>
    ){
        // Each element in grouped_polynomials is a group of univariate polynomials to be converted to a bivariate polynomial
        // So here, create a Vandermonde matrix first
        let mut evaluation_points = Vec::new();
        evaluation_points.push(LargeField::new(UnsignedInteger::from(0u64)));
        for i in 0..y_degree{
            evaluation_points.push(LargeField::new(UnsignedInteger::from((i+1) as u64)));
        }
        
        // Generate vandermonde matrix
        let vandermonde = vandermonde_matrix(evaluation_points.clone());
        let inverse_vandermonde = inverse_vandermonde(vandermonde);

        let _ = grouped_polynomials.par_iter_mut().map(|bv_group|{
            // Each group is of size degree+1
            let num_points_in_each_poly = bv_group[0].len();
            let mut horizontal_polynomials = vec![vec![]; num_points_in_each_poly];
            for poly in bv_group.iter(){
                for (i,eval) in poly.iter().enumerate(){
                    horizontal_polynomials[i].push(eval.clone());
                }
            }
            // Now each horizontal_polynomials[i] is a set of evaluations of a univariate polynomial
            let horizontal_coefficients : Vec<Polynomial<LargeField>> = horizontal_polynomials.into_par_iter().map(|evals|{
                let coefficients = matrix_vector_multiply(&inverse_vandermonde, &evals);
                return Polynomial::new(&coefficients);
            }).collect();

            let mut y_append_polys = vec![vec![]; evaluation_points_expansion.len()];
            let final_evaluations: Vec<Vec<LargeField>> = horizontal_coefficients.par_iter().map(|poly|{
                let evaluations = poly.evaluate_slice(&evaluation_points_expansion.as_slice());
                return evaluations;
            }).collect();
            for evaluation_poly in final_evaluations{
                for (i,eval) in evaluation_poly.iter().enumerate(){
                    y_append_polys[i].push(eval.clone());
                }
            }
            bv_group.append(&mut y_append_polys);
        });
    }
}