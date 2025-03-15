use std::vec::Vec;
use crate::context::Context;
use std::collections::HashMap;
use types::{Msg, ProtMsg, Replica, Val, WrapperMsg};
use itertools::{any, Itertools};
use std::clone::Clone;
use std::iter::zip;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use rayon::prelude::*;
use crate::math::{evaluate_polynomial_from_coefficients_at_position, interpolate_polynomial};

pub(crate) fn compute_polynomial_coefficients(shares_vec: &Vec<Vec<FieldElement<Stark252PrimeField>>>, alpha_i: &Vec<FieldElement<Stark252PrimeField>>) -> Vec<Vec<FieldElement<Stark252PrimeField>>> {
    assert!(shares_vec.len() > 0);
    assert!(shares_vec.iter().all(|v| v.len() == shares_vec[0].len()), "All vectors must have the same length");
    
    let mut f_vec_coefficients: Vec<Vec<FieldElement<Stark252PrimeField>>> = Vec::new();
    for i in 0..shares_vec[0].len() {
        let shares_value = shares_vec.iter().map(|v| v[i]).collect_vec();
        let shares_eval_points = alpha_i.clone();
        let shares = zip(shares_eval_points, shares_value).collect_vec();
        let coefficients = interpolate_polynomial(shares);
        f_vec_coefficients.push(coefficients);
    }
    f_vec_coefficients
}

impl Context {

    pub async fn start_compression(self: &mut Context) {
        // TODO: get from input channel

        // [[x^(1)_1, x^(1)_2, ..., x^(1)_k)], [x^(2)_1, x^(2)_2, ..., x^(2)_k], ..., [x^(N)_1, x^(N)_2, x^(N)_3, ..., x^(N)_k]]
        self.x_vec_shares = Vec::new();
        assert_eq!(self.x_vec_shares.len(), self.N);
        assert!(self.x_vec_shares.windows(2).all(|w| w[0].len() == w[1].len()));

        // [[y^(1)_1, y^(1)_2, ..., y^(1)_k)], [y^(2)_1, y^(2)_2, ..., y^(2)_k], ..., [y^(N)_1, y^(N)_2, y^(N)_3, ..., y^(N)_k]]
        self.y_vec_shares = Vec::new();
        assert_eq!(self.y_vec_shares.len(), self.N);
        assert!(self.y_vec_shares.windows(2).all(|w| w[0].len() == w[1].len()));
        assert_eq!(self.x_vec_shares[0].len(), self.y_vec_shares[0].len());

        // [alpha_1, alpha_2, ..., alpha_{N-1}, alpha_{N}, alpha_{N+1}, ..., alpha_{2N-1}]
        self.alpha_i = Vec::new();
        assert_eq!(self.alpha_i.len(), 2 * self.N - 1);

        // [r_1, r_2, ..., r_{N-1}]
        self.r = Vec::new();
        assert_eq!(self.r.len(), self.N - 1);

        // [o_1, o_2, ..., o_{(N-1)/2}]
        self.o = Vec::new();
        assert_eq!(self.o.len(), (self.N - 1) / 2);

        // [
        //     [... coefficients for polynomial defined by: (alpha_1, x^(1)_1), (alpha_2, x^(2)_1), ..., (alpha_N, x^(N)_1)) ...],
        //     [... coefficients for polynomial defined by: (alpha_1, x^(1)_1), (alpha_2, x^(2)_1), ..., (alpha_N, x^(N)_2)) ...],
        //      ...
        //     [... coefficients for polynomial defined by: (alpha_1, x^(1)_k), (alpha_2, x^(2)_k), ..., (alpha_N, x^(N)_k)) ...]
        // ]
        // =
        // [ f_1, f_2, ..., f_k ]
        self.f_vec_coefficient_shares = compute_polynomial_coefficients(&self.x_vec_shares, &self.alpha_i[0..self.N].to_vec());

        // [
        //     [... coefficients for polynomial defined by: (alpha_1, y^(1)_1), (alpha_2, y^(2)_1), ..., (alpha_N, y^(N)_1)) ...],
        //     [... coefficients for polynomial defined by: (alpha_1, y^(1)_1), (alpha_2, y^(2)_1), ..., (alpha_N, y^(N)_2)) ...],
        //      ...
        //     [... coefficients for polynomial defined by: (alpha_1, y^(1)_k), (alpha_2, y^(2)_k), ..., (alpha_N, y^(N)_k)) ...]
        // ]
        // =
        // [ g_1, g_2, ..., g_k ]
        self.g_vec_coefficient_shares = compute_polynomial_coefficients(&self.y_vec_shares, &self.alpha_i[0..self.N].to_vec());

        // {
        //    N+1 => [f_1(alpha_{N+1}), f_2(alpha_{N+1}), ..., f_k(alpha_{N+1})]
        //    N+2 => [f_1(alpha_{N+2}), f_2(alpha_{N+2}), ..., f_k(alpha_{N+2})]
        //    ...
        //    2N-1 => [f_1(alpha_{2N-1}), f_2(alpha_{2N-1}), ..., f_k(alpha_{2N-1})]
        // }
        let mut f_alpha: HashMap<usize, Vec<FieldElement<Stark252PrimeField>>> = HashMap::new();

        // {
        //    N+1 => [g_1(alpha_{N+1}), g_2(alpha_{N+1}), ..., g_k(alpha_{N+1})]
        //    N+2 => [g_1(alpha_{N+2}), g_2(alpha_{N+2}), ..., g_k(alpha_{N+2})]
        //    ...
        //    2N-1 => [g_1(alpha_{2N-1}), g_2(alpha_{2N-1}), ..., g_k(alpha_{2N-1})]
        // }
        let mut g_alpha: HashMap<usize, Vec<FieldElement<Stark252PrimeField>>> = HashMap::new();

        for i in self.N..2*self.N {
            let eval_point = self.alpha_i[i];
            
            let mut eval_f_vec_for_alpha_i: Vec<FieldElement<Stark252PrimeField>> = Vec::new();
            for pol_idx in 0..self.f_vec_coefficient_shares.len() {
                let value = evaluate_polynomial_from_coefficients_at_position(self.f_vec_coefficient_shares[pol_idx].clone(), eval_point);
                eval_f_vec_for_alpha_i.push(value);
            }
            f_alpha.insert(i, eval_f_vec_for_alpha_i.clone());

            let mut eval_g_vec_for_alpha_i: Vec<FieldElement<Stark252PrimeField>> = Vec::new();
            for pol_idx in 0..self.g_vec_coefficient_shares.len() {
                let value = evaluate_polynomial_from_coefficients_at_position(self.f_vec_coefficient_shares[pol_idx].clone(), eval_point);
                eval_g_vec_for_alpha_i.push(value);
            }
            g_alpha.insert(i, eval_g_vec_for_alpha_i.clone());

        }

        // Preparing inputs for Pi_ExMult

        // [
        //     [a^(1)_1, a^(1)_2, ..., a^(1)_k)],
        //     [a^(2)_1, a^(2)_2, ..., a^(2)_k],
        //     ...,
        //     [a^(2N-1)_1, a^(2N-1)_2, a^(2N-1)_3, ..., a^(2N-1)_k]
        // ]
        let mut a_vec_shares: Vec<Vec<Option<FieldElement<Stark252PrimeField>>>> = Vec::new();
        for i in 1..=2*self.N-1 { // self.N..=2*self.N-1
            a_vec_shares.push(
                f_alpha.get(&(i)).unwrap().clone().iter().map(|x| Some(*x)).collect_vec()
            );
        }
        assert_eq!(a_vec_shares.len(), 2*self.N-1); // self.N
        assert!(a_vec_shares.windows(2).all(|w| w[0].len() == w[1].len()));

        // [
        //     [b^(1)_1, a^(1)_2, ..., b^(1)_k)],
        //     [b^(2)_1, b^(2)_2, ..., b^(2)_k],
        //     ...,
        //     [b^(2N-1)_1, b^(2N-1)_2, b^(2N-1)_3, ..., b^(2N-1)_k]
        // ]
        let mut b_vec_shares: Vec<Vec<Option<FieldElement<Stark252PrimeField>>>> = Vec::new();
        for i in 1..=2*self.N-1 { // self.N..=2*self.N-1
            b_vec_shares.push(
                g_alpha.get(&(i)).unwrap().clone().iter().map(|x| Some(*x)).collect_vec()
            );
        }
        assert_eq!(b_vec_shares.len(), 2*self.N-1); // self.N
        assert!(b_vec_shares.windows(2).all(|w| w[0].len() == w[1].len()));
        assert_eq!(a_vec_shares[0].len(), b_vec_shares[0].len());

        // [r^(1), r^(2), ..., r^(N)]
        let r_shares: Vec<Option<FieldElement<Stark252PrimeField>>> = Vec::new();
        assert_eq!(r_shares.len(), self.N);

        // [o^(1), o^(2), ..., o^(N/2)]
        let o_shares: Vec<FieldElement<Stark252PrimeField>> = Vec::new();
        assert_eq!(o_shares.len(), self.N / 2);

        // [
        //      Some([c_1, c_2, ..., c_{2t+1}]),
        //      Some([c_1, c_2, ..., c_{2t+1}]]),
        //      ...,
        //      Some([c_1, c_2, ..., c_{2t+1}]])
        // ]
        // ^-- contains N/(2t+1) many Option<Vec<...>>
        let z_options: Vec<Option<Vec<FieldElement<Stark252PrimeField>>>> = self.PiExMult(a_vec_shares, b_vec_shares, r_shares, o_shares);
        if any(&z_options, |x| x.is_none()) {
            // self.terminate() // FAIL // TODO
            return
        }
        let z: Vec<Vec<FieldElement<Stark252PrimeField>>> = z_options.iter().map(|x| x.clone().unwrap()).collect_vec();
        assert_eq!(z.len(), self.N); // self.N/(2*self.num_faults+1)
        self.on_ex_mult_terminating(z.clone());
    }

    pub fn PiExMult(self: &mut Context,
        a_vec_shares: Vec<Vec<Option<FieldElement<Stark252PrimeField>>>>,
        b_vec_shares: Vec<Vec<Option<FieldElement<Stark252PrimeField>>>>,
        r_shares: Vec<Option<FieldElement<Stark252PrimeField>>>,
        o_shares: Vec<FieldElement<Stark252PrimeField>>,
    ) -> Vec<Option<Vec<FieldElement<Stark252PrimeField>>>> {
        Vec::new() // Replace with actual call
    }

    pub async fn on_ex_mult_terminating(self: &mut Context, z_i_shares: Vec<Vec<FieldElement<Stark252PrimeField>>>) {
        assert_eq!(z_i_shares.len(), self.N); // self.N / (self.num_faults + 1)
        assert_eq!(z_i_shares[0].len(), 2*self.num_faults + 1);
        assert!(z_i_shares.windows(2).all(|w| w[0].len() == w[1].len()));

        // flatten z_i_shares
        let z_i_shares_flat: Vec<FieldElement<Stark252PrimeField>> = z_i_shares.into_iter().flatten().collect_vec();
        assert_eq!(z_i_shares_flat.len(), self.N);

        // compute coefficients of h(.) from points [(alpha_1, z_1), (alpha_1, z_1), ..., (alpha_{2N-1}, z_{2N-1})]
        assert_eq!(self.alpha_i.len(), z_i_shares_flat.len());
        assert_eq!(self.alpha_i.len(), 2*self.N - 1);
        let shares: Vec<(FieldElement<Stark252PrimeField>, FieldElement<Stark252PrimeField>)> = zip(
            self.alpha_i.clone(), z_i_shares_flat.clone()).collect_vec();
        let h_coefficients = interpolate_polynomial(shares);

        let r: FieldElement<Stark252PrimeField> = self.PiCoin();

        if any(&self.alpha_i, |alpha| *alpha == r) {
            // self.terminate() // FAIL // TODO
        } else {
            let mut f: Vec<FieldElement<Stark252PrimeField>> = Vec::new();
            let mut g: Vec<FieldElement<Stark252PrimeField>> = Vec::new();
            let h:  FieldElement<Stark252PrimeField> = evaluate_polynomial_from_coefficients_at_position(h_coefficients.clone(), r);
            assert_eq!(self.f_vec_coefficient_shares.len(), self.g_vec_coefficient_shares.len());
            for i in 0..self.f_vec_coefficient_shares.len() {
                let f_val = evaluate_polynomial_from_coefficients_at_position(self.f_vec_coefficient_shares[i].clone(), r);
                let g_val = evaluate_polynomial_from_coefficients_at_position(self.g_vec_coefficient_shares[i].clone(), r);
                f.push(f_val);
                g.push(g_val);
            }

            // self.terminate() // f, g, h // TODO
        }

    }
    
    pub fn PiCoin(self: &mut Context) -> FieldElement<Stark252PrimeField> {
        return FieldElement::zero(); // TODO: call actual implementation!
    }

}