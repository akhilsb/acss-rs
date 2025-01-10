use std::vec::Vec;
use crate::context::Context;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use types::{Msg, ProtMsg, Replica, WrapperMsg};
use std::convert::TryInto;
use itertools::Itertools;
use byteorder::{ByteOrder, LittleEndian};

/// Groups elements from a vector into subgroups of a specified size.
///
/// This function takes a vector of i64 integers and groups them into subvectors
/// of size `group_size + 1`. If there are not enough elements to complete the
/// last group, the last element is repeated to fill the group.
///
/// # Arguments
///
/// * `elements` - A vector of i64 integers to be grouped.
/// * `group_size` - An u64 integer specifying the size of each group.
///
/// # Returns
///
/// A vector of vectors of i64 integers, where each inner vector represents a group.
///
/// # Examples
///
/// ```
/// use publicweak::protocol::group_elements;
/// let elements = vec![1, 2, 3, 4, 5, 6, 7];
/// let group_size = 2;
/// let result = group_elements(elements, group_size);
/// assert_eq!(result, vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 7, 7]]);
/// ```
///
/// # Notes
///
/// - If `elements` is empty, an empty vector will be returned.
/// - If `group_size` is 0, it will be interpreted as maximum group size.
pub fn group_elements(elements: Vec<Option<i64>>, group_size: u64) -> Vec<Vec<Option<i64>>> {
    let mut result = Vec::new();
    let mut current_group = Vec::new();
    let actual_group_size = group_size as usize;

    for (index, &element) in elements.iter().enumerate() {
        current_group.push(element);

        if current_group.len() == actual_group_size || index == elements.len() - 1 {
            while current_group.len() < actual_group_size {
                current_group.push(*current_group.last().unwrap_or(&element));
            }
            result.push(current_group);
            current_group = Vec::new();
        }
    }
    result
}

/// Evaluates a polynomial at a given point using modular arithmetic.
///
/// # Arguments
///
/// * `coefficients` - A vector of i64 integers representing the coefficients of the polynomial,
///                    from the lowest degree term to the highest.
/// * `evaluation_point` - The point at which to evaluate the polynomial.
/// * `modulus` - Result is modulus this value.
///
/// # Returns
///
/// The result of the polynomial evaluation modulo the given modulus.
///
/// # Example
///
/// ```
/// use publicweak::protocol::evaluate_polynomial_from_coefficients_at_position;
/// let coefficients = vec![1, 2, 3];  // Represents the polynomial 1 + 2x + 3x^2
/// let evaluation_point = 15;
/// let modulus = 17;
/// let result = evaluate_polynomial_from_coefficients_at_position(coefficients, evaluation_point, modulus);
/// assert_eq!(result, 9);  // (1 + 2*5 + 3*5^2) % 1000 = 86
/// ```
pub fn evaluate_polynomial_from_coefficients_at_position(coefficients: Vec<i64>, evaluation_point: i64, modulus: i64) -> i64 {
    let mut result = 0;
    let mut x_power = 1;

    for coefficient in coefficients {
        result = (result + coefficient * x_power).rem_euclid(modulus);
        x_power = (x_power * evaluation_point).rem_euclid(modulus);
    }

    result
}

/// Checks if the interpolated polynomial from shares is at most of degree t in a finite field.
///
/// # Arguments
///
/// * `degree` - The maximum allowed degree of the polynomial.
/// * `shares` - A vector of (x, y) coordinates representing the shares.
/// * `modulus` - The modulus for the finite field.
///
/// # Returns
///
/// `true` if the interpolated polynomial is at most of degree t, `false` otherwise.
pub fn is_degree_t_consistent(degree: i64, shares: Vec<(i64, i64)>, modulus: i64) -> bool {
    let coeffs = interpolate_polynomial(shares, modulus);
    coeffs.len() as i64 - 1 <= degree
}

/// Computes the modular multiplicative inverse using the extended Euclidean algorithm.
fn mod_inverse(a: i64, m: i64) -> i64 {
    let (mut old_r, mut r) = (a, m);
    let (mut old_s, mut s) = (1, 0);

    while r != 0 {
        let quotient = old_r / r;
        let temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;

        let temp_s = s;
        s = old_s - quotient * s;
        old_s = temp_s;
    }

    old_s.rem_euclid(m)
}

/// Interpolates a polynomial by solving a system of linear equations in a finite field.
///
/// # Arguments
///
/// * `shares` - A vector of (x, y) coordinates representing the shares.
/// * `modulus` - The modulus for the finite field.
///
/// # Returns
///
/// A vector of coefficients of the interpolated polynomial, from lowest to highest degree.
pub fn interpolate_polynomial(shares: Vec<(i64, i64)>, modulus: i64) -> Vec<i64> {
    let n = shares.len();
    let mut matrix = vec![vec![0i64; n + 1]; n];

    // Populate the matrix
    for (i, &(x, y)) in shares.iter().enumerate() {
        let mut x_power = 1i64;
        for j in 0..n {
            matrix[i][j] = x_power.rem_euclid(modulus);
            x_power = (x_power * x).rem_euclid(modulus);
        }
        matrix[i][n] = y.rem_euclid(modulus);
    }

    // Perform Gaussian elimination
    for i in 0..n {
        // Find pivot
        let mut pivot_row = i;
        for j in i + 1..n {
            if matrix[j][i] != 0 {
                pivot_row = j;
                break;
            }
        }

        // Swap rows if necessary
        if pivot_row != i {
            matrix.swap(i, pivot_row);
        }

        let pivot = matrix[i][i];
        let pivot_inv = mod_inverse(pivot, modulus);

        // Normalize pivot row
        for j in i..=n {
            matrix[i][j] = (matrix[i][j] * pivot_inv).rem_euclid(modulus);
        }

        // Eliminate in other rows
        for k in 0..n {
            if k != i {
                let factor = matrix[k][i];
                for j in i..=n {
                    matrix[k][j] = (matrix[k][j] - factor * matrix[i][j]).rem_euclid(modulus);
                }
            }
        }
    }

    // Extract solution
    let mut result: Vec<i64> = matrix.iter().map(|row| row[n]).collect();

    // Remove leading zero coefficients
    while result.len() > 1 && result.last() == Some(&0) {
        result.pop();
    }

    result
}

/// Generates a vandermonde matrix with the specified number of rows and columns.
/// The values are computed over a finite field defined by the provided modulus.
///
/// # Arguments
///
/// * `rows` - The number of rows in the matrix.
/// * `cols` - The number of columns in the matrix.
/// * `modulus` - The modulus for finite field computations.
///
/// # Returns
///
/// A 2D vector representing the vandermonde matrix.
fn generate_vandermonde_matrix(rows: usize, cols: usize, modulus: i64) -> Vec<Vec<i64>> {
    (0..rows)
        .map(|i| {
            (0..cols)
                .map(|j| {
                    let base = i as i64 + 1; // Using row index + 1 as the base.
                    base.pow(j as u32).rem_euclid(modulus)
                })
                .collect()
        })
        .collect()
}

/// Multiplies a vector by a matrix and returns the result as a new vector.
/// Computations are done over a finite field defined by the modulus.
///
/// # Arguments
///
/// * `vector` - The vector to multiply.
/// * `matrix` - The matrix to be multiplied by.
/// * `modulus` - The modulus for finite field computations.
///
/// # Returns
///
/// A vector that is the result of the multiplication.
fn multiply_vector_matrix(vector: &Vec<i64>, matrix: &Vec<Vec<i64>>, modulus: i64) -> Vec<i64> {
    matrix.iter().map(|row| {
        row.iter().enumerate().fold(0, |acc, (i, &val)| {
            (acc + val * vector[i]) % modulus
        })
    }).collect()
}

/// Computes the inner product of two vectors.
/// The computation is carried out over a finite field defined by the modulus.
///
/// # Arguments
///
/// * `vec_a` - The first vector.
/// * `vec_b` - The second vector.
/// * `modulus` - The modulus for finite field computations.
///
/// # Returns
///
/// The scalar result of the inner product.
fn inner_product(vec_a: &Vec<i64>, vec_b: &Vec<i64>, modulus: i64) -> i64 {
    vec_a.iter().zip(vec_b.iter())
        .fold(0, |acc, (&a, &b)| acc + a * b % modulus)
}

fn serialize_option_i64_to_vec_u8(num: Option<i64>) -> Vec<u8> {
    let mut buf = Vec::new();
    match num {
        None => {
            buf.push(0); // Flag for None
        }
        Some(val) => {
            buf.push(1); // Flag for Some
            buf.extend_from_slice(&[0u8; 8]); // Extend buffer to fit an i64
            LittleEndian::write_i64(&mut buf[1..], val);
        }
    }
    buf
}

fn deserialize_vec_u8_to_option_i64(bytes: Vec<u8>) -> Option<i64> {
    if bytes.is_empty() {
        return None; // Early return if input is empty
    }

    match bytes[0] {
        0 => None,
        1 => {
            assert!(bytes.len() == 9, "Expected length for Some(i64) is 9 bytes");
            Some(LittleEndian::read_i64(&bytes[1..]))
        },
        _ => panic!("Invalid flag byte"),
    }
}

fn contains_only_some(values: &Vec<Option<i64>>) -> bool {
    values.iter().all(|value| value.is_some())
}

fn convert_to_vec_i64(values: Vec<Option<i64>>) -> Vec<i64> {
    values.into_iter().filter_map(|x| x).collect()
}

impl Context {

    pub async fn start_multiplication(self: &mut Context) {
        // Inputs to protocol; need to change for actual implementation:
        let evaluation_points: Option<i64> = None;

        // TODO: the following blocks only generate some garbage values for testing purposes -> need to get the actual values from somewhere?
        self.shares_a = vec![Some(1), Some(2), Some(3), Some(4), Some(5), Some(6), Some(7), Some(8), Some(9), Some(0)];
        self.shares_b = vec![Some(0), Some(9), Some(8), Some(7), Some(6), Some(5), Some(4), Some(3), Some(2), Some(1)];
        assert_eq!(self.shares_a.len(), self.shares_b.len());

        self.shares_r = vec![Some(4), Some(4), Some(4), Some(4), Some(4), Some(4), Some(4), Some(4), Some(4), Some(4)];

        self.o_shares_for_group = Vec::with_capacity(self.num_nodes / (2 * self.num_faults + 1));
        for _ in 0..(self.num_nodes / (2 * self.num_faults + 1)) {
            let mut o_shares: Vec<Option<i64>> = Vec::with_capacity(self.num_faults);
            for _ in 0..self.num_faults {
                o_shares.push(Some(3));
            }
            assert!(o_shares.len() == self.num_faults);
            self.o_shares_for_group.push(o_shares);
        }

        // Partition inputs into groups
        let num_groups: usize = self.num_nodes / (2 * self.num_faults + 1);
        let group_size: usize = self.shares_a.len().div_ceil(num_groups);

        let grouped_elements_a: Vec<Vec<Option<i64>>> = group_elements(self.shares_a.clone(), group_size as u64);
        let grouped_elements_b: Vec<Vec<Option<i64>>> = group_elements(self.shares_b.clone(), group_size as u64);
        assert_eq!(grouped_elements_a.len(), grouped_elements_b.len());
        assert_eq!(grouped_elements_a.len(), (self.num_faults + 1));

        // Expand o_shares for each group
        let vdm_matrix = generate_vandermonde_matrix(self.num_nodes, self.num_faults, self.modulus);
        for o_shares in self.o_shares_for_group.clone() {
            let expanded_o_shares = multiply_vector_matrix(&(o_shares.clone().into_iter().filter_map(|x| x).collect()), &vdm_matrix, self.modulus);
            self.expanded_o_shares_for_group.push(expanded_o_shares);
        }

        // Define f(X)
        let num_zs = 2 * self.num_faults + 1;
        let mut zs = Vec::with_capacity(num_zs);
        for i in 0..num_zs {
            if contains_only_some(&grouped_elements_a[i]) && contains_only_some(&grouped_elements_b[i]) && self.shares_r[i].is_some() {
                let grouped_elements_a_values = convert_to_vec_i64(grouped_elements_a[i].clone());
                let grouped_elements_b_values = convert_to_vec_i64(grouped_elements_b[i].clone());
                let z = inner_product(&grouped_elements_a_values, &grouped_elements_b_values, self.modulus) + self.shares_r[i].unwrap();
                zs[i] = Some(z);
            } else {
                zs[i] = None;
            }
        }

        // Compute Shares on evaluations on f(x) and send to parties for reconstruction
        for i in 0..self.num_nodes {
            let evaluation_point_P_i = self.evaluation_point[&i];
            // Compute my share of f(evaluation_point_P_i) and send it to party P_i
            // TODO: self.expanded_o_shares_for_group[0][i] cannot be right? Probably misunderstanding the protocol here?
            let mut share: Option<i64> = None;
            if !zs.iter().any(|x| x.is_none()) {
                share = None
            } else {
                share = Some(
                    self.expanded_o_shares_for_group[0][i].clone()
                        + evaluate_polynomial_from_coefficients_at_position(zs.clone().into_iter().filter_map(|x| x).collect(), evaluation_point_P_i, self.modulus)
                );
            }

            // send share to P_i
            let replica = i as usize;
            let mut content = serialize_option_i64_to_vec_u8(share);
            let msg = Msg {
                content: content,
                origin: self.myid
            };
            let distribute_sharing_of_share_msg =  ProtMsg::FxShareMessage(msg.clone(), self.myid);
            let sec_key_for_replica = self.sec_key_map[&(replica)].clone();
            let wrapper_msg = WrapperMsg::new(distribute_sharing_of_share_msg.clone(), self.myid, &sec_key_for_replica.as_slice());
            self.send(replica, wrapper_msg).await;
        }
    }

    pub async fn handle_fx_share_message(self: &mut Context, msg:Msg) {
        let evaluation_point = self.evaluation_point[&msg.origin];
        let content = msg.content;
        let deserialized_content = deserialize_vec_u8_to_option_i64(content);
        let share: Option<i64> = deserialized_content;

        self.received_fx_share_messages.insert(evaluation_point, share);

        if self.received_fx_share_messages.len() >= 2 * self.num_faults + 1 {
            let mut contains_none = false;
            for (key, value) in &self.received_fx_share_messages {
                    if value.is_none() {
                        contains_none = true;
                    }
            }

            let mut Zi: Option<i64> = None;
            if !contains_none {
                let mut result_vec: Vec<(i64, i64)> = Vec::new();
                for (key, value) in self.received_fx_share_messages.clone() {
                        result_vec.push((key, value.unwrap()));
                }
                let interpolated_coefficients = interpolate_polynomial(result_vec, self.modulus);

                if interpolated_coefficients.len() <= 2 * self.num_faults {
                    Zi = Some(evaluate_polynomial_from_coefficients_at_position(interpolated_coefficients, self.evaluation_point[&self.myid], self.modulus));
                }
            } else {
                Zi = None;
            }

            // send Zi to all parties as ReconstructedPointMessage
            for i in 0..self.num_nodes {
                let replica = i as usize;
                let mut content = serialize_option_i64_to_vec_u8(share);
                let msg = Msg {
                    content: content,
                    origin: self.myid
                };
                let reconstructed_point_msg =  ProtMsg::ReconstructedPointMessage(msg.clone(), self.myid);
                let sec_key_for_replica = self.sec_key_map[&(replica)].clone();
                let wrapper_msg = WrapperMsg::new(reconstructed_point_msg.clone(), self.myid, &sec_key_for_replica.as_slice());
                self.send(replica, wrapper_msg).await;
            }

        }

    }

    pub async fn handle_reconstructed_point_message(self: &mut Context, msg:Msg) {

    }

    pub async fn handle_hash_broadcast_message(self: &mut Context, msg:Msg) {

    }
}