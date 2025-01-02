use std::vec::Vec;
use crate::context::Context;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use types::{Msg, ProtMsg, Replica, WrapperMsg};
use std::convert::TryInto;
use itertools::Itertools;

// use types::{Msg, ProtMsg};
// use std::collections::{HashSet, HashMap};
// use super::Context;
// use bincode::Error;
// use std::collections::HashMap;
// use rand::thread_rng;
// use std::io::{Read, Write};
// use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
// use std::collections::HashMap;


/// Serializes a HashMap<i64, Option<Vec<i64>>> to a Vec<u8>.
///
/// # Arguments
///
/// * `results` - A reference to the HashMap to be serialized.
///
/// # Returns
///
/// A `Result` containing the serialized Vec<u8> if successful, or a `bincode::Error` if serialization fails.
///
/// # Example
///
/// ```
/// use publicweak::protocol::serialize_hashmap_results;
/// let mut results = HashMap::new();
/// results.insert(1, Some(vec![10, 20, 30]));
/// results.insert(2, None);
/// results.insert(3, Some(vec![40, 50]));
///
/// match serialize_hashmap_results(&results) {
///     Ok(bytes) => println!("Serialized bytes: {:?}", bytes),
///     Err(e) => eprintln!("Serialization error: {}", e),
/// }
/// ```
pub fn serialize_hashmap_results(results: &HashMap<i64, Option<Vec<i64>>>) -> Result<Vec<u8>, bincode::Error> {
    // This uses old version 1 bincode serialization
    bincode::serialize(results)
}

/// Deserializes a Vec<u8> into a HashMap<i64, Option<Vec<i64>>>.
///
/// # Arguments
///
/// * `bytes` - A slice of u8 containing the serialized data to be deserialized.
///
/// # Returns
///
/// A `Result` containing the deserialized HashMap if successful, or a `bincode::Error` if deserialization fails.
///
/// # Example
///
/// ```
/// let bytes = // ... some serialized data ...
///
/// match deserialize_hashmap_results(&bytes) {
///     Ok(results) => {
///         println!("Deserialized results:");
///         for (key, value) in results.iter() {
///             println!("{}: {:?}", key, value);
///         }
///     },
///     Err(e) => eprintln!("Deserialization error: {}", e),
/// }
/// ```
pub fn deserialize_hashmap_results(bytes: &[u8]) -> Result<HashMap<i64, Option<Vec<i64>>>, bincode::Error> {
    // This uses old version 1 bincode serialization
    bincode::deserialize(bytes)
}

fn serialize_i64_tuple(tuple: (i64, i64)) -> Vec<u8> {
    let mut result = Vec::new();

    // First, serialize the length of the tuple
    result.extend_from_slice(&(2u32).to_le_bytes());

    // Then serialize each i64 value
    result.extend_from_slice(&tuple.0.to_le_bytes());
    result.extend_from_slice(&tuple.1.to_le_bytes());

    result
}

fn deserialize_i64_tuple(bytes: &[u8]) -> (i64, i64) {
    if bytes.len() < 4 { // At least 4 bytes for the length
        return (0, 0);
    }

    // Deserialize the length
    // let len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let len = 2;

    // Check if we have enough bytes for the specified length
    if bytes.len() < 4 + (len * 8) {
        return (0, 0);
    }

    let mut result = Vec::with_capacity(len);

    // Deserialize each i64 value
    for i in 0..len {
        let start = 4 + (i * 8);
        let end = start + 8;
        let value = i64::from_le_bytes(bytes[start..end].try_into().unwrap());
        result.push(value);
    }

    let (x, y) = result.into_iter().collect_tuple().unwrap();
    (x, y)
    // Some(result)
}


fn serialize_i64_opti64_tuple(tuple: (i64, Option<i64>)) -> Vec<u8> {
    let mut result = Vec::new();

    // Serialize the first i64
    result.extend_from_slice(&tuple.0.to_le_bytes());

    // Serialize the Option<i64>
    match tuple.1 {
        Some(value) => {
            result.push(1); // Indicator for Some
            result.extend_from_slice(&value.to_le_bytes());
        },
        None => {
            result.push(0); // Indicator for None
        },
    }

    result
}

fn deserialize_i64_opti64_tuple(bytes: &[u8]) -> Option<(i64, Option<i64>)> {
    if bytes.len() < 9 { // At least 8 bytes for i64 and 1 byte for Option indicator
        return None;
    }

    let first = i64::from_le_bytes(bytes[0..8].try_into().unwrap());

    let second = match bytes[8] {
        0 => None,
        1 if bytes.len() >= 17 => {
            Some(i64::from_le_bytes(bytes[9..17].try_into().unwrap()))
        },
        _ => return None, // Invalid format
    };

    Some((first, second))
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

impl Context {

    pub async fn start_reconstruction(self: &mut Context) {
        assert_eq!(self.num_nodes, self.sharings.len());

        // TODO: change how the party gets the sharings;
        // TODO: for now we just initialize some random values as placeholders,
        // TODO: but need to replace this with actual sharings!
        self.sharings = (0..self.num_nodes).map(|_| Some(7)).collect();

        // Group the N shares into groups where each group contains t+1 shares.
        self.grouped_shares = group_elements(self.sharings.clone(), (self.num_faults + 1) as u64);

        for (group_index, group_shares) in self.grouped_shares.clone().iter().enumerate() {
            // println!("Group Index: {}, Group Shares: {}", group_index, group_shares);
            // println!("Group Index: {}, Group Shares: {}", group_index, group_shares.iter().map(|&x| x.to_string()).collect::<Vec<String>>().join(", "));

            if ! self.grouped_shares[group_index].clone().iter().all(|x| x.is_some()) {
                // one of the shares is None --> cannot continue with this group
                continue
            }

            for replica_id in 1..=self.num_nodes { // TODO: ? 0..self.num_nodes-1 or 1..=self.num_nodes
                println!("Replica {}", replica_id);
                let grouped_shares_unwrapped: Vec<i64> = self.grouped_shares[group_index].clone().iter().map(|&x| x.unwrap()).collect();
                let replica: Replica = replica_id;
                let sharing_of_share: i64 = evaluate_polynomial_from_coefficients_at_position(
                    grouped_shares_unwrapped, // self.grouped_shares[group_index].clone(),
                    self.evaluation_point[&replica],
                    self.modulus
                );

                let content: (i64, i64) = (group_index as i64, sharing_of_share);
                let serialized_content = serialize_i64_tuple(content);
                let msg = Msg {
                    content: serialized_content,
                    origin: self.myid
                };
                let distribute_sharing_of_share_msg =  ProtMsg::DistributeSharingOfShare(msg.clone(), self.myid);

                if replica_id == self.myid {
                    // directly call received message handler
                    self.handle_distribute_sharing_of_share_message(msg).await;
                } else {
                    // send message over network
                    let sec_key_for_replica = self.sec_key_map[&(replica as usize)].clone();
                    let wrapper_msg = WrapperMsg::new(distribute_sharing_of_share_msg.clone(), self.myid, &sec_key_for_replica.as_slice());
                    self.send(replica, wrapper_msg).await;
                    // for (replica, sec_key) in self.sec_key_map.clone().into_iter() {
                    //     if replica == replica_id {
                    //         let wrapper_msg = WrapperMsg::new(distribute_sharing_of_share_msg.clone(), self.myid, &sec_key.as_slice());
                    //         self.send(replica, wrapper_msg).await;
                    //     }
                    // }
                }

            }

        }
    }

    pub async fn handle_distribute_sharing_of_share_message(self: &mut Context, msg:Msg) {
        // let from = msg.origin;
        let share_evaluation_point = self.evaluation_point[&msg.origin];
        let content = msg.content;
        let deserialized_content = deserialize_i64_tuple(&content);
        let group_id: i64 = deserialized_content.0;
        let share: i64 = deserialized_content.1;

        self.received_sharing_of_shares
            .entry(group_id)
            .or_insert_with(HashMap::new)
            .insert(share_evaluation_point, share);

        let share_count = self.received_sharing_of_shares[&group_id].len();
        if share_count >= self.num_nodes - self.num_faults {
            // get the contents of self.received_sharing_of_shares[group_id] with the key as the first element of a tuple and the value as the second element of the tuple
            // shares should be a Vec of tuples of evaluation_point (i64) and share (i64)
            let mut shares: Vec<(i64, i64)> = Vec::new();
            for (evaluation_point, share) in self.received_sharing_of_shares[&group_id].clone().into_iter() {
                shares.push((evaluation_point, share));
            }

            let mut result: Option<i64> = None;
            if is_degree_t_consistent(self.num_faults.try_into().unwrap(), shares.clone(), self.modulus) {
                let coefficients = interpolate_polynomial(shares, self.modulus);
                result = Some(evaluate_polynomial_from_coefficients_at_position(coefficients, 0, self.modulus));
            } else {
                // result stays None -> "failure symbol"
            }

            let content: (i64, Option<i64>) = (group_id, result);
            let serialized_content = serialize_i64_opti64_tuple(content);
            let msg = Msg {
                content: serialized_content,
                origin: self.myid
            };
            let distribute_sharing_of_share_msg =  ProtMsg::ReconstructedShare(msg, self.myid);
            self.broadcast_all(distribute_sharing_of_share_msg).await;
        }
    }


    pub async fn handle_reconstructed_share(self: &mut Context, msg:Msg) {
        // let from = msg.origin;
        let share_evaluation_point = self.evaluation_point[&msg.origin];
        let deserialized = deserialize_i64_tuple(&msg.content);
        let group_id: i64 = deserialized.0;
        let reconstructed_share: i64 = deserialized.1;

        self.received_shares
            .entry(group_id)
            .or_insert_with(HashMap::new)
            .insert(share_evaluation_point, reconstructed_share);

        let share_count = self.received_shares[&group_id].len();
        if share_count >= self.num_nodes - self.num_faults {
            let mut result: Option<Vec<i64>> = None;

            let mut shares: Vec<(i64, i64)> = Vec::new();
            for (evaluation_point, share) in self.received_shares[&group_id].clone().into_iter() {
                shares.push((evaluation_point, share));
            }
            if is_degree_t_consistent(self.num_faults.try_into().unwrap(), shares.clone(), self.modulus) {
                let coefficients = interpolate_polynomial(shares, self.modulus);
                result = Some(coefficients);
            } else {
                // result stays None -> "failure symbol"
            }

            self.results.insert(group_id, result);
            if self.protocol_complete() {

                let result_serialized = serialize_hashmap_results(&self.results).unwrap();
                self.terminate(result_serialized).await;

                // let mut output = String::new();
                // for (group_index, _) in self.results.iter().enumerate() {
                //     let group_index = group_index as i64;
                //     if !output.is_empty() {
                //         output.push(';');
                //     }
                //     match self.results.get(&group_index) {
                //         Some(Some(vec)) => {
                //             let group_str = vec.iter()
                //                 .map(|&num| num.to_string())
                //                 .collect::<Vec<String>>()
                //                 .join(",");
                //             output.push_str(&group_str);
                //         },
                //         Some(None) | None => {
                //             output.push_str("FAIL");
                //         }
                //     }
                // }
                //
                // self.terminate(output).await;
            }
        }

    }

    pub fn protocol_complete(self: &mut Context) -> bool {
        for (group_index, _) in self.grouped_shares.iter().enumerate() {
            if !self.results.contains_key(&(group_index as i64)) {
                return false;
            }
        }
        true
    }

}