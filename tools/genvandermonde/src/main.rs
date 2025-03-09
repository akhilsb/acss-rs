// // Tool to precompute inverse vandermonde matrices for
// use consensus::{LargeField, ShamirSecretSharing};
// use serde_json;
// use std::fs::File;
// use std::io::Write;

// fn main() {
//     for t in 1..=33 {
//         let num_nodes = 3 * t + 1;
//         let x_values: Vec<u64> = (0..num_nodes as u64).collect();

//         let sss = ShamirSecretSharing::new(t, num_nodes);
//         let vandermonde = sss.vandermonde_matrix(&x_values);
//         let inv_vandermonde = sss.inverse_vandermonde(vandermonde);
//         // write to file
//         let lt_path = format!("../../data/lt/vandermonde_inverse-{}.json", num_nodes);
//         write_to_file(&lt_path, &inv_vandermonde);

//         let sss_ht = ShamirSecretSharing::new(2 * t, num_nodes);
//         let vandermonde_ht = sss_ht.vandermonde_matrix(&x_values);
//         let inv_vandermonde_ht = sss_ht.inverse_vandermonde(vandermonde_ht);
//         // write to file
//         let ht_path = format!("../../data/ht/vandermonde_inverse-{}.json", num_nodes);
//         write_to_file(&ht_path, &inv_vandermonde_ht);
//     }
// }

// fn write_to_file(path: &str, matrix: &Vec<Vec<LargeField>>) {
//     let serializable_matrix: Vec<Vec<Vec<u8>>> = matrix
//         .iter()
//         .map(|row| {
//             row.iter()
//                 .map(|el| el.to_bytes_be().to_vec()) // Convert to big-endian bytes and collect into Vec<u8>
//                 .collect()
//         })
//         .collect();

//     match File::create(path) {
//         Ok(mut file) => {
//             let json_data = serde_json::to_string_pretty(&serializable_matrix).unwrap();
//             if let Err(e) = file.write_all(json_data.as_bytes()) {
//                 eprintln!("Failed to write to {}: {}", path, e);
//             }
//         }
//         Err(e) => {
//             eprintln!("Failed to create file {}: {}", path, e);
//         }
//     }
// }

fn main () 
{
    
}