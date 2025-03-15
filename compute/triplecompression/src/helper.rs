use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use rayon::prelude::*;

pub(crate) fn hash_vec_u8(input: Vec<FieldElement<Stark252PrimeField>>) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    for element in input {
        hasher.update(element.to_bytes_le());
        hasher.update(b";");
    }
    let hash = hasher.finalize();
    hash.to_vec()
}

pub(crate) fn group_elements_by_count<T: Clone + Send + Sync>(elements: Vec<T>, num_groups: usize) -> Vec<Vec<T>> {
    if elements.is_empty() || num_groups == 0 {
        return Vec::new();
    }

    let total_elements = elements.len();
    let actual_num_groups = num_groups.min(total_elements);
    let elements_per_group = (total_elements + actual_num_groups - 1) / actual_num_groups; // Ceiling division
    
    (0..actual_num_groups).into_par_iter().map(|group_idx| {
        let start_idx = group_idx * elements_per_group;
        let mut group = Vec::with_capacity(elements_per_group);
        
        for j in 0..elements_per_group {
            let idx = start_idx + j;
            if idx < total_elements {
                group.push(elements[idx].clone());
            } else if !group.is_empty() {
                let last = group.last().unwrap().clone();
                group.push(last);
            }
        }
        group
    }).collect()
}

pub(crate) fn contains_only_some<T: Send + Sync>(values: &Vec<Option<T>>) -> bool {
    values.par_iter().find_any(|value| value.is_none()).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_vec_u8() {
        use sha2::{Sha256, Digest};

        // Test with empty vector
        let empty_input: Vec<FieldElement<Stark252PrimeField>> = vec![];
        let empty_result = hash_vec_u8(empty_input);

        // Manually calculate hash for empty input
        let mut empty_hasher = Sha256::new();
        let empty_expected = empty_hasher.finalize().to_vec();
        assert_eq!(empty_result, empty_expected);

        // Test with a single element
        let single_value = FieldElement::<Stark252PrimeField>::from(42u64);
        let single_input = vec![single_value.clone()];
        let single_result = hash_vec_u8(single_input);

        // Manually calculate hash for single input
        let mut single_hasher = Sha256::new();
        single_hasher.update(single_value.to_bytes_le());
        single_hasher.update(b";");
        let single_expected = single_hasher.finalize().to_vec();
        assert_eq!(single_result, single_expected);

        // Test with multiple elements
        let value1 = FieldElement::<Stark252PrimeField>::from(123u64);
        let value2 = FieldElement::<Stark252PrimeField>::from(456u64);
        let value3 = FieldElement::<Stark252PrimeField>::from(789u64);
        let multi_input = vec![value1.clone(), value2.clone(), value3.clone()];
        let multi_result = hash_vec_u8(multi_input);

        // Manually calculate hash for multiple inputs
        let mut multi_hasher = Sha256::new();
        multi_hasher.update(value1.to_bytes_le());
        multi_hasher.update(b";");
        multi_hasher.update(value2.to_bytes_le());
        multi_hasher.update(b";");
        multi_hasher.update(value3.to_bytes_le());
        multi_hasher.update(b";");
        let multi_expected = multi_hasher.finalize().to_vec();
        assert_eq!(multi_result, multi_expected);

        // Ensure different inputs produce different hashes
        let different_input = vec![FieldElement::<Stark252PrimeField>::from(999u64)];
        let different_result = hash_vec_u8(different_input);
        assert_ne!(different_result, single_result);
    }

    #[test]
    fn test_group_elements_by_count() {
        // Test empty vector
        let empty: Vec<i32> = Vec::new();
        let result = group_elements_by_count(empty, 3);
        assert_eq!(result, Vec::<Vec<i32>>::new());

        // Test zero groups
        let data = vec![1, 2, 3];
        let result = group_elements_by_count(data.clone(), 0);
        assert_eq!(result, Vec::<Vec<i32>>::new());

        // Test even distribution
        let data = vec![1, 2, 3, 4, 5, 6]; // 6 elements
        let result = group_elements_by_count(data.clone(), 3); // 3 groups
        assert_eq!(result, vec![vec![1, 2], vec![3, 4], vec![5, 6]]);

        // Test uneven distribution
        let data = vec![1, 2, 3, 4, 5, 6, 7]; // 7 elements
        let result = group_elements_by_count(data.clone(), 3); // 3 groups
        assert_eq!(result, vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 7, 7]]);

        // Test more groups than elements
        let data = vec![1, 2, 3]; // 3 elements
        let result = group_elements_by_count(data.clone(), 5); // 5 groups requested
        // Should create only 3 groups (one per element)
        assert_eq!(result, vec![vec![1], vec![2], vec![3]]);

        // Test single group
        let data = vec![1, 2, 3, 4, 5];
        let result = group_elements_by_count(data.clone(), 1);
        assert_eq!(result, vec![data.clone()]);
    }

    #[test]
    fn test_contains_only_some() {
        // Test with empty vector
        let empty: Vec<Option<i32>> = Vec::new();
        assert!(contains_only_some(&empty));

        // Test with vector containing only Some values
        let all_some = vec![Some(1), Some(2), Some(3)];
        assert!(contains_only_some(&all_some));

        // Test with vector containing only None values
        let all_none: Vec<Option<i32>> = vec![None, None, None];
        assert!(!contains_only_some(&all_none));

        // Test with vector containing mixed Some and None values
        let mixed = vec![Some(1), None, Some(3)];
        assert!(!contains_only_some(&mixed));

        // Test with None at beginning
        let none_at_start = vec![None, Some(2), Some(3)];
        assert!(!contains_only_some(&none_at_start));

        // Test with None at end
        let none_at_end = vec![Some(1), Some(2), None];
        assert!(!contains_only_some(&none_at_end));

        // Test with single Some
        let single_some = vec![Some(42)];
        assert!(contains_only_some(&single_some));

        // Test with single None
        let single_none = vec![None as Option<i32>];
        assert!(!contains_only_some(&single_none));

        // Test with large vector to exercise parallel processing
        let large_all_some = (0..10000).map(Some).collect::<Vec<_>>();
        assert!(contains_only_some(&large_all_some));

        let mut large_with_one_none = (0..10000).map(Some).collect::<Vec<_>>();
        large_with_one_none[5000] = None;
        assert!(!contains_only_some(&large_with_one_none));
    }
    
}





























// fn convert_to_vec_i64(values: Vec<Option<i64>>) -> Vec<i64> {
//     values.into_iter().filter_map(|x| x).collect()
// }


// pub(crate) fn group_elements<T: Clone>(elements: Vec<T>, group_size: usize) -> Vec<Vec<T>> {
//     let mut result = Vec::new();
//     let mut current_group = Vec::new();
//     let total_len = elements.len();
//     let actual_group_size = if group_size == 0 { total_len } else { group_size + 1 };
// 
//     for (index, element) in elements.into_iter().enumerate() {
//         current_group.push(element);
// 
//         if current_group.len() == actual_group_size || index == total_len - 1 {
//             while current_group.len() < actual_group_size {
//                 if let Some(last) = current_group.last() {
//                     current_group.push(last.clone());
//                 }
//             }
//             result.push(current_group);
//             current_group = Vec::new();
//         }
//     }
//     result
// }