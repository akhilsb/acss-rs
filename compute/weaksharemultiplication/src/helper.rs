/// Groups elements from a vector into a specified number of subgroups.
///
/// This function takes a vector of elements of type T and divides them into
/// the specified number of groups. Each group will have approximately the same
/// number of elements. If the elements can't be divided evenly, some groups may
/// have one more element than others.
///
/// # Arguments
///
/// * `elements` - A vector of elements of type T to be grouped.
/// * `num_groups` - A usize integer specifying the number of groups to create.
///
/// # Returns
///
/// A vector of vectors of elements of type T, where each inner vector represents a group.
///
/// # Examples
///
/// ```
/// let elements = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
/// let num_groups = 3;
/// let result = group_elements_by_count(elements, num_groups);
/// assert_eq!(result, vec![vec![1, 2, 3, 4], vec![5, 6, 7], vec![8, 9, 10]]);
/// ```
///
/// # Notes
///
/// - If `elements` is empty, an empty vector will be returned.
/// - If `num_groups` is 0 or greater than the number of elements, each element will be in its own group.
/// - Type T must implement the Clone trait.
pub(crate) fn group_elements_by_count<T: Clone>(mut elements: Vec<T>, num_groups: usize) -> Vec<Vec<T>> {
    if elements.is_empty() || num_groups == 0 {
        return Vec::new();
    }

    let total_elements = elements.len();
    let actual_num_groups = num_groups.min(total_elements);
    let base_group_size = total_elements / actual_num_groups;
    let extra_elements = total_elements % actual_num_groups;

    let mut result = Vec::with_capacity(actual_num_groups);

    for i in 0..actual_num_groups {
        let mut group_size = base_group_size;
        if i < extra_elements {
            group_size += 1;
        }

        let mut group = Vec::with_capacity(group_size);
        for _ in 0..group_size {
            if let Some(element) = elements.pop() {
                group.push(element);
            }
        }
        group.reverse(); // To maintain original order within the group
        result.push(group);
    }

    result.reverse(); // To maintain overall original order
    result
}



pub(crate) fn hash_vec_u8(input: Vec<i64>) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    for i in input {
        hasher.update(i.to_le_bytes());
        hasher.update(b";")
    }
    let hash = hasher.finalize();
    let hash_vec: Vec<u8> = hash.to_vec();
    hash_vec
}

pub(crate) fn contains_only_some(values: &Vec<Option<i64>>) -> bool {
    values.iter().all(|value| value.is_some())
}


/// Groups elements from a vector into subgroups of a specified size.
///
/// This function takes a vector of elements of type T and groups them into subvectors
/// of size `group_size + 1`. If there are not enough elements to complete the
/// last group, the last element is cloned to fill the group.
///
/// # Arguments
///
/// * `elements` - A vector of elements of type T to be grouped.
/// * `group_size` - A usize integer specifying the size of each group.
///
/// # Returns
///
/// A vector of vectors of elements of type T, where each inner vector represents a group.
///
/// # Examples
///
/// ```
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
/// - Type T must implement the Clone trait.
pub(crate) fn group_elements<T: Clone>(elements: Vec<T>, group_size: usize) -> Vec<Vec<T>> {
    let mut result = Vec::new();
    let mut current_group = Vec::new();
    let total_len = elements.len();
    let actual_group_size = if group_size == 0 { total_len } else { group_size + 1 };

    for (index, element) in elements.into_iter().enumerate() {
        current_group.push(element);

        if current_group.len() == actual_group_size || index == total_len - 1 {
            while current_group.len() < actual_group_size {
                if let Some(last) = current_group.last() {
                    current_group.push(last.clone());
                }
            }
            result.push(current_group);
            current_group = Vec::new();
        }
    }
    result
}

// fn convert_to_vec_i64(values: Vec<Option<i64>>) -> Vec<i64> {
//     values.into_iter().filter_map(|x| x).collect()
// }