use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::traits::ByteConversion;

pub(crate) struct GroupValueOption {
    pub group: usize,
    pub value: Option<FieldElement<Stark252PrimeField>>,
}

pub(crate) struct GroupHashValueOption {
    pub(crate) group: usize,
    pub(crate) value: Option<Vec<u8>>,
}

#[derive(Clone)]
pub(crate) enum WeakShareMultiplicationResult {
    FAIL,
    SUCCESS(usize, i64)
}

pub(crate) fn serialize_group_value_option(value: GroupValueOption) -> Vec<u8> {
    let mut result = value.group.to_be_bytes().to_vec();
    match value.value {
        Some(v) => {
            result.push(1);
            result.extend_from_slice(&v.to_bytes_be());
        }
        None => {
            result.push(0);
        }
    }
    result
}

pub(crate) fn deserialize_group_value_option(data: &[u8]) -> GroupValueOption {
    let group = usize::from_be_bytes(data[..size_of::<usize>()].try_into().unwrap());
    if data[size_of::<usize>()] == 0 {
        GroupValueOption { group, value: None }
    } else {
        let value = FieldElement::from_bytes_be(data[size_of::<usize>() + 1..].try_into().unwrap()).unwrap();
        GroupValueOption {
            group,
            value: Some(value),
        }
    }
}

pub(crate) fn serialize_group_hash_value_option(value: GroupHashValueOption) -> Vec<u8> {
    let mut result = value.group.to_be_bytes().to_vec();
    match value.value {
        Some(v) => {
            result.push(1);
            result.extend_from_slice(&(v.len() as u64).to_be_bytes());
            result.extend_from_slice(&v);
        }
        None => {
            result.push(0);
        }
    }
    result
}

pub(crate) fn deserialize_group_hash_value_option(data: &[u8]) -> GroupHashValueOption {
    let group = usize::from_be_bytes(data[..size_of::<usize>()].try_into().unwrap());
    if data[size_of::<usize>()] == 0 {
        GroupHashValueOption { group, value: None }
    } else {
        let len = u64::from_be_bytes(data[size_of::<usize>() + 1..size_of::<usize>() + 1 + size_of::<u64>()].try_into().unwrap()) as usize;
        let value = data[size_of::<usize>() + 1 + size_of::<u64>()..].to_vec();
        GroupHashValueOption {
            group,
            value: Some(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_group_value_option() {
        let group_id = 42;
        let field_value = FieldElement::<Stark252PrimeField>::from(123u64);
        let original = GroupValueOption {
            group: group_id,
            value: Some(field_value.clone()),
        };

        let serialized = serialize_group_value_option(original);
        let deserialized = deserialize_group_value_option(&serialized);
        assert_eq!(deserialized.group, group_id);
        assert!(deserialized.value.is_some());
        assert_eq!(deserialized.value.unwrap(), field_value);

        let original_none = GroupValueOption {
            group: group_id,
            value: None,
        };
        let serialized_none = serialize_group_value_option(original_none);
        let deserialized_none = deserialize_group_value_option(&serialized_none);
        assert_eq!(deserialized_none.group, group_id);
        assert!(deserialized_none.value.is_none());
    }

    #[test]
    fn test_serialize_deserialize_group_hash_value_option() {
        use std::mem::size_of;
        
        let group_id = 42;
        let hash_value = vec![1, 2, 3, 4, 5];
        let original = GroupHashValueOption {
            group: group_id,
            value: Some(hash_value.clone()),
        };

        let serialized = serialize_group_hash_value_option(original);
        assert_eq!(
            serialized.len(),
            size_of::<usize>() + 1 + size_of::<u64>() + hash_value.len()
        );
        assert_eq!(serialized[size_of::<usize>()], 1); // 1 indicates Some

        let deserialized = deserialize_group_hash_value_option(&serialized);
        assert_eq!(deserialized.group, group_id);
        assert!(deserialized.value.is_some());
        assert_eq!(deserialized.value.unwrap(), hash_value);

        let original_none = GroupHashValueOption {
            group: group_id,
            value: None,
        };
        let serialized_none = serialize_group_hash_value_option(original_none);
        assert_eq!(serialized_none.len(), size_of::<usize>() + 1);
        assert_eq!(serialized_none[size_of::<usize>()], 0); // 0 indicates None
        let deserialized_none = deserialize_group_hash_value_option(&serialized_none);
        assert_eq!(deserialized_none.group, group_id);
        assert!(deserialized_none.value.is_none());

        let empty_vec = Vec::<u8>::new();
        let original_empty = GroupHashValueOption {
            group: group_id,
            value: Some(empty_vec),
        };
        let serialized_empty = serialize_group_hash_value_option(original_empty);
        let deserialized_empty = deserialize_group_hash_value_option(&serialized_empty);
        assert_eq!(deserialized_empty.group, group_id);
        assert_eq!(deserialized_empty.value.unwrap(), Vec::<u8>::new());
    }
    
}


/*
// pub(crate) struct GroupValue {
//     group: usize,
//     value: i64,
// }

// i64
// pub(crate) fn serialize_i64(value: i64) -> Vec<u8> {
//     value.to_be_bytes().to_vec()
// }
// 
// pub(crate) fn deserialize_i64(data: &[u8]) -> i64 {
//     i64::from_be_bytes(data.try_into().unwrap())
// }

// Option<i64>
// pub(crate) fn serialize_option_i64(value: Option<i64>) -> Vec<u8> {
//     match value {
//         Some(v) => {
//             let mut result = vec![1u8];
//             result.extend_from_slice(&v.to_be_bytes());
//             result
//         }
//         None => vec![0u8],
//     }
// }
// 
// pub(crate) fn deserialize_option_i64(data: &[u8]) -> Option<i64> {
//     if data.is_empty() {
//         return None;
//     }
//     match data[0] {
//         0 => None,
//         1 => {
//             let value = i64::from_be_bytes(data[1..].try_into().unwrap());
//             Some(value)
//         }
//         _ => panic!("Invalid Option<i64> data"),
//     }
// }

// // GroupValue
// pub(crate) fn serialize_group_value(value: GroupValue) -> Vec<u8> {
//     let mut result = value.group.to_be_bytes().to_vec();
//     result.extend_from_slice(&value.value.to_be_bytes());
//     result
// }
// 
// pub(crate) fn deserialize_group_value(data: &[u8]) -> GroupValue {
//     let group = usize::from_be_bytes(data[..size_of::<usize>()].try_into().unwrap());
//     let value = i64::from_be_bytes(data[size_of::<usize>()..].try_into().unwrap());
//     GroupValue { group, value }
// }



// fn serialize_option_i64_to_vec_u8(num: Option<i64>) -> Vec<u8> {
//     let mut buf = Vec::new();
//     match num {
//         None => {
//             buf.push(0); // Flag for None
//         }
//         Some(val) => {
//             buf.push(1); // Flag for Some
//             buf.extend_from_slice(&[0u8; 8]); // Extend buffer to fit an i64
//             LittleEndian::write_i64(&mut buf[1..], val);
//         }
//     }
//     buf
// }
//
// fn deserialize_vec_u8_to_option_i64(bytes: Vec<u8>) -> Option<i64> {
//     if bytes.is_empty() {
//         return None; // Early return if input is empty
//     }
//
//     match bytes[0] {
//         0 => None,
//         1 => {
//             assert!(bytes.len() == 9, "Expected length for Some(i64) is 9 bytes");
//             Some(LittleEndian::read_i64(&bytes[1..]))
//         },
//         _ => panic!("Invalid flag byte"),
//     }
// }
 */