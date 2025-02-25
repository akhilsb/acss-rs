use std::vec::Vec;
use crate::context::Context;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use types::{Msg, ProtMsg, Replica, WrapperMsg};
use std::convert::TryInto;
use itertools::Itertools;
use byteorder::{ByteOrder, LittleEndian};
use std::clone::Clone;
use std::mem::size_of;
use base64ct::{Base64, Encoding};
use crate::helper::{contains_only_some, group_elements_by_count, hash_vec_u8};
use crate::serialize::{GroupValue, GroupValueOption, GroupHashValueOption, serialize_group_value_option, deserialize_group_value_option, serialize_group_hash_value_option, deserialize_group_hash_value_option, WeakShareMultiplicationResult};
use crate::math::{interpolate_polynomial, generate_vandermonde_matrix, matrix_vector_mul, dot_product, evaluate_polynomial_from_coefficients_at_position};


impl Context {

    pub async fn start_multiplication(self: &mut Context) {
        // TODO: Get values from input channel
        self.a_vec_shares = vec![vec![Some(1), Some(2)], vec![Some(1), Some(2)], vec![Some(1), Some(2)], vec![Some(1), Some(2)]];
        self.b_vec_shares = vec![vec![Some(1), Some(2)], vec![Some(1), Some(2)], vec![Some(1), Some(2)], vec![Some(1), Some(2)]];
        self.r_shares = vec![Some(4), Some(4), Some(4), Some(4), Some(4), Some(4), Some(4), Some(4), Some(4), Some(4)];
        self.o_shares = vec![4, 4, 4, 4, 4, 4, 4, 4, 4, 4];

        assert_eq!(self.a_vec_shares.len(), self.b_vec_shares.len());
        assert_eq!(self.b_vec_shares.len(), self.r_shares.len());
        assert_eq!(self.r_shares.len(), self.N);
        assert_eq!(self.o_shares.len(), (self.num_faults * self.N) / (2 * self.num_faults + 1));

        // Initialize
        self.cs = vec![vec![Some(0); 2*self.num_faults + 1]; self.N / (2 * self.num_faults + 1)];

        // Group inputs
        let a_vec_shares_grouped = group_elements_by_count(self.a_vec_shares.clone(), self.N / (2 * self.num_faults + 1));
        let b_vec_shares_grouped = group_elements_by_count(self.b_vec_shares.clone(), self.N / (2 * self.num_faults + 1));
        let r_shares_grouped = group_elements_by_count(self.r_shares.clone(), self.N / (2 * self.num_faults + 1));
        let o_shares_grouped = group_elements_by_count(self.o_shares.clone(), self.N / (2 * self.num_faults + 1));
        // Check that there are the correct number of groups
        assert_eq!(a_vec_shares_grouped.len(), self.N / (2 * self.num_faults + 1));
        assert_eq!(b_vec_shares_grouped.len(), self.N / (2 * self.num_faults + 1));
        assert_eq!(r_shares_grouped.len(), self.N / (2 * self.num_faults + 1));
        assert_eq!(o_shares_grouped.len(), self.N / (2 * self.num_faults + 1));
        // Check each group has correct number of elements
        assert!(a_vec_shares_grouped.iter().all(|x| x.len() == self.num_faults));
        assert!(b_vec_shares_grouped.iter().all(|x| x.len() == self.num_faults));
        assert!(r_shares_grouped.iter().all(|x| x.len() == self.num_faults));
        assert!(o_shares_grouped.iter().all(|x| x.len() == (self.num_faults * self.N) / (2*self.num_faults + 1)));

        let vdm_matrix = generate_vandermonde_matrix(self.N, self.num_faults, self.modulus);

        let mut o_tilde_grouped = Vec::with_capacity(self.N / (2 * self.num_faults + 1));
        self.zs = Vec::with_capacity(2 * self.num_faults + 1);
        let mut share_for_party: Vec<HashMap<usize, Option<i64>>> = Vec::with_capacity(self.N);

        // Compute all the shares and store them in share_for_party[group][party]
        for i in 0..(self.N / (2 * self.num_faults + 1)) {
            o_tilde_grouped[i] = matrix_vector_mul(&vdm_matrix, &o_shares_grouped[i], self.modulus);
            self.zs[i] = Vec::with_capacity(2 * self.num_faults + 1);

            let mut contains_none = false;
            for k in 1..=(2 * self.num_faults + 1) {
                if contains_only_some(&a_vec_shares_grouped[i][k]) && contains_only_some(&b_vec_shares_grouped[i][k]) {} else {
                    contains_none = true;
                }
            }
            if contains_none {
                // Cannot compute shares if there are bot in a/b
                for p in 1..=self.num_nodes {
                    share_for_party[i].insert(p, None);
                }
            } else {
                for k in 1..=(2 * self.num_faults + 1) {
                    let a = a_vec_shares_grouped[i][k].iter().map(|x| { x.unwrap() }).collect_vec();
                    let b = b_vec_shares_grouped[i][k].iter().map(|x| { x.unwrap() }).collect_vec();
                    self.zs[i][k] = dot_product(&a, &b) + r_shares_grouped[i][k].clone().unwrap();
                }
                for p in 1..=self.num_nodes {
                    let evaluation_point = p;
                    let share = evaluate_polynomial_from_coefficients_at_position(self.zs[i].clone(), evaluation_point as i64, self.modulus) + o_tilde_grouped[i][p];
                    share_for_party[i].insert(p, Some(share));
                }
            }
        }

        // Send shares for all groups to all parties
        for i in 0..(self.N / (2 * self.num_faults + 1)) {
            for p in 1..=self.num_nodes {
                // send share to P_p
                let replica = p;
                let mut content = serialize_group_value_option(GroupValueOption {
                    group: i,
                    value: share_for_party[i][&p]
                });
                let msg = Msg {
                    content,
                    origin: self.myid
                };
                let distribute_sharing_of_share_msg =  ProtMsg::FxShareMessage(msg.clone(), self.myid);
                let sec_key_for_replica = self.sec_key_map[&(replica)].clone();
                let wrapper_msg = WrapperMsg::new(
                    distribute_sharing_of_share_msg.clone(),
                    self.myid,
                    &sec_key_for_replica.as_slice()
                );
                self.send(replica, wrapper_msg).await;
            }
        }
    }

    pub async fn handle_fx_share_message(self: &mut Context, msg:Msg) {
        let evaluation_point = self.evaluation_point[&msg.origin];
        let content = msg.content;
        let deserialized_content = deserialize_group_value_option(&*content);
        let group: usize = deserialized_content.group;
        let share: Option<i64> = deserialized_content.value;

        // self.received_fx_shares.insert(group, (evaluation_point, share));
        self.received_fx_shares.entry(group).or_insert_with(Vec::new).push((evaluation_point, share));

        if self.reconstruction_result.contains_key(&group) {
            // reconstruction was already sent to other parties for this group --> skip
        } else {
            if share.is_none() {
                self.reconstruction_result.insert(group, None);
                self.distribute_reconstruction_result(group).await;
            } else if self.received_fx_shares.len() >= 2*self.num_faults+1 {
                let points = self.received_fx_shares.get(&group).unwrap().iter().map(|x| (x.0, x.1.unwrap())).collect_vec();
                let coefficients: Vec<i64> = interpolate_polynomial(points, self.modulus);
                let evaluation_result = evaluate_polynomial_from_coefficients_at_position(coefficients, 0, self.modulus);
                self.reconstruction_result.insert(group, Some(evaluation_result));
                self.distribute_reconstruction_result(group).await;
            }
        }
    }

    pub async fn distribute_reconstruction_result(self: &mut Context, group: usize) {
        for p in 1..=self.num_nodes {
            let content = GroupValueOption {
                group: group,
                value: self.reconstruction_result[&group]
            };
            let msg = Msg {
                content: serialize_group_value_option(content),
                origin: self.myid
            };
            let m =  ProtMsg::GroupReconstructionMessage(msg.clone(), self.myid);
            let sec_key_for_replica = self.sec_key_map[&(p)].clone();
            let wrapper_msg = WrapperMsg::new(
                m.clone(),
                self.myid,
                &sec_key_for_replica.as_slice()
            );
            self.send(p, wrapper_msg).await;
        }
    }

    pub async fn handle_reconstruction_result_message(self: &mut Context, msg: Msg) {
        let content = msg.content;
        let deserialized_content = deserialize_group_value_option(&content);
        let sender: usize = msg.origin as usize;
        let group: usize = deserialized_content.group;
        let value: Option<i64> = deserialized_content.value;

        self.received_reconstruction_shares.entry(group).or_insert_with(HashMap::new).insert(sender, value);
        if self.received_reconstruction_shares[&group].len() >= 2*self.num_faults + 1 && !self.Z.contains_key(&group) {
            let shares =  self.received_reconstruction_shares.get(&group).unwrap().iter().map(|x| (x.0.clone() as i64, x.1.clone().unwrap())).collect_vec();
            let mut coefficients = vec![0; 2*self.num_faults + 1];
            let coeff_tmp = interpolate_polynomial(shares, self.modulus);
            for (index, value) in coeff_tmp.iter().enumerate() {
                coefficients[index] = *value;
            }

            self.coefficients_z.insert(group, coefficients);
            let hash: Vec<u8> = hash_vec_u8(self.coefficients_z[&group].clone());
            self.Z.insert(group.clone(), hash);

            // Broadcast Z[group]
            let content = GroupHashValueOption {
                group: group,
                value: Some(self.Z[&group].clone())
            };
            let serialized_content = serialize_group_hash_value_option(content);
            let msg = Msg {
                content: serialized_content,
                origin: self.myid
            };
            let distribute_sharing_of_share_msg =  ProtMsg::HashBroadcastMessage(msg, self.myid);
            self.broadcast_all(distribute_sharing_of_share_msg).await; // TODO: May need to invoke custom RBC here and adapt invocation of handle_Z_hash_broadcast_message. How to handle this?

        }
    }

    pub async fn handle_Z_hash_broadcast_message(self: &mut Context, msg: Msg) {
        let content = msg.content;
        let deserialized_content = deserialize_group_hash_value_option(&*content);
        let group: usize = deserialized_content.group;
        let value: Option<Vec<u8>> = deserialized_content.value;

        self.received_Z.entry(group).or_insert_with(Vec::new).push(value);

        if self.received_Z[&group].iter().any(|x| x.is_none()) || !self.received_Z[&group].windows(2).all(|w| w[0] == w[1]) {
            self.result.insert(group, WeakShareMultiplicationResult::FAIL);
        } else {
            if self.received_Z[&group].len() >= 2*self.num_faults + 1 {
                for k in 1..=2*self.num_faults + 1 {
                    self.cs[group][k] = Some(self.zs[group][k] - self.r_shares_grouped[group][k].unwrap());
                }
            }
        }

        if self.result.len() == 2*self.num_faults+1 && self.result.iter().all(|x| matches!(x.1, WeakShareMultiplicationResult::FAIL) || matches!(x.1, WeakShareMultiplicationResult::SUCCESS(_, _))) {
            // TODO: uncomment terminate call; signature needs to be fixed
            // self.terminate(self.result.clone()).await;
        }
    }

}