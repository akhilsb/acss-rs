use crypto::hash::{do_hash, Hash};

use crate::{
    context::Context,
    msg::{Commitment, ProtMsg, WSSMsg, WSSMsgSer},
};

use super::ASKSState;
use consensus::LargeField;

impl Context {
    pub async fn reconstruct_asks(&mut self, instance_id: usize) {
        if !self.asks_state.contains_key(&instance_id) {
            log::error!(
                "Do not possess ASKS state with the given instance ID {}",
                instance_id
            );
            return;
        }

        let asks_context = self.asks_state.get(&instance_id).unwrap();
        if asks_context.share.is_some() {
            // Create message
            let share_msg = WSSMsg {
                share: asks_context.share.clone().unwrap(),
                nonce_share: asks_context.nonce_share.clone().unwrap(),
                origin: asks_context.origin,
            };
            let share_msg_ser = WSSMsgSer::from_unser(&share_msg);
            // Broadcast message
            self.broadcast(ProtMsg::Reconstruct(share_msg_ser, instance_id))
                .await;
        } else {
            log::info!(
                "Did not receive share from dealer of instance id {}",
                instance_id
            );
            return;
        }
    }

    pub async fn process_asks_reconstruct(
        &mut self,
        share: WSSMsgSer,
        share_sender: usize,
        instance_id: usize,
    ) {
        if !self.asks_state.contains_key(&instance_id) {
            let new_state = ASKSState::new(share.origin);
            self.asks_state.insert(instance_id, new_state);
        }

        let asks_state = self.asks_state.get_mut(&instance_id).unwrap();
        if asks_state.rbc_state.message.is_none() {
            log::error!("RBC did not terminate for this party yet for ASKS instance id {}, skipping share processing", instance_id);
            return;
        }

        let comm_ser = asks_state.rbc_state.message.clone().unwrap();
        let comm: Commitment = bincode::deserialize(&comm_ser).unwrap();

        // compute commitment of share and match it with terminated commitments
        let share_comm = share.compute_commitment();
        if share_comm != comm[share_sender] {
            log::error!(
                "Commitment does not match broadcasted commitment for ASKS instance {}",
                instance_id
            );
            return;
        }

        let deser_share = share.to_unser();
        asks_state
            .secret_shares
            .insert(share_sender, (deser_share.share, deser_share.nonce_share));
        if asks_state.secret_shares.len() == self.num_faults + 1 {
            // Interpolate polynomial shares and coefficients

            // Storing the evaluations along with x coordinates
            let mut share_poly_shares = Vec::new();

            let mut nonce_poly_shares = Vec::new();
            let mut x_coords = Vec::new();

            for rep in 0..self.num_nodes {
                if asks_state.secret_shares.contains_key(&rep) {
                    let shares_party = asks_state.secret_shares.get(&rep).unwrap();
                    share_poly_shares.push(shares_party.0.clone());
                    nonce_poly_shares.push(shares_party.1.clone());
                    x_coords.push(LargeField::from((rep + 1) as u64));
                }
            }

            // Interpolate polynomial to get the polynomial object (i.e coefficients array)
            let share_poly_coeffs = self
                .large_field_uv_sss
                .reconstructing(&x_coords, &share_poly_shares);
            let nonce_poly_coeffs = self
                .large_field_uv_sss
                .reconstructing(&x_coords, &nonce_poly_shares);

            // Reconstruct all evaluations
            let all_shares: Vec<LargeField> = self
                .large_field_uv_sss
                .generating_shares(&share_poly_coeffs);
            let nonce_all_shares: Vec<LargeField> = self
                .large_field_uv_sss
                .generating_shares(&nonce_poly_coeffs);

            // Compute and match commitments
            let all_commitments: Vec<Hash> = all_shares
                .into_iter()
                .zip(nonce_all_shares.into_iter())
                .map(|(share, nonce)| {
                    let mut appended_vec = Vec::new();
                    appended_vec.extend(share.to_bytes_be());
                    appended_vec.extend(nonce.to_bytes_be());
                    return do_hash(appended_vec.as_slice());
                })
                .collect();

            let mut match_flag = true;
            for (old, new) in comm.into_iter().zip(all_commitments.into_iter()) {
                match_flag = match_flag && (old == new);
            }

            let secret;
            if !match_flag {
                log::error!("Broadcasted and generated commitments do not match, the dealer did not use a degree-t polynomial for ASKS instance {}", instance_id);
                // Invoke termination with Zero as secret.
                secret = LargeField::from(0);
            } else {
                log::info!(
                    "Successfully reconstructed secret for ASKS instance {}",
                    instance_id
                );
                secret = share_poly_coeffs.coefficients()[0].clone()
                // Invoke termination with
            }
            log::info!(
                "Sending back value to ACS: {} for ASKS instancce {}",
                secret,
                instance_id
            );
            self.terminate(instance_id, Some(secret)).await;
        }
    }
}
