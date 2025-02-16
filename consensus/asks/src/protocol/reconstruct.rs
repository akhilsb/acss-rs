use crypto::hash::{do_hash, Hash};

use crate::{
    context::Context,
    msg::{Commitment, ProtMsg, WSSMsg, WSSMsgSer},
};

use super::ASKSState;
use lambdaworks_math::fft::polynomial;
use lambdaworks_math::polynomial::Polynomial;

use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::traits::{IsFFTField, IsField};
use num_bigint_dig::{BigInt, Sign};
use num_traits::cast::ToPrimitive;

type StarkField = FieldElement<Stark252PrimeField>;
use types::{SyncMsg, SyncState, WrapperMsg};

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

        // TODO: maybe wrap in a different type?

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
            let mut share_poly_shares: Vec<StarkField> = Vec::new();
            let mut nonce_poly_shares: Vec<StarkField> = Vec::new();

            for rep in 0..self.num_nodes {
                let x_val = StarkField::from(rep as u64) + StarkField::from(1u64);
                if asks_state.secret_shares.contains_key(&rep) {
                    let shares_party = asks_state.secret_shares.get(&rep).unwrap();
                    // share_poly_shares.push(LargeField::from(shares_party.0.clone()));
                    // nonce_poly_shares.push(LargeField::from(shares_party.1.clone()));
                    share_poly_shares.push(StarkField::from(shares_party.0.to_u64().unwrap_or(0)));
                    nonce_poly_shares.push(StarkField::from(shares_party.1.to_u64().unwrap_or(0)));
                }
            }

            // Interpolate polynomial
            // let share_poly_coeffs = self.large_field_uv_sss.polynomial_coefficients(&share_poly_shares);
            // let nonce_poly_coeffs = self.large_field_uv_sss.polynomial_coefficients(&nonce_poly_shares);

            // // TODO: Use lambdaworks
            // let all_shares: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|val| self.large_field_uv_sss.mod_evaluate_at(&share_poly_coeffs, val)).collect();
            // let nonce_all_shares: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|val| self.large_field_uv_sss.mod_evaluate_at(&nonce_poly_coeffs, val)).collect();

            let x_values: Vec<StarkField> = (1..=self.num_nodes)
                .map(|x| StarkField::from(x as u64))
                .collect();

            // let share_poly = Polynomial::interpolate(&x_values, &share_poly_shares).unwrap();
            // let nonce_poly = Polynomial::interpolate(&x_values, &nonce_poly_shares).unwrap();

            let share_poly =
                Polynomial::interpolate_fft::<Stark252PrimeField>(&share_poly_shares[..]).unwrap();
            let nonce_poly =
                Polynomial::interpolate_fft::<Stark252PrimeField>(&nonce_poly_shares[..]).unwrap();

            // Extract coefficients
            let share_poly_coeffs = share_poly.coefficients().to_vec();
            let nonce_poly_coeffs = nonce_poly.coefficients().to_vec();

            // interpolation DONE
            // eval
            // let all_shares: Vec<StarkField> = (1..=self.num_nodes)
            //     .map(|val| share_poly.evaluate(&StarkField::from(val as u64)))
            //     .collect();
            // let nonce_all_shares: Vec<StarkField> = (1..=self.num_nodes)
            //     .map(|val| nonce_poly.evaluate(&StarkField::from(val as u64)))
            //     .collect();
            let offset = StarkField::one();
            let blowup_factor = 1; // @akhilsb: Should I change this?
            let domain_size = Some(self.num_nodes.next_power_of_two());

            let all_shares =
                Polynomial::evaluate_offset_fft(&share_poly, blowup_factor, domain_size, &offset)
                    .unwrap();
            let nonce_all_shares =
                Polynomial::evaluate_offset_fft(&nonce_poly, blowup_factor, domain_size, &offset)
                    .unwrap();

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
                secret = StarkField::from(0);
            } else {
                log::info!(
                    "Successfully reconstructed secret for ASKS instance {}",
                    instance_id
                );
                secret = share_poly_coeffs[0].clone();
                // Invoke termination with
            }
            log::info!(
                "Sending back value to ACS: {} for ASKS instancce {}",
                secret,
                instance_id
            );
            self.terminate_reconstruct(instance_id, Some(secret)).await;
        }
    }

    // TODO: @sohamjog handle the terminate function
    pub async fn terminate_reconstruct(&mut self, instance_id: usize, secret: Option<StarkField>) {
        let instance: usize = instance_id % self.threshold;
        let rep = instance_id / self.threshold;

        if secret.is_none() {
            // Completed sharing
            // let msg: (usize, usize, Option<StarkField>) = (instance, rep, None);
            // TODO: Uncomment later
            // let status = self.out_asks_values.send(msg).await;
            // let cancel_handler = self
            //     .sync_send
            //     .send(
            //         0,
            //         SyncMsg {
            //             sender: self.myid,
            //             state: SyncState::COMPLETED,
            //             value: Vec::new(),
            //         },
            //     )
            //     .await;
            // self.add_cancel_handler(cancel_handler);

            log::info!("Sent result back to original channel {:?}", self.myid);
        } else {
            let new_secret = secret.clone();
            // Completed reconstruction of the secret
            let msg: (usize, usize, Option<StarkField>) =
                (instance, rep, Some(new_secret.unwrap()));
            // TODO: Uncomment later
            // let status = self.out_asks_values.send(msg).await;
            // Convert the secret to bytes
            // let secret_bytes: Vec<u8> = secret.unwrap().to_bytes_be().to_vec(); // .1 extracts the actual bytes

            // Send the message
            // let cancel_handler = self
            //     .sync_send
            //     .send(
            //         0,
            //         SyncMsg {
            //             sender: self.myid,
            //             state: SyncState::COMPLETED,
            //             value: secret_bytes,
            //         },
            //     )
            //     .await;
            // self.add_cancel_handler(cancel_handler);

            log::info!("Sent result back to original channel {:?}", self.myid);
        }
    }
}
