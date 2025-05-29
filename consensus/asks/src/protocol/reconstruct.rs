use std::collections::HashMap;

use crypto::{LargeField, hash::{do_hash, Hash}, aes_hash::MerkleTree};
use lambdaworks_math::polynomial::Polynomial;
use types::WrapperMsg;

use crate::{context::Context, msg::{WSSMsg, WSSMsgSer, ProtMsg}};

use super::ASKSState;

impl Context{
    pub async fn reconstruct_asks(&mut self, instance_id: usize, reconstruct_to_all: bool){
        if !self.asks_state.contains_key(&instance_id){
            log::error!("Do not possess ASKS state with the given instance ID {}", instance_id);
            return;
        }

        let asks_context = self.asks_state.get(&instance_id).unwrap();
        // Check if the reconstruction needs to be all-to-all or just to a single dealer
        if asks_context.shares.is_some(){
            if reconstruct_to_all{
                let share_msg = WSSMsg{
                    shares: asks_context.shares.clone().unwrap(),
                    nonce_shares: asks_context.nonce_shares.clone().unwrap(),
                    merkle_proofs: asks_context.merkle_proofs.clone().unwrap(),
                    reconstruct_to_all: reconstruct_to_all,
                    origin: asks_context.origin
                };
                let share_msg_ser = WSSMsgSer::from_unser(&share_msg);
                // Broadcast message
                self.broadcast(ProtMsg::Reconstruct(share_msg_ser, instance_id)).await;
            }
            else{
                let shares = asks_context.shares.clone().unwrap();
                let nonce_shares = asks_context.nonce_shares.clone().unwrap();
                let merkle_proofs = asks_context.merkle_proofs.clone().unwrap();
                let origin = asks_context.origin.clone();
                for (((index, share), nonce_share), merkle_proof) in (shares.iter().enumerate().zip(nonce_shares.iter())).zip(merkle_proofs.iter()){
                    
                    let share_msg = WSSMsg{
                        shares: vec![share.clone()],
                        nonce_shares: vec![nonce_share.clone()],
                        merkle_proofs: vec![merkle_proof.clone()],
                        reconstruct_to_all: reconstruct_to_all,
                        origin: origin
                    };
                    let share_msg_ser = WSSMsgSer::from_unser(&share_msg);
                    let sec_key = self.sec_key_map.get(&index).clone().unwrap();
                    let wrapper_msg = WrapperMsg::new(
                        ProtMsg::Reconstruct(share_msg_ser, instance_id),
                        self.myid, 
                        sec_key
                    );
                    let cancel_handler = self.net_send.send(index, wrapper_msg).await;
                    self.add_cancel_handler(cancel_handler);
                }
            }
        }
        else{
            log::info!("Did not receive share from dealer of instance id {}", instance_id);
            return;
        }
    }

    pub async fn process_asks_reconstruct(&mut self, share: WSSMsgSer, share_sender: usize, instance_id: usize){
        if !self.asks_state.contains_key(&instance_id){
            let new_state = ASKSState::new(share.origin, share.reconstruct_to_all);
            self.asks_state.insert(instance_id, new_state);
        }

        let asks_state = self.asks_state.get_mut(&instance_id).unwrap();
        if asks_state.rbc_state.message.is_none() || asks_state.roots.is_none(){
            log::error!("RBC did not terminate for this party yet for ASKS instance id {}, skipping share processing", instance_id);
            return;
        }

        let mut roots = asks_state.roots.clone().unwrap();

        // compute commitment of share and match it with terminated commitments
        let share_comm: Vec<Hash> = share.merkle_proofs.iter().map(|proof| proof.root()).collect();
        if !asks_state.reconstruct_to_all{
            roots = vec![roots[self.myid].clone()];
        }

        if share_comm != roots{
            log::error!("Commitment does not match broadcasted commitment for ASKS instance {}", instance_id);
            return;
        }

        let deser_share = share.to_unser();
        if asks_state.secret_shares.len() < deser_share.shares.len(){
            // append remaining vectors to the list
            for _ in 0..deser_share.shares.len() - asks_state.secret_shares.len(){
                asks_state.secret_shares.push(HashMap::new());
            }
        }
        let mut recon_commitments = Vec::new();
        let mut secrets = Vec::new();
        for (share_map, (share,nonce)) in asks_state.secret_shares.iter_mut().zip(deser_share.shares.iter().zip(deser_share.nonce_shares.iter())){
            share_map.insert(share_sender , (share.clone(), nonce.clone()));
            if share_map.len() == self.num_faults +1 {
                // Interpolate polynomial shares and coefficients
                let mut share_poly_shares = Vec::new();
                let mut nonce_poly_shares = Vec::new();
                let mut evaluation_indices = Vec::new();
    
                for rep in 0..self.num_nodes{
                    if share_map.contains_key(&rep){
                        let shares_party = share_map.get(&rep).unwrap();
                        let evaluation_index = LargeField::from((rep+1) as u64);
                        evaluation_indices.push(evaluation_index);
                        share_poly_shares.push(shares_party.0.clone());
                        nonce_poly_shares.push(shares_party.1.clone());
                    }
                }
                
                // Interpolate polynomial
                let share_poly_coeffs = Polynomial::interpolate(&evaluation_indices, &share_poly_shares).unwrap();
                let nonce_poly_coeffs = Polynomial::interpolate(&evaluation_indices, &nonce_poly_shares).unwrap();
                
                let all_shares: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|val| share_poly_coeffs.evaluate(&LargeField::from(val as u64))).collect();
                let nonce_all_shares: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|val| nonce_poly_coeffs.evaluate(&LargeField::from(val as u64))).collect();
                
                // Compute and match commitments
                let all_commitments: Vec<Hash> = all_shares.into_iter().zip(nonce_all_shares.into_iter()).map(|(share,nonce)|{
                    let mut appended_vec = Vec::new();
                    appended_vec.extend(share.to_bytes_be());
                    appended_vec.extend(nonce.to_bytes_be());
                    return do_hash(appended_vec.as_slice());
                }).collect();
                
                let root_comm = MerkleTree::new(all_commitments, &self.hash_context).root();
                log::info!("Reconstructed roots in ASKS instance {} initiated by party {}", instance_id, instance_id/self.threshold);
                
                recon_commitments.push(root_comm);
                let secret = share_poly_coeffs.evaluate(&LargeField::zero()).clone();
                secrets.push(secret);
            }
        }
        if !recon_commitments.is_empty(){
            if asks_state.reconstruct_to_all{
                // Match state roots of all secrets
                for ((index,recon_comm), broadcast_comm) in recon_commitments.into_iter().enumerate().zip(roots.into_iter()){
                    if recon_comm != broadcast_comm {
                        log::error!("Reconstructed commitment does not match the state roots for ASKS instance {}", instance_id);
                        secrets[index] = LargeField::from(0 as u64);
                    }
                }
            }
            else{
                // Else get the ith root from the set of commitments
                let my_commitment = roots[0].clone();
                let recon_comm = recon_commitments[0].clone();
                if recon_comm != my_commitment{
                    log::error!("Reconstructed commitment does not match the state roots for ASKS instance {} for secret key reconstruction", instance_id);
                    secrets[0] = LargeField::from(0 as u64);
                }
            }
            
            log::info!("Sending back value to ACS: {:?} for ASKS instance {}", secrets,instance_id);
            self.terminate(instance_id, Some(secrets)).await;
        }
    }
}