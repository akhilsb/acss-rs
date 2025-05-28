use consensus::get_shards;
use crypto::{LargeField, hash::{do_hash, Hash}, encrypt, decrypt, aes_hash::{MerkleTree, Proof}, rand_field_element};
use ctrbc::CTRBCMsg;
use network::{plaintcp::CancelHandler, Acknowledgement};
use types::{WrapperMsg, Replica};

use crate::{context::Context, msg::{WSSMsg, WSSMsgSer, ProtMsg}};

use super::state::ASKSState;

impl Context{
    pub async fn init_asks(&mut self, instance_id: usize, num_secrets: usize, reconstruct_to_all: bool, secret_vec: Option<Vec<LargeField>>){        
        log::info!("Got request to initialize ASKS instance {} with {} secrets, reconstruct_all_to_all: {}", instance_id,num_secrets, reconstruct_to_all);
        // Sample secret polynomial first
        let mut shares_vec = Vec::new();
        let mut nonce_shares_vec = Vec::new();
        let mut merkle_roots = Vec::new();
        let mut merkle_proofs_vec = Vec::new();

        for _ in 0..self.num_nodes{
            shares_vec.push(Vec::new());
            nonce_shares_vec.push(Vec::new());
            merkle_proofs_vec.push(Vec::new());
        }

        for index in 0..num_secrets{
            let mut coefficients;
            if secret_vec.is_some(){
                coefficients = vec![secret_vec.as_ref().unwrap()[index].clone()];
            }
            else{
                coefficients = vec![rand_field_element()];
            }
            let sampled_coeffs: Vec<LargeField> = (1..self.num_faults+1).into_iter().map(|_| 
                rand_field_element()
            ).collect();
            coefficients.extend(sampled_coeffs);
            
            let nonce_coefficients: Vec<LargeField> = (0..self.num_faults+1).into_iter().map(|_| 
                rand_field_element()
            ).collect();
    
            let shares: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|point|
                self.large_field_uv_sss.mod_evaluate_at(&coefficients, point)
            ).collect();
    
            let nonce_shares: Vec<LargeField> = (1..self.num_nodes+1).into_iter().map(|point|
                self.large_field_uv_sss.mod_evaluate_at(&nonce_coefficients, point)
            ).collect();
    
            let commitments: Vec<Hash> = shares.clone().into_iter().zip(nonce_shares.clone().into_iter()).map(|(share,nonce)|{
                let mut appended_vec = Vec::new();
                appended_vec.extend(share.to_bytes_be());
                appended_vec.extend(nonce.to_bytes_be());
                return do_hash(appended_vec.as_slice());
            }).collect();

            let merkle_tree = MerkleTree::new(commitments,&self.hash_context);
            merkle_roots.push(merkle_tree.root());

            let merkle_proofs: Vec<Proof> = (0..self.num_nodes).into_iter().map(|i| merkle_tree.gen_proof(i)).collect();
            // Add shares, nonce_shares, merkle proofs to the respective vectors
            for (((index, share),nonce), proof) in (shares.into_iter().enumerate().zip(nonce_shares.into_iter())).zip(merkle_proofs.into_iter()){
                shares_vec[index].push(share);
                nonce_shares_vec[index].push(nonce);
                merkle_proofs_vec[index].push(proof);
            }
        }
        
        let mut share_message_vec = Vec::new();
        for ((shares, nonce_shares), proofs) in (shares_vec.into_iter().zip(nonce_shares_vec.into_iter())).zip(merkle_proofs_vec.into_iter()){
            let wss_shares_msg = WSSMsg{
                shares: shares,
                nonce_shares: nonce_shares,
                merkle_proofs: proofs,
                reconstruct_to_all: reconstruct_to_all,
                origin: self.myid
            };
            share_message_vec.push(wss_shares_msg);
        }

        for (rep, share_msg) in (0..self.num_nodes).into_iter().zip(share_message_vec.into_iter()){
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            let wss_sermsg = WSSMsgSer::from_unser(&share_msg);
            let encrypted_share = encrypt(&secret_key, bincode::serialize(&wss_sermsg).unwrap());

            let prot_msg_init = ProtMsg::Init( encrypted_share, instance_id);
            let wrapper_msg = WrapperMsg::new(prot_msg_init, self.myid, &secret_key);
            let cancel_handler = self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }

    pub async fn process_init_asks(&mut self, enc_shares: Vec<u8>, sender: Replica, instance_id: usize){
        // Decrypt message
        log::info!("Processing Init ASKS message from party {} in instance id {}", sender, instance_id);
        let secret_key_sender = self.sec_key_map.get(&sender).unwrap();
        let dec_msg = decrypt(&secret_key_sender, enc_shares);
        let deser_msg: WSSMsgSer = bincode::deserialize(dec_msg.as_slice()).unwrap();
        
        // Verify commitment
        let share_comm = deser_msg.compute_commitments();
        let share_msg = deser_msg.to_unser();
        let mut bool_flag = true;
        for (proof,item) in share_msg.merkle_proofs.iter().zip(share_comm.iter()){
            bool_flag &= proof.validate(&self.hash_context) && (proof.item() == *item);
        }
        if bool_flag == false{
            log::error!("Merkle Proof validation failed for ASKS instance instantiated by party {} in instance id {}", sender, instance_id);
            return;
        }

        let roots: Vec<Hash> = share_msg.merkle_proofs.iter().map(|x| x.root()).collect();

        if !self.asks_state.contains_key(&instance_id){
            let new_state = ASKSState::new(sender, deser_msg.reconstruct_to_all);
            self.asks_state.insert(instance_id, new_state);
        }

        let new_asks_state = self.asks_state.get_mut(&instance_id).unwrap();

        new_asks_state.shares = Some(share_msg.shares);
        new_asks_state.nonce_shares = Some(share_msg.nonce_shares);
        new_asks_state.merkle_proofs = Some(share_msg.merkle_proofs);
        
        // Start Echo and Ready phases of broadcast
        // Broadcast commitment
        let comm_ser = bincode::serialize(&roots).unwrap();
        let shards = get_shards(comm_ser, self.num_faults+1, 2*self.num_faults);
        let shard_hashes = shards.iter().map(|shard| do_hash(shard.as_slice())).collect();

        let mt = MerkleTree::new(shard_hashes, &self.hash_context);

        new_asks_state.verified_hash = Some(mt.root());
        new_asks_state.echo_sent = true;
        // Send ECHOs now
        for rep in 0..self.num_nodes{
            let secret_key_party = self.sec_key_map.get(&rep).clone().unwrap();

            let rbc_msg = CTRBCMsg{
                shard: shards[self.myid].clone(),
                mp: mt.gen_proof(self.myid),
                origin: sender,
            };

            let echo = ProtMsg::Echo(rbc_msg, deser_msg.reconstruct_to_all, instance_id);
            let wrapper_msg = WrapperMsg::new(echo,self.myid, secret_key_party.as_slice());

            let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }
}