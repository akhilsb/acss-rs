use consensus::ShamirSecretSharing;
use consensus::get_shards;
use crypto::{
    aes_hash::MerkleTree,
    decrypt, encrypt,
    hash::{do_hash, Hash},
};
use ctrbc::CTRBCMsg;
use network::{plaintcp::CancelHandler, Acknowledgement};
use types::{Replica, WrapperMsg};

use crate::{
    context::Context,
    msg::{Commitment, ProtMsg, WSSMsg, WSSMsgSer},
};

use super::state::ASKSState;

impl Context {
    pub async fn init_asks(&mut self, instance_id: usize) {
        let rand_elem = ShamirSecretSharing::rand_field_element();
        // Sample secret polynomial first

        let coefficients = self.large_field_uv_sss.sample_polynomial(rand_elem);
        let nonce_coefficients = self.large_field_uv_sss.sample_polynomial(rand_elem);

        let shares = self.large_field_uv_sss.generating_shares(&coefficients);
        let nonce_shares = self
            .large_field_uv_sss
            .generating_shares(&nonce_coefficients);

        let commitments: Vec<Hash> = shares
            .clone()
            .into_iter()
            .zip(nonce_shares.clone().into_iter())
            .map(|(share, nonce)| {
                let mut appended_vec = Vec::new();
                appended_vec.extend(share.to_bytes_be());
                appended_vec.extend(nonce.to_bytes_be());
                return do_hash(appended_vec.as_slice());
            })
            .collect();

        let share_msgs: Vec<WSSMsg> = shares
            .into_iter()
            .zip(nonce_shares.into_iter())
            .map(|(share, nonce)| WSSMsg {
                share: share,
                nonce_share: nonce,
                origin: self.myid,
            })
            .collect();

        for (rep, share_msg) in (0..self.num_nodes).into_iter().zip(share_msgs.into_iter()) {
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            let wss_sermsg = WSSMsgSer::from_unser(&share_msg);
            let encrypted_share = encrypt(&secret_key, bincode::serialize(&wss_sermsg).unwrap());

            let prot_msg_init = ProtMsg::Init(encrypted_share, commitments.clone(), instance_id);
            let wrapper_msg = WrapperMsg::new(prot_msg_init, self.myid, &secret_key);
            let cancel_handler = self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }

    pub async fn process_init_asks(
        &mut self,
        enc_shares: Vec<u8>,
        comm: Commitment,
        sender: Replica,
        instance_id: usize,
    ) {
        // Decrypt message
        let secret_key_sender = self.sec_key_map.get(&sender).unwrap();
        let dec_msg = decrypt(&secret_key_sender, enc_shares);
        let deser_msg: WSSMsgSer = bincode::deserialize(dec_msg.as_slice()).unwrap();

        // Verify commitment
        let share_comm = deser_msg.compute_commitment();
        if comm[self.myid].clone() != share_comm {
            log::error!(
                "Error verifying share commitment, abandoning ASKS instance {}",
                instance_id
            );
            return;
        }

        let share = deser_msg.to_unser();

        if !self.asks_state.contains_key(&instance_id) {
            let new_state = ASKSState::new(sender);
            self.asks_state.insert(instance_id, new_state);
        }

        let new_asks_state = self.asks_state.get_mut(&instance_id).unwrap();

        new_asks_state.share = Some(share.share);
        new_asks_state.nonce_share = Some(share.nonce_share);

        // Start Echo and Ready phases of broadcast
        // Broadcast commitment
        let comm_ser = bincode::serialize(&comm).unwrap();
        let shards = get_shards(comm_ser, self.num_faults + 1, 2 * self.num_faults);
        let shard_hashes = shards
            .iter()
            .map(|shard| do_hash(shard.as_slice()))
            .collect();

        let mt = MerkleTree::new(shard_hashes, &self.hash_context);

        new_asks_state.verified_hash = Some(mt.root());
        new_asks_state.echo_sent = true;
        // Send ECHOs now
        for rep in 0..self.num_nodes {
            let secret_key_party = self.sec_key_map.get(&rep).clone().unwrap();

            let rbc_msg = CTRBCMsg {
                shard: shards[self.myid].clone(),
                mp: mt.gen_proof(self.myid),
                origin: sender,
            };

            let echo = ProtMsg::Echo(rbc_msg, instance_id);
            let wrapper_msg = WrapperMsg::new(echo, self.myid, secret_key_party.as_slice());

            let cancel_handler: CancelHandler<Acknowledgement> =
                self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }
}
