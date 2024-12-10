use super::{ProtMsg, ShareMsg};
use types::WrapperMsg;
use crypto::hash::Hash;
use network::{plaintcp::CancelHandler, Acknowledgement};
use reed_solomon_rs::fec::fec::FEC;

use super::Context;
impl Context {
    pub async fn ready_self(&mut self, hash: Hash) {
        let msg = ShareMsg {
            share: self.fragment.clone(),
            hash,
            origin: self.myid,
        };
        self.handle_ready(msg).await;
    }

    pub async fn start_ready(self: &mut Context, hash: Hash) {
        // Draft a message
        let msg = ShareMsg {
            share: self.fragment.clone(),
            hash,
            origin: self.myid,
        };
        // Wrap the message in a type
        let protocol_msg = ProtMsg::Ready(msg, self.myid);

        // Echo to every node the encoding corresponding to the replica id
        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            if replica == self.myid {
                self.ready_self(hash).await;
                continue;
            }
            let wrapper_msg = WrapperMsg::new(protocol_msg.clone(), self.myid, &sec_key.as_slice());
            let cancel_handler: CancelHandler<Acknowledgement> =
                self.net_send.send(replica, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }

    // TODO: handle ready
    pub async fn handle_ready(self: &mut Context, msg: ShareMsg) {
        if self.done {
            self.terminate("1".to_string()).await;
        }
        log::info!("Received {:?} as ready", msg);

        let senders = self.ready_senders.entry(msg.hash.clone()).or_default();

        if senders.insert(msg.origin) {
            let shares = self.received_readys.entry(msg.hash.clone()).or_default();
            shares.push(msg.share);

            let mut max_shares_count = 0;
            let mut max_shares_hash: Option<Hash> = None;

            // Find the hash with the most shares
            for (hash, shares_vec) in self.received_readys.iter() {
                if shares_vec.len() > max_shares_count {
                    max_shares_count = shares_vec.len();
                    max_shares_hash = Some(hash.clone());
                }
            }

            // If we have enough shares for a hash, prepare for error correction
            if max_shares_count >= self.num_nodes - self.num_faults {
                if let Some(hash) = max_shares_hash {
                    let shares_for_correction = self.received_readys.get(&hash).unwrap();
                    // TODO: Implement error correction on shares_for_correction
                    let f = match FEC::new(self.num_faults, self.num_nodes) {
                        Ok(f) => f,
                        Err(e) => {
                            log::info!("FEC initialization failed with error: {:?}", e);
                            return;
                        }
                    };
                    log::info!("Decoding {:?}", shares_for_correction.to_vec());
                    match f.decode([].to_vec(), shares_for_correction.to_vec()) {
                        Ok(data) => {
                            log::info!("Outputting: {:?}", data);
                            self.done = true;
                        }
                        Err(e) => {
                            log::info!("Decoding failed with error: {}", e.to_string());
                        }
                    }
                    if self.done {
                        self.terminate("1".to_string()).await;
                    }
                }
            }
        }
    }
}
