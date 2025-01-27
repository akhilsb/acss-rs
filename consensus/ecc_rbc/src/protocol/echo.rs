use crypto::hash::{do_hash, Hash};
use reed_solomon_rs::fec::fec::*;

use crate::{Context, ShareMsg, ProtMsg};
use types::WrapperMsg;

use network::{plaintcp::CancelHandler, Acknowledgement};
impl Context {
    pub async fn echo_self(&mut self, hash: Hash, share: Share, instance_id: usize) {
        let msg = ShareMsg {
            share: share.clone(),
            hash,
            origin: self.myid,
        };
        self.handle_echo(msg, instance_id).await;
    }
    pub async fn start_echo(self: &mut Context, msg_content: Vec<u8>, instance_id: usize) {
        let hash = do_hash(&msg_content);

        let f = match FEC::new(self.num_faults, self.num_nodes) {
            Ok(f) => f,
            Err(e) => {
                log::info!("FEC initialization failed with error: {:?}", e);
                return;
            }
        };
        let mut shares: Vec<Share> = vec![
            Share {
                number: 0,
                data: vec![]
            };
            self.num_nodes
        ];
        {
            let output = |s: Share| {
                shares[s.number] = s.clone(); // deep copy
            };
            if let Err(e) = f.encode(&msg_content, output) {
                log::info!("Encoding failed with error: {:?}", e);
            }
            //f.encode(&msg_content, output)?;
        }
        let rbc_context = self.rbc_context.entry(instance_id).or_default();
        rbc_context.fragment = shares[self.myid].clone();

        log::info!("Shares: {:?}", shares);

        // Echo to every node the encoding corresponding to the replica id
        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            if replica == self.myid {
                self.echo_self(hash, shares[self.myid].clone(), instance_id).await;
                continue;
            }
            let msg = ShareMsg {
                share: shares[replica].clone(),
                hash,
                origin: self.myid,
            };
            let protocol_msg = ProtMsg::Echo(msg, instance_id);
            let wrapper_msg = WrapperMsg::new(protocol_msg.clone(), self.myid, &sec_key.as_slice());
            let cancel_handler: CancelHandler<Acknowledgement> =
            self.net_send.send(replica, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }

    pub async fn handle_echo(self: &mut Context, msg: ShareMsg, instance_id: usize) {
        let rbc_context = self.rbc_context.entry(instance_id).or_default();

        let senders = rbc_context.echo_senders.entry(msg.hash).or_default();

        // Only count if we haven't seen an echo from this sender for this message
        if senders.insert(msg.origin) {
            *rbc_context.received_echo_count.entry(msg.hash).or_default() += 1;

            // let count = self.received_echo_count.get(&msg.content).unwrap();
            let mut mode_content: Option<Hash> = None;
            let mut max_count = 0;

            for (content, &count) in rbc_context.received_echo_count.iter() {
                if count > max_count {
                    max_count = count;
                    mode_content = Some(content.clone());
                }
            }

            // Check if we've received n - techoes for this message
            if max_count == self.num_nodes - self.num_faults {
                //<Ready, f(your own fragment), h> to everyone
                if let Some(hash) = mode_content {
                    self.start_ready(hash, instance_id).await;
                }
            }
        }
    }
}
