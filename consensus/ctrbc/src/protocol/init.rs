use consensus::get_shards;
use crypto::{
    aes_hash::{MerkleTree, HashState},
    hash::{do_hash, Hash},
};
use types::{WrapperMsg};

use crate::{Context};
use crate::{CTRBCMsg, ProtMsg};
use network::{plaintcp::CancelHandler, Acknowledgement};

impl Context {
    // Dealer sending message to everybody
    pub async fn start_init(self: &mut Context, msg:Vec<u8>, instance_id:usize) {
        let shards = get_shards(msg, self.num_faults+1, 2*self.num_faults);
        
        let merkle_tree = construct_merkle_tree(shards.clone(),&self.hash_context);
        
        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            
            let ctrbc_msg = CTRBCMsg {
                shard: shards[replica].clone(),
                mp: merkle_tree.gen_proof(replica),
                origin: self.myid,
            };
            
            if replica == self.myid {
                self.handle_init(ctrbc_msg,instance_id).await;
            } 
            
            else {
                let protocol_msg = ProtMsg::Init(ctrbc_msg, instance_id);
                let wrapper_msg = WrapperMsg::new(protocol_msg.clone(), self.myid, &sec_key.as_slice());
                let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
                self.add_cancel_handler(cancel_handler);
            }

        }
    }

    pub async fn handle_init(self: &mut Context, msg: CTRBCMsg, instance_id:usize) {
        //send echo
        // self.start_echo(msg.content.clone()).await;
        if !msg.verify_mr_proof(&self.hash_context) {
            log::error!(
                "Invalid Merkle Proof sent by node {}, abandoning RBC",
                msg.origin
            );
            return;
        }

        log::debug!(
            "Received Init message {:?} from node {}.",
            msg.shard,
            msg.origin,
        );

        let ctrbc_msg = CTRBCMsg {
            shard: msg.shard,
            mp: msg.mp,
            origin: msg.origin,
        };

        // Start echo
        self.handle_echo(ctrbc_msg.clone(), self.myid,instance_id).await;
        let protocol_msg = ProtMsg::Echo(ctrbc_msg, instance_id);

        self.broadcast(protocol_msg).await;

        // Invoke this function after terminating the protocol.
        //self.terminate("1".to_string()).await;
    }
}

pub fn construct_merkle_tree(shards:Vec<Vec<u8>>, hc: &HashState)->MerkleTree{
    let hashes_rbc: Vec<Hash> = shards
        .into_iter()
        .map(|x| do_hash(x.as_slice()))
        .collect();

    MerkleTree::new(hashes_rbc, hc)
}
