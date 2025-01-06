use std::{ time::SystemTime};

use async_recursion::async_recursion;
use consensus::get_shards;
use crypto::{hash::{do_hash, Hash}, aes_hash::MerkleTree};
use num_bigint::{BigUint, RandBigInt};
use types::{beacon::{BatchWSSMsg, CoinMsg, CTRBCMsg, WrapperMsg, Val}, Replica, beacon::{Round, BeaconMsg}};

/**
 * The functions in this file instantiate the Batched Asynchronous weak Verifiable Secret Sharing (BAwVSS) protocol. 
 * 
 * In this protocol, nodes use Hash functions to instantiate a weak VSS protocol. Refer to our paper for more details about the protocol. 
 */

impl Context{
    #[async_recursion]
    pub async fn start_new_round(&mut self, round:Round,vec_round_vals:Vec<(Round,Vec<(Replica,BigUint)>)>){
        let now = SystemTime::now();
        
        log::info!("Protocol started");
        let mut beacon_msgs = Vec::new();
        let mut rbc_vec = Vec::new();
        let vec_round_msgs:Vec<(Round,Vec<(Replica,Val)>)> = vec_round_vals.into_iter().map(|(x,y)| {
            let mut msgs_vec = Vec::new();
            for (rep,val) in y.into_iter(){
                msgs_vec.push((rep,Self::pad_shares(val)));
            }
            return (x,msgs_vec);
        }).collect();
        // Start a new BAwVSS instance once every frequency rounds. 
        if new_round%self.frequency == 0{
            // Start Batched AwVSS. 
            let faults = self.num_faults;
            // Secret number can be increased to any number possible, but there exists a performance tradeoff with the size of RBC increasing
            // Each BAwVSS instance shares self.batch_size secrets. 
            let batch_size = self.batch_size;
            let low_r = BigUint::from(0u32);
            let prime = self.secret_domain.clone();
            let nonce_prime = self.nonce_domain.clone();

            let mut share_vec:Vec<[u8;32]> = Vec::new();
            let mut nonce_share_vec:Vec<[u8;32]> = Vec::new();
            // The following code combines shares from all secrets into a single shares vector, a single nonce vector
            // This singular vector conversion allows us to use the hash_batch API effectively. 
            for _i in 0..batch_size+1{
                let secret = rand::thread_rng().gen_biguint_range(&low_r, &prime.clone());
                let nonce = rand::thread_rng().gen_biguint_range(&low_r, &nonce_prime.clone());
                // Use Shamir Secret Sharing to create n secret shares
                let shamir_ss = ShamirSecretSharing{
                    threshold:faults+1,
                    share_amount:3*faults+1,
                    prime: prime.clone()
                };
                // Use Shamir Secret Sharing to create n nonce shares
                let nonce_ss = ShamirSecretSharing{
                    threshold:faults+1,
                    share_amount:3*faults+1,
                    prime: nonce_prime.clone(),
                };
                let shares = shamir_ss.split(secret);
                let nonce_shares = nonce_ss.split(nonce);
                for (shares,nonces) in shares.clone().into_iter().zip(nonce_shares.clone().into_iter()){
                    let share_bytes = Self::pad_shares(shares.1);
                    let nonce_share_bytes = Self::pad_shares(nonces.1);
                    share_vec.push(share_bytes);
                    nonce_share_vec.push(nonce_share_bytes);
                }
                //secret_shares.push(shamir_ss.split(secret));
                //nonce_shares.push(nonce_ss.split(nonce));
            }
            let commitments = self.hash_context.hash_batch(share_vec.clone(), nonce_share_vec.clone());
            let share_comm_iter = share_vec.into_iter().zip(nonce_share_vec.into_iter()).zip(commitments.into_iter());
            let mut secret_num:usize = 1;
            
            // Vector of shares and commitments. Each element contains the shares and commitments of a single secret
            let mut share_comm_hash = Vec::new();
            let mut hashes_vec: Vec<Vec<Hash>> = Vec::new();

            // Each vector contains $n$ shares and commitments of shares of each secret. 
            let mut share_comm_single_secret = Vec::new(); 
            let mut hashes_vec_single_secret= Vec::new();
            for ((share,nonce),comm) in share_comm_iter.into_iter(){
                if secret_num == self.num_nodes +1{
                    secret_num = 1;

                    // One batch of shares is complete. Add vector to master vector
                    share_comm_hash.push(share_comm_single_secret);
                    hashes_vec.push(hashes_vec_single_secret);

                    share_comm_single_secret = Vec::new();
                    hashes_vec_single_secret = Vec::new();
                }
                share_comm_single_secret.push((share,nonce,comm.clone()));
                hashes_vec_single_secret.push(comm);
                secret_num += 1;
            }

            // Create a Merkle tree on top of secret shares to generate a commitment
            let mt_vec = MerkleTree::build_trees(hashes_vec, &self.hash_context);

            //let mut hashes_ms:Vec<Vec<Hash>> = Vec::new();
            // // (Replica, Secret, Random Nonce, One-way commitment)
            // let share_comm_hash:Vec<Vec<(usize,Vec<u8>,Vec<u8>,Hash)>> = secret_shares.clone().iter().zip(nonce_shares.iter()).into_iter().map(|(y,nonce)| {
            //     let mut hashes:Vec<Hash> = Vec::new();
            //     let acc_secs:Vec<(usize, Vec<u8>, Vec<u8>, Hash)> = y.iter().zip(nonce.iter()).map(|(x,non)| {
            //         // H(R,X)

            //         let added_secret = non.1.clone()+x.1.clone();
            //         let comm_secret = added_secret.to_bytes_be();
            //         let hash:Hash = do_hash(comm_secret.as_slice());
                    
            //         // R
            //         let vec_comm = non.1.to_bytes_be();
            //         hashes.push(hash.clone());

            //         // (Replica,Secret share, Nonce Share, Commitment)
            //         (x.0,x.1.to_bytes_be(),vec_comm.clone(),hash)    
            //     }).collect();
            //     hashes_ms.push(hashes);
            //     acc_secs
            // }).collect();
            // Create a vector of self.batch_size Merkle trees. 
            //let merkle_tree_vec:Vec<MerkleTree<Hash, HashingAlg>> = hashes_ms.into_iter().map(|x| MerkleTree::from_iter(x.into_iter())).collect();
            let mut vec_msgs_to_be_sent:Vec<(Replica,BatchWSSMsg)> = Vec::new();
            
            for i in 0..self.num_nodes{
                vec_msgs_to_be_sent.push((i+1,
                    BatchWSSMsg::new( self.myid,Vec::new(), Vec::new(), Vec::new())));
            }
            let mut roots_vec:Vec<Hash> = Vec::new();
            //let mut master_vec:Vec<u8> = Vec::new();
            for (vec,mt) in share_comm_hash.into_iter().zip(mt_vec.into_iter()).into_iter(){
                let mut i = 0;
                for y in vec.into_iter(){
                    // Secret shares
                    vec_msgs_to_be_sent[i].1.secrets.push(y.0);
                    // Commitments
                    vec_msgs_to_be_sent[i].1.nonces.push(y.1);
                    // Merkle proofs from the commitment to the Merkle root
                    vec_msgs_to_be_sent[i].1.mps.push(mt.gen_proof(i));
                    i = i+1;
                }
                roots_vec.push(mt.root());
                //master_vec.append(&mut Vec::from(mt.root()));
            }
            for (rep,batchwss) in vec_msgs_to_be_sent.into_iter(){
                let beacon_msg = BeaconMsg::new(self.myid, new_round, batchwss,roots_vec.clone(), vec_round_msgs.clone());
                // TODO: Bad way of extracting a message.
                // This rbc_vec variable is used in the future to Reliably broadcast the Merkle root vector.  
                if rep == 1{
                    rbc_vec = beacon_msg.clone().serialize_ctrbc();
                }
                // else{
                //     assert!(do_hash(rbc_vec.as_slice()).iter().zip(do_hash(beacon_msg.serialize_ctrbc().as_slice()).iter()).all(|(a,b)| a == b), "Hashes are not equal");
                // }
                beacon_msgs.push((rep,beacon_msg));
            }
        }
        else{
            for i in 0..self.num_nodes{
                let beacon_msg = BeaconMsg::new_with_appx(self.myid, new_round, vec_round_msgs.clone());
                // TODO: Bad way of extracting a message.
                // This rbc_vec variable is used in the future to Reliably broadcast the Merkle root vector. 
                if i==0{
                    rbc_vec = beacon_msg.clone().serialize_ctrbc();
                }
                // else{
                //     assert!(do_hash(rbc_vec.as_slice()).iter().zip(do_hash(beacon_msg.serialize_ctrbc().as_slice()).iter()).all(|(a,b)| a == b), "Hashes are not equal");
                // }
                beacon_msgs.push((i+1,beacon_msg));
            }
        }
        // Use SHA256 only here and nowhere else. This is because AES hash can only perform 2:1 compression. 
        let shards = get_shards(rbc_vec, self.num_faults+1, 2*self.num_faults);
        // Construct Merkle tree
        let hashes_rbc:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
        let merkle_tree = MerkleTree::new(hashes_rbc,&self.hash_context);
        for (rep,beacon_msg) in beacon_msgs.into_iter(){
            let replica = rep.clone()-1;
            let sec_key = self.sec_key_map.get(&replica).unwrap().clone();
            let ctrbc_msg = CTRBCMsg::new(
                shards[replica].clone(), 
                merkle_tree.gen_proof(replica), 
                new_round,
                self.myid
            );
            // Logging purposes: Verify your Merkle Proof
            //log::info!("Mp verification {}",ctrbc_msg.verify_mr_proof());
            // TODO: we cannot send a message to ourself today
            if replica != self.myid{
                //batch_wss.master_root = master_root.clone();
                // Use Cachin-Tessaro's Reliable Broadcast to broadcast the root vector
                let beacon_init = CoinMsg::CTRBCInit(beacon_msg,ctrbc_msg);
                // send shares over a private channel
                let wrapper_msg = WrapperMsg::new(beacon_init, self.myid, &sec_key,new_round);
                self.send(replica, wrapper_msg).await;
            }
            else {
                self.process_rbcinit(beacon_msg,ctrbc_msg).await;
            }
        }
        // Proceed to the next round
        if new_round > 0{
            self.increment_round(round).await;
        }
        self.add_benchmark(String::from("start_batchwss"), now.elapsed().unwrap().as_nanos());
    }

    pub fn pad_shares(inp:BigUint)->[u8;32]{
        let mut byte_arr = inp.to_bytes_be();
        if byte_arr.len() > 32{
            panic!("All inputs must be within 32 bytes");
        }
        else {
            let mut vec_zeros = vec![0u8;32-byte_arr.len()];
            vec_zeros.append(&mut byte_arr);
            vec_zeros.try_into().unwrap_or_else(
                |v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", 32, v.len())
            )
        }
    }
}