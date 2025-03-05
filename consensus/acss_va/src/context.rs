use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV4},
};

use anyhow::{anyhow, Result};
use config::Node;

use fnv::FnvHashMap;
use network::{
    plaintcp::{CancelHandler, TcpReceiver, TcpReliableSender},
    Acknowledgement,
};
use num_bigint_dig::{BigInt};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, Receiver, Sender},
    oneshot,
};
// use tokio_util::time::DelayQueue;
use types::{Replica,WrapperMsg};

use consensus::{SmallFieldSSS, LargeFieldSSS, FoldingDZKContext};

use crypto::{aes_hash::HashState, LargeField, LargeFieldSer, hash::Hash};

use crate::{msg::ProtMsg, handlers::Handler, protocol::BatchACSSState};

pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica, WrapperMsg<ProtMsg>, Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg<ProtMsg>>,
    
    /// Data context
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    byz: bool,

    /// Primes for computation
    pub small_field_prime: u64,
    pub large_field_prime: BigInt,

    /// Secret Key map
    pub sec_key_map: HashMap<Replica, Vec<u8>>,

    /// Hardware acceleration context
    pub hash_context: HashState,

    /// Cancel Handlers
    pub cancel_handlers: HashMap<u64, Vec<CancelHandler<Acknowledgement>>>,
    exit_rx: oneshot::Receiver<()>,
    
    // Each Reliable Broadcast instance is associated with a Unique Identifier. 
    // pub avid_context: HashMap<usize, ACSSState>,

    // Maximum number of RBCs that can be initiated by a node. Keep this as an identifier for RBC service. 
    pub threshold: usize, 

    pub max_id: usize,

    /// Shamir secret sharing states
    pub small_field_sss: SmallFieldSSS,
    pub large_field_sss: LargeFieldSSS,

    pub large_field_bv_sss: LargeFieldSSS,
    pub large_field_uv_sss: LargeFieldSSS,

    /// DZK Proof context
    pub folding_dzk_context: FoldingDZKContext,


    /// Constants for PRF seeding
    pub nonce_seed: usize,

    /// State for ACSS
    pub acss_state: HashMap<usize, BatchACSSState>,

    /// Input and output request channels
    pub inp_acss_requests: Receiver<(usize, Vec<LargeFieldSer>)>,
    pub out_acss_shares: Sender<(usize, usize, Hash, Vec<LargeFieldSer>)>
}

impl Context {
    pub fn spawn(config: Node, 
        inp_req_channel: Receiver<(usize, Vec<LargeFieldSer>)>,
        out_shares_channel: Sender<(usize, usize, Hash, Vec<LargeFieldSer>)>,
        byz: bool) -> anyhow::Result<oneshot::Sender<()>> {
        // Add a separate configuration for RBC service. 
        // Constants for RBC service as a channel

        let mut consensus_addrs: FnvHashMap<Replica, SocketAddr> = FnvHashMap::default();
        
        for (replica, address) in config.net_map.iter() {
            let address: SocketAddr = address.parse().expect("Unable to parse address");
            consensus_addrs.insert(*replica, SocketAddr::from(address.clone()));
        }


        let my_port = consensus_addrs.get(&config.id).unwrap();
        let my_address = to_socket_address("0.0.0.0", my_port.port());
        
        // Setup networking
        let (tx_net_to_consensus, rx_net_to_consensus) = unbounded_channel();
        TcpReceiver::<Acknowledgement, WrapperMsg<ProtMsg>, _>::spawn(
            my_address,
            Handler::new(tx_net_to_consensus),
        );

        let consensus_net = TcpReliableSender::<Replica, WrapperMsg<ProtMsg>, Acknowledgement>::with_peers(
            consensus_addrs.clone(),
        );
        let (exit_tx, exit_rx) = oneshot::channel();

        // Keyed AES ciphers
        let key0 = [5u8; 16];
        let key1 = [29u8; 16];
        let key2 = [23u8; 16];
        let hashstate = HashState::new(key0, key1, key2);
        let hashstate2 = HashState::new(key0, key1, key2);

        let threshold:usize = 10000;
        let rbc_start_id = threshold*config.id;

        let small_field_prime:u64 = 4294967291;
        let large_field_prime: BigInt = BigInt::parse_bytes(b"115792088158918333131516597762172392628570465465856793992332884130307292657121",10).unwrap();
        
        let large_field_prime_bv: BigInt = BigInt::parse_bytes(b"57896044618658097711785492504343953926634992332820282019728792003956564819949", 10).unwrap();
        
        //let small_field_prime = 37;
        //let large_field_prime: BigInt = BigInt::parse_bytes(b"1517", 10).unwrap();

        // Preload vandermonde matrix inverse to enable speedy polynomial coefficient interpolation
        let file_name_pattern = "data/ht/vandermonde_inverse-{}.json";
        let file_name_pattern_lt = "data/lt/vandermonde_inverse-{}.json";
        // // Save to file
        let file_path = file_name_pattern.replace("{}", config.num_nodes.to_string().as_str());
        let file_path_lt = file_name_pattern_lt.replace("{}", config.num_nodes.to_string().as_str());
        let smallfield_ss = SmallFieldSSS::new(
            config.num_faults+1, 
            config.num_nodes, 
            small_field_prime
        );
        // Blinding and Nonce polynomials
        let largefield_ss = LargeFieldSSS::new(
            config.num_faults+1, 
            config.num_nodes, 
            large_field_prime.clone()
        );

        let lf_bv_sss = LargeFieldSSS::new_with_vandermonde(
            2*config.num_faults +1, 
            config.num_nodes,
            file_path,
            large_field_prime_bv.clone(),
        );

        let lf_uv_sss = LargeFieldSSS::new_with_vandermonde(
            config.num_faults +1,
            config.num_nodes,
            file_path_lt,
            large_field_prime_bv.clone()
        );

        // Prepare dZK context for halving degrees
        let mut start_degree = config.num_faults as isize;
        let end_degree = 2 as usize;
        let mut ss_contexts = HashMap::default();
        while start_degree > 0 {
            let split_point;
            if start_degree % 2 == 0{
                split_point = start_degree/2;
            }
            else{
                split_point = (start_degree+1)/2;
            }
            start_degree = start_degree - split_point;
            ss_contexts.insert(start_degree,split_point);
        }
        //ss_contexts.insert(start_degree, lf_dzk_sss);

        // Folding context
        let folding_context = FoldingDZKContext{
            large_field_uv_sss: lf_uv_sss.get_fft_sss(),
            hash_context: hashstate2,
            poly_split_evaluation_map: ss_contexts,
            evaluation_points: (1..config.num_nodes+1).into_iter().collect(),
            recon_threshold: config.num_faults+1,
            end_degree_threshold: end_degree,
        };

        tokio::spawn(async move {
            let mut c = Context {
                net_send: consensus_net,
                net_recv: rx_net_to_consensus,
                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                hash_context: hashstate,
                myid: config.id,
                byz: byz,
                num_faults: config.num_faults,
                cancel_handlers: HashMap::default(),
                exit_rx: exit_rx,
                
                small_field_prime: small_field_prime,
                large_field_prime: large_field_prime,

                //avid_context:HashMap::default(),
                threshold: 10000,

                max_id: rbc_start_id, 

                small_field_sss: smallfield_ss,
                large_field_sss: largefield_ss,

                large_field_bv_sss: lf_bv_sss,
                large_field_uv_sss: lf_uv_sss,

                folding_dzk_context:folding_context,

                acss_state: HashMap::default(),
                nonce_seed: 1,

                inp_acss_requests: inp_req_channel,
                out_acss_shares: out_shares_channel
            };

            // Populate secret keys from config
            for (id, sk_data) in config.sk_map.clone() {
                c.sec_key_map.insert(id, sk_data.clone());
            }

            // Run the consensus context
            if let Err(e) = c.run().await {
                log::error!("Consensus error: {}", e);
            }
        });
        Ok(exit_tx)
    }

    pub async fn broadcast(&mut self, protmsg: ProtMsg) {
        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            if self.byz && replica % 2 == 0 {
                // Simulates a crash fault
                continue;
            }
            if replica != self.myid {
                let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice());
                let cancel_handler: CancelHandler<Acknowledgement> =
                    self.net_send.send(replica, wrapper_msg).await;
                self.add_cancel_handler(cancel_handler);
            }
        }
    }

    pub fn add_cancel_handler(&mut self, canc: CancelHandler<Acknowledgement>) {
        self.cancel_handlers.entry(0).or_default().push(canc);
    }

    pub async fn send(&mut self, replica: Replica, wrapper_msg: WrapperMsg<ProtMsg>) {
        let cancel_handler: CancelHandler<Acknowledgement> =
            self.net_send.send(replica, wrapper_msg).await;
        self.add_cancel_handler(cancel_handler);
    }

    pub async fn run(&mut self) -> Result<()> {
        // The process starts listening to messages in this process.
        
        loop {
            tokio::select! {
                // Receive exit handlers
                exit_val = &mut self.exit_rx => {
                    exit_val.map_err(anyhow::Error::new)?;
                    log::info!("Termination signal received by the server. Exiting.");
                    break
                },
                msg = self.net_recv.recv() => {
                    // Received messages are processed here
                    log::trace!("Got a consensus message from the network: {:?}", msg);
                    let msg = msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    self.process_msg(msg).await;
                },
                acss_req_msg = self.inp_acss_requests.recv() => {
                    let acss_msg = acss_req_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    let acss_inst_id = self.myid*self.threshold + acss_msg.0;
                    let acss_share_msgs_ser = acss_msg.1;
                    let acss_lf_secrets: Vec<LargeField> = acss_share_msgs_ser.into_iter().map(|x| LargeField::from_signed_bytes_be(x.as_slice())).collect();
                    self.init_batch_acss_va(acss_lf_secrets, acss_inst_id).await;
                }
            };
        }
        Ok(())
    }
}

pub fn to_socket_address(ip_str: &str, port: u16) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}
