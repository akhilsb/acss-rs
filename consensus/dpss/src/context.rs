use std::{
    collections::{HashMap, HashSet},
    net::{SocketAddr, SocketAddrV4},
    time::{SystemTime, UNIX_EPOCH},
};
use anyhow::{anyhow, Result};
use config::Node;

use fnv::FnvHashMap;
use network::{
    plaintcp::{CancelHandler, TcpReceiver, TcpReliableSender},
    Acknowledgement,
};
use signal_hook::{iterator::Signals, consts::{SIGINT, SIGTERM}};
use tokio::{sync::{
    mpsc::{UnboundedReceiver, Sender, Receiver, channel, unbounded_channel},
    oneshot,
}};
// use tokio_util::time::DelayQueue;
use types::{Replica, SyncMsg, SyncState, WrapperMsg};

use consensus::{SyncHandler, LargeFieldSSS, LargeField};
use crypto::{aes_hash::HashState, hash::Hash};

use crate::{msg::ProtMsg, Handler, protocol::DPSSState};

pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica, WrapperMsg<ProtMsg>, Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg<ProtMsg>>,
    pub sync_send: TcpReliableSender<Replica, SyncMsg, Acknowledgement>,
    pub sync_recv: UnboundedReceiver<SyncMsg>,
    /// Data context
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    _byz: bool,


    pub large_field_shamir_ss: LargeFieldSSS,
    /// Secret Key map
    pub sec_key_map: HashMap<Replica, Vec<u8>>,

    /// Hardware acceleration context
    pub hash_context: HashState,

    /// Cancel Handlers
    pub cancel_handlers: HashMap<u64, Vec<CancelHandler<Acknowledgement>>>,
    exit_rx: oneshot::Receiver<()>,

    pub num_batches: usize,
    pub per_batch: usize,

    // Maximum number of RBCs that can be initiated by a node. Keep this as an identifier for RBC service. 
    pub threshold: usize, 

    pub max_id: usize,

    /// Constants for PRF seeding
    pub nonce_seed: usize,

    ///// State for GatherState and ACS
    pub dpss_state: DPSSState,

    pub completed_batches: HashMap<Replica, HashSet<usize>>,
    pub acs_input_set: HashSet<Replica>,
    /// Channels to interact with other services

    pub acss_req: Sender<(usize, Vec<LargeField>)>,
    pub acss_out_recv: Receiver<(usize, usize, Hash, Option<Vec<LargeField>>)>,

    pub acs_term_event: Sender<(usize,usize)>,
    pub acs_out_recv: Receiver<(usize,Vec<usize>)>,

    pub pub_rec_req_send_channel: Sender<(usize, Replica)>,
    pub pub_rec_out_recv_channel: Receiver<(usize, Replica, Vec<LargeField>)>
}

// s = num_batches*per_batch
// num_batches = 1,3,5
// num_batches = 1, per_batch = 10000/(t+1); n=16, per_batch = 1600, n=16, n=40, n=64
// s*(t+1) - 3t+1 system
// T = s*(t+1), s = T/(t+1),  T=10000
// low_or_high= true: Low-threshold DPSS, high: High-threshold DPSS

impl Context {
    pub fn spawn(
        config: Node,
        num_batches: usize,
        per_batch: usize,
        low_or_high: bool,
        byz: bool) -> anyhow::Result<oneshot::Sender<()>> {
        // Add a separate configuration for RBC service. 

        let mut consensus_addrs: FnvHashMap<Replica, SocketAddr> = FnvHashMap::default();

        let mut acss_config = config.clone();
        let mut acs_config = config.clone();

        let port_acss: u16 = 150;
        let port_acs: u16 = 300;
        
        for (replica, address) in config.net_map.iter() {
            let address: SocketAddr = address.parse().expect("Unable to parse address");
            
            let acss_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_acss);
            let rbc_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_acs);

            acss_config.net_map.insert(*replica, acss_address.to_string());
            acs_config.net_map.insert(*replica, rbc_address.to_string());

            consensus_addrs.insert(*replica, SocketAddr::from(address.clone()));

        }
        log::info!("Consensus addresses: {:?}", consensus_addrs);
        let my_port = consensus_addrs.get(&config.id).unwrap();
        let my_address = to_socket_address("0.0.0.0", my_port.port());
        let mut syncer_map: FnvHashMap<Replica, SocketAddr> = FnvHashMap::default();
        syncer_map.insert(0, config.client_addr);

        // Setup networking
        let (tx_net_to_consensus, rx_net_to_consensus) = unbounded_channel();
        TcpReceiver::<Acknowledgement, WrapperMsg<ProtMsg>, _>::spawn(
            my_address,
            Handler::new(tx_net_to_consensus),
        );

        let syncer_listen_port = config.client_port;
        let syncer_l_address = to_socket_address("0.0.0.0", syncer_listen_port);

        // The server must listen to the client's messages on some port that is not being used to listen to other servers
        let (tx_net_to_client, rx_net_from_client) = unbounded_channel();
        TcpReceiver::<Acknowledgement, SyncMsg, _>::spawn(
            syncer_l_address,
            SyncHandler::new(tx_net_to_client),
        );

        let consensus_net = TcpReliableSender::<Replica, WrapperMsg<ProtMsg>, Acknowledgement>::with_peers(
            consensus_addrs.clone(),
        );
        let sync_net =
            TcpReliableSender::<Replica, SyncMsg, Acknowledgement>::with_peers(syncer_map);
        let (exit_tx, exit_rx) = oneshot::channel();

        // Keyed AES ciphers
        let key0 = [5u8; 16];
        let key1 = [29u8; 16];
        let key2 = [23u8; 16];
        let hashstate = HashState::new(key0, key1, key2);

        let rbc_start_id = 1;
                
        // Blinding and Nonce polynomials
        let largefield_ss = LargeFieldSSS::new(
            config.num_faults+1, 
            config.num_nodes
        );
        // Prepare ACSS context
        let (acss_req_send_channel, acss_req_recv_channel) = channel(10000);
        let (acss_out_send_channel, acss_out_recv_channel) = channel(10000);
        
        let (pub_rec_req_send_channel, pub_rec_req_recv_channel) = channel(10000);
        let (pub_rec_out_send_channel, pub_rec_out_recv_channel) = channel(10000);

        let (acs_req_send_channel, acs_req_recv_channel) = channel(10000);
        let (acs_out_send_channel, acs_out_recv_channel) = channel(10000);

        tokio::spawn(async move {
            let mut c = Context {
                net_send: consensus_net,
                net_recv: rx_net_to_consensus,
                sync_send: sync_net,
                sync_recv: rx_net_from_client,
                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                hash_context: hashstate,
                myid: config.id,
                _byz: byz,
                num_faults: config.num_faults,
                cancel_handlers: HashMap::default(),
                exit_rx: exit_rx,
                
                large_field_shamir_ss: largefield_ss,

                //avid_context:HashMap::default(),
                threshold: 10000,

                max_id: rbc_start_id, 
                dpss_state: DPSSState::new(),

                num_batches: num_batches,
                per_batch: per_batch, 

                
                completed_batches: HashMap::default(),

                acs_input_set: HashSet::default(),

                nonce_seed: 1,

                acss_req: acss_req_send_channel,
                acss_out_recv: acss_out_recv_channel,

                acs_term_event: acs_req_send_channel,
                acs_out_recv: acs_out_recv_channel,

                pub_rec_req_send_channel: pub_rec_req_send_channel,
                pub_rec_out_recv_channel: pub_rec_out_recv_channel,
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
        let _acss_serv_status;
        if low_or_high{
            // _acss_serv_status = acss_bv::Context::spawn(
            //     acss_config,
            //     acss_req_recv_channel,
            //     acss_out_send_channel, 
            //     false
            // );
            _acss_serv_status = acss_ske::Context::spawn(
                acss_config,
                acss_req_recv_channel,
                acss_out_send_channel, 
                pub_rec_req_recv_channel,
                pub_rec_out_send_channel,
                false,
                false
            );
        }
        // else{
        //     _acss_serv_status = hacss::Context::spawn(
        //         acss_config,
        //         acss_req_recv_channel,
        //         acss_out_send_channel, 
        //         false
        //     );
        // }

        let _acs_serv_status = acs::Context::spawn(
            acs_config,
            acs_req_recv_channel, 
            acs_out_send_channel, 
            false
        );

        if _acs_serv_status.is_err() {
            log::error!("Error spawning acs because of {:?}", _acs_serv_status.err().unwrap());
        }

        // let _acs_serv_status = ibft::Context::spawn(
        //     acs_config,
        //     acs_req_recv_channel, 
        //     acs_out_send_channel, 
        //     false
        // );

        // if _acs_serv_status.is_err() {
        //     log::error!("Error spawning acs because of {:?}", _acs_serv_status.err().unwrap());
        // }

        let mut signals = Signals::new(&[SIGINT, SIGTERM])?;
        signals.forever().next();
        log::error!("Received termination signal");
        Ok(exit_tx)
    }

    pub async fn broadcast(&mut self, protmsg: ProtMsg) {
        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice());
            let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
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

    pub async fn run(&mut self) -> Result<()>{
        // The process starts listening to messages in this process.
        // First, the node sends an alive message
        let cancel_handler = self
            .sync_send
            .send(
                0,
                SyncMsg {
                    sender: self.myid,
                    state: SyncState::ALIVE,
                    value: "".to_string().into_bytes(),
                },
            )
            .await;
        self.add_cancel_handler(cancel_handler);
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
                sync_msg = self.sync_recv.recv() =>{
                    let sync_msg = sync_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    match sync_msg.state {
                        SyncState::START =>{
                            log::info!("Consensus Start time: {:?}", SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis());
                            // Start your protocol from here
                            for _instance in 0..self.num_batches{
                                let _status = self.start_acss(self.per_batch).await;
                            }
                        },
                        SyncState::STOP =>{
                            // Code used for internal purposes
                            log::info!("Consensus Stop time: {:?}", SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis());
                            log::info!("Termination signal received by the server. Exiting.");
                            break
                        },
                        _=>{}
                    }
                },
                acss_msg = self.acss_out_recv.recv() => {
                    let acss_msg = acss_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    log::debug!("Received message from CTRBC channel {:?}", acss_msg);
                    self.process_acss_event(acss_msg.0, acss_msg.1, acss_msg.2, acss_msg.3).await;
                },
                acs_output = self.acs_out_recv.recv() =>{
                    let acs_output = acs_output.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    log::debug!("Received message from RBC channel {:?}", acs_output);
                    self.process_consensus_output(acs_output.1).await;
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
