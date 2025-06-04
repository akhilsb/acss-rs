use std::{
    collections::{HashMap, HashSet, VecDeque},
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

use consensus::{SyncHandler, LargeFieldSSS, LargeField, LargeFieldSer};
use crypto::{aes_hash::HashState, hash::Hash};

use crate::{msg::ProtMsg, Handler, protocol::{DPSSState, BAState}};

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

    pub opt_or_pess: bool,
    pub lin_or_quad: bool,
    pub ibft: bool,

    pub terminated: bool,

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

    pub coin_batch: usize,
    pub coin_shares: VecDeque<LargeField>,

    // Maximum number of RBCs that can be initiated by a node. Keep this as an identifier for RBC service. 
    pub threshold: usize, 

    pub max_id: usize,

    /// Constants for PRF seeding
    pub nonce_seed: usize,

    ///// State for GatherState and ACS
    pub dpss_state: DPSSState,
    pub ba_state: BAState,

    pub completed_batches: HashMap<Replica, HashSet<usize>>,
    pub acs_input_set: HashSet<Replica>,
    /// Channels to interact with other services

    pub acss_req: Sender<(usize, Vec<LargeField>)>,
    pub acss_out_recv: Receiver<(usize, usize, Hash, Option<Vec<LargeField>>)>,

    pub bin_aa_req: Sender<(usize, i64, Vec<LargeFieldSer>)>,
    pub bin_aa_out_recv: Receiver<(usize, i64)>,

    pub fin_mvba_req_send: Sender<(usize, usize, Vec<LargeFieldSer>)>,
    pub fin_mvba_out_recv: Receiver<(usize, Vec<usize>)>,

    pub acs_term_event: Sender<(usize,usize, Vec<LargeFieldSer>)>,
    pub acs_out_recv: Receiver<(usize,Vec<usize>)>,

    pub pub_rec_req_send_channel: Sender<(usize, Replica)>,
    pub pub_rec_out_recv_channel: Receiver<(usize, Replica, Vec<LargeField>)>,

    pub ra_req_send_channel: Sender<(usize, usize, usize)>,
    pub ra_out_recv_channel: Receiver<(usize, usize, usize)>,
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
        opt_or_pess: bool,
        lin_or_quad: bool,
        ibft: bool,
        byz: bool
    ) -> anyhow::Result<oneshot::Sender<()>> {
        // Add a separate configuration for RBC service. 

        let mut consensus_addrs: FnvHashMap<Replica, SocketAddr> = FnvHashMap::default();

        let mut acss_config = config.clone();
        let mut acs_config = config.clone();
        let mut ba_config = config.clone();
        let mut mvba_config = config.clone();
        let mut ra_config = config.clone();

        let port_acss: u16 = 150;
        let port_acs: u16 = 900;
        let port_bba: u16 = 1800;
        let port_mvba: u16 = 2100;
        let port_ra: u16 = 2700;
        
        for (replica, address) in config.net_map.iter() {
            let address: SocketAddr = address.parse().expect("Unable to parse address");
            
            let acss_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_acss);
            let rbc_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_acs);
            let ba_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_bba);
            let mvba_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_mvba);
            let ra_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_ra);

            acss_config.net_map.insert(*replica, acss_address.to_string());
            acs_config.net_map.insert(*replica, rbc_address.to_string());
            ba_config.net_map.insert(*replica, ba_address.to_string());
            mvba_config.net_map.insert(*replica, mvba_address.to_string());
            ra_config.net_map.insert(*replica, ra_address.to_string());

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
        let (bin_aa_req, bin_aa_req_recv) = channel(10000);
        let (bin_aa_out_send, bin_aa_out_recv) = channel(10000);

        let (fin_mvba_req_send, fin_mvba_req_recv) = channel(10000);
        let (fin_mvba_out_send, fin_mvba_out_recv) = channel(10000);
        
        let (acss_req_send_channel, acss_req_recv_channel) = channel(10000);
        let (acss_out_send_channel, acss_out_recv_channel) = channel(10000);
        
        let (pub_rec_req_send_channel, pub_rec_req_recv_channel) = channel(10000);
        let (pub_rec_out_send_channel, pub_rec_out_recv_channel) = channel(10000);

        let (acs_req_send_channel, acs_req_recv_channel) = channel(10000);
        let (acs_out_send_channel, acs_out_recv_channel) = channel(10000);

        let (ra_req_send_channel, ra_req_recv_channel) = channel(10000);
        let (ra_out_send_channel, ra_out_recv_channel) = channel(10000);        

        let coin_secrets = (60/(config.num_faults+1))*(config.num_faults+1);
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
                terminated: false,

                // Protocol configuration
                opt_or_pess: opt_or_pess,
                lin_or_quad: lin_or_quad,
                ibft: ibft,

                num_faults: config.num_faults,
                cancel_handlers: HashMap::default(),
                exit_rx: exit_rx,
                
                large_field_shamir_ss: largefield_ss,

                //avid_context:HashMap::default(),
                threshold: 10000,

                max_id: rbc_start_id, 
                dpss_state: DPSSState::new(),
                ba_state: BAState::new(),

                num_batches: num_batches,
                per_batch: per_batch, 
                
                coin_batch: coin_secrets,
                coin_shares: VecDeque::new(),
                
                completed_batches: HashMap::default(),

                acs_input_set: HashSet::default(),

                nonce_seed: 1,

                acss_req: acss_req_send_channel,
                acss_out_recv: acss_out_recv_channel,

                bin_aa_req: bin_aa_req,
                bin_aa_out_recv: bin_aa_out_recv,

                fin_mvba_req_send: fin_mvba_req_send,
                fin_mvba_out_recv: fin_mvba_out_recv,

                acs_term_event: acs_req_send_channel,
                acs_out_recv: acs_out_recv_channel,

                pub_rec_req_send_channel: pub_rec_req_send_channel,
                pub_rec_out_recv_channel: pub_rec_out_recv_channel,

                ra_req_send_channel: ra_req_send_channel,
                ra_out_recv_channel: ra_out_recv_channel,
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
        let ibft_or_acs = ibft;
        let _acss_serv_status = acss_ske::Context::spawn(
            acss_config,
            acss_req_recv_channel,
            acss_out_send_channel, 
            pub_rec_req_recv_channel,
            pub_rec_out_send_channel,
            false,
            lin_or_quad,
            false
        );

        let _acs_serv_status; 
        if ibft_or_acs{
            _acs_serv_status = acs::Context::spawn(
                acs_config,
                acs_req_recv_channel, 
                acs_out_send_channel, 
                false
            );
        }
        else{
            _acs_serv_status = ibft::Context::spawn(
                acs_config,
                acs_req_recv_channel,
                acs_out_send_channel,
                config.num_nodes-config.num_faults,
                false
            )
        }

        if _acs_serv_status.is_err() {
            log::error!("Error spawning acs because of {:?}", _acs_serv_status.err().unwrap());
        }

        let _ba_serv_status = binary_ba::Context::spawn(
            ba_config,
            bin_aa_req_recv,
            bin_aa_out_send,
            false
        );

        if _ba_serv_status.is_err() {
            log::error!("Error spawning BA because of {:?}", _ba_serv_status.err().unwrap());
        }

        let _fin_mvba_status ;
        if ibft_or_acs{
            _fin_mvba_status = fin_mvba::Context::spawn(
                mvba_config,
                fin_mvba_req_recv,
                fin_mvba_out_send,
                false
            );
        }
        else{
            _fin_mvba_status = ibft::Context::spawn(
                mvba_config,
                fin_mvba_req_recv,
                fin_mvba_out_send,
                1,
                false
            )
        }

        if _fin_mvba_status.is_err() {
            log::error!("Error spawning acs because of {:?}", _fin_mvba_status.err().unwrap());
        }

        let _ra_status = ra::Context::spawn(
            ra_config,
            ra_req_recv_channel,
            ra_out_send_channel,
            false,
        );

        if _ra_status.is_err() {
            log::error!("Error spawning ra because of {:?}", _ra_status.err().unwrap());
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
                            let _status = self.start_acss(self.coin_batch).await;
                            // Start code from here
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
                },
                bin_aa_out_msg = self.bin_aa_out_recv.recv() => {
                    let bin_aa_out_msg = bin_aa_out_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    log::info!("Received message from Binary AA channel {:?}", bin_aa_out_msg);
                    self.process_bin_aa_output(bin_aa_out_msg.0, bin_aa_out_msg.1).await;
                },
                fin_mvba_out_msg = self.fin_mvba_out_recv.recv() => {
                    let fin_mvba_out_msg = fin_mvba_out_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    log::debug!("Received message from Fin MVBA channel {:?}", fin_mvba_out_msg);
                    let median_value;
                    if self.ibft{
                        median_value = fin_mvba_out_msg.1[self.num_faults+1].clone();
                    }
                    else{
                        median_value = fin_mvba_out_msg.1[0].clone()
                    }
                    self.process_fin_mvba_output(fin_mvba_out_msg.0, median_value).await;
                },
                pub_rec_out_msg = self.pub_rec_out_recv_channel.recv() => {
                    let pub_rec_out_msg = pub_rec_out_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    log::debug!("Received message from Pub Rec channel {:?}", pub_rec_out_msg);
                    self.process_acss_pubrec_output(pub_rec_out_msg.1, pub_rec_out_msg.2).await;
                },
                ra_out_msg = self.ra_out_recv_channel.recv() => {
                    let ra_out_msg = ra_out_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    log::debug!("Received message from RA channel {:?}", ra_out_msg);
                    self.process_ra_output(ra_out_msg.1, ra_out_msg.2 as i64).await;
                },
            };
        }
        Ok(())
    }
}

pub fn to_socket_address(ip_str: &str, port: u16) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}
