use std::{
    collections::{HashMap, HashSet},
    net::{SocketAddr, SocketAddrV4},
};

use anyhow::{anyhow, Result};
use config::Node;

use fnv::FnvHashMap;
use network::{
    plaintcp::{CancelHandler, TcpReceiver, TcpReliableSender},
    Acknowledgement,
};
//use signal_hook::{iterator::Signals, consts::{SIGINT, SIGTERM}};
use tokio::{sync::{
    mpsc::{UnboundedReceiver, Sender, Receiver, channel, unbounded_channel},
    oneshot,
}};
// use tokio_util::time::DelayQueue;
use types::{Replica, WrapperMsg};

use consensus::{LargeFieldSSS, LargeFieldSer};
use crypto::{aes_hash::HashState, LargeField, hash::Hash};

use crate::{msg::ProtMsg, Handler, protocol::ACSState};

pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica, WrapperMsg<ProtMsg>, Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg<ProtMsg>>,
    //pub sync_send: TcpReliableSender<Replica, SyncMsg, Acknowledgement>,
    //pub sync_recv: UnboundedReceiver<SyncMsg>,
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

    //pub num_batches: usize,
    //pub per_batch: usize,

    // Maximum number of RBCs that can be initiated by a node. Keep this as an identifier for RBC service. 
    pub threshold: usize, 

    pub max_id: usize,

    /// Constants for PRF seeding
    pub nonce_seed: usize,

    ///// State for GatherState and ACS
    pub acs_state: ACSState,
    
    pub acss_map: HashMap<Replica, 
        HashMap<usize, 
        (
            Option<(Vec<LargeField>, Hash)>,
            Option<(Vec<LargeField>, Hash)>)>
        >,

    pub completed_batches: HashMap<Replica, HashSet<usize>>,
    pub acs_input_set: HashSet<Replica>,
    /// Channels to interact with other services

    //pub acss_req: Sender<(usize, Vec<LargeFieldSer>)>,
    //pub acss_out_recv: Receiver<(usize, usize, Hash, Vec<LargeFieldSer>)>,

    pub event_recv_channel: Receiver<(usize,usize, Vec<LargeFieldSer>)>,
    pub acs_out_channel: Sender<(usize,Vec<usize>)>,

    pub asks_req: Sender<(usize, usize, bool, bool, Option<Vec<LargeField>>,Option<usize>)>,
    pub asks_out_recv: Receiver<(usize, Replica, Option<Vec<LargeField>>)>,

    pub ctrbc_req: Sender<Vec<u8>>,
    pub ctrbc_out_recv: Receiver<(usize, usize, Vec<u8>)>,

    pub ra_req_send: Sender<(usize, usize, usize)>,
    pub ra_out_recv: Receiver<(usize, Replica, usize)>
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
        term_event_channel: Receiver<(usize,usize, Vec<LargeFieldSer>)>,
        acs_out_channel: Sender<(usize,Vec<usize>)>,
        byz: bool) -> anyhow::Result<(oneshot::Sender<()>, Vec<Result<oneshot::Sender<()>>>)> {
        // Add a separate configuration for RBC service. 

        let mut consensus_addrs: FnvHashMap<Replica, SocketAddr> = FnvHashMap::default();

        //let mut acss_config = config.clone();
        let mut rbc_config = config.clone();
        let mut ra_config = config.clone();
        let mut asks_config = config.clone();

        //let port_acss: u16 = 150;
        let port_rbc: u16 = 150;
        let port_ra: u16 = 300;
        let port_asks: u16 = 450;
        for (replica, address) in config.net_map.iter() {
            let address: SocketAddr = address.parse().expect("Unable to parse address");
            
            //let acss_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_acss);
            let rbc_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_rbc);
            let ra_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_ra);
            let asks_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_asks);

            //acss_config.net_map.insert(*replica, acss_address.to_string());
            rbc_config.net_map.insert(*replica, rbc_address.to_string());
            ra_config.net_map.insert(*replica, ra_address.to_string());
            asks_config.net_map.insert(*replica, asks_address.to_string());

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

        //let syncer_listen_port = config.client_port;
        //let syncer_l_address = to_socket_address("0.0.0.0", syncer_listen_port);

        // The server must listen to the client's messages on some port that is not being used to listen to other servers
        //let (tx_net_to_client, rx_net_from_client) = unbounded_channel();
        //TcpReceiver::<Acknowledgement, SyncMsg, _>::spawn(
        //    syncer_l_address,
        //    SyncHandler::new(tx_net_to_client),
        //);

        let consensus_net = TcpReliableSender::<Replica, WrapperMsg<ProtMsg>, Acknowledgement>::with_peers(
            consensus_addrs.clone(),
        );
        //let sync_net =
        //    TcpReliableSender::<Replica, SyncMsg, Acknowledgement>::with_peers(syncer_map);
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
        //let (acss_req_send_channel, acss_req_recv_channel) = channel(10000);
        //let (acss_out_send_channel, acss_out_recv_channel) = channel(10000);
        // Prepare RBC config
        let (ctrbc_req_send_channel, ctrbc_req_recv_channel) = channel(10000);
        let (ctrbc_out_send_channel, ctrbc_out_recv_channel) = channel(10000);
        
        let (ra_req_send_channel, ra_req_recv_channel) = channel(10000);
        let (ra_out_send_channel, ra_out_recv_channel) = channel(10000);
        
        let (asks_req_send_channel, asks_req_recv_channel) = channel(10000);
        let (asks_out_send_channel, asks_out_recv_channel) = channel(10000);

        tokio::spawn(async move {
            let mut c = Context {
                net_send: consensus_net,
                net_recv: rx_net_to_consensus,
                //sync_send: sync_net,
                //sync_recv: rx_net_from_client,
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
                acs_state: ACSState::new(),

                //num_batches: num_batches,
                //per_batch: per_batch, 

                acss_map: HashMap::default(),
                completed_batches: HashMap::default(),

                acs_input_set: HashSet::default(),

                nonce_seed: 1,

                //acss_req: acss_req_send_channel,
                //acss_out_recv: acss_out_recv_channel,
                event_recv_channel: term_event_channel,
                acs_out_channel: acs_out_channel,

                ctrbc_req: ctrbc_req_send_channel,
                ctrbc_out_recv: ctrbc_out_recv_channel,

                asks_req: asks_req_send_channel,
                asks_out_recv: asks_out_recv_channel,

                ra_req_send: ra_req_send_channel,
                ra_out_recv: ra_out_recv_channel
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
        // let _acss_serv_status;
        // if low_or_high{
        //     _acss_serv_status = acss_va::Context::spawn(
        //         acss_config,
        //         acss_req_recv_channel,
        //         acss_out_send_channel, 
        //         false
        //     );
        // }
        // else{
        //     _acss_serv_status = hacss::Context::spawn(
        //         acss_config,
        //         acss_req_recv_channel,
        //         acss_out_send_channel, 
        //         false
        //     );
        // }
        // This is so that the inner contexts are not dropped by the compiler
        let mut statuses = Vec::new();

        let _rbc_serv_status = ctrbc::Context::spawn(
            rbc_config,
            ctrbc_req_recv_channel, 
            ctrbc_out_send_channel, 
            false
        );

        statuses.push(_rbc_serv_status);

        let _asks_serv_status = asks::Context::spawn(
            asks_config, 
            asks_req_recv_channel, 
            asks_out_send_channel,
            false
        );

        statuses.push(_asks_serv_status);

        let _ra_serv_status = ra::Context::spawn(
            ra_config,
            ra_req_recv_channel,
            ra_out_send_channel,
            false
        );

        statuses.push(_ra_serv_status);

        // let mut signals = Signals::new(&[SIGINT, SIGTERM])?;
        // signals.forever().next();
        // log::error!("Received termination signal");
        Ok((exit_tx, statuses))
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
                // sync_msg = self.sync_recv.recv() =>{
                //     let sync_msg = sync_msg.ok_or_else(||
                //         anyhow!("Networking layer has closed")
                //     )?;
                //     match sync_msg.state {
                //         SyncState::START =>{
                //             log::info!("Consensus Start time: {:?}", SystemTime::now()
                //                 .duration_since(UNIX_EPOCH)
                //                 .unwrap()
                //                 .as_millis());
                //             // Start your protocol from here
                //             // Write a function to broadcast a message. We demonstrate an example with a PING function
                //             // Dealer sends message to everybody. <M, init>
                //             for instance in 0..self.num_batches{
                //                 //self.start_acss(self.per_batch).await;
                //                 let _status = self.asks_req.send((instance, None, false)).await;
                //             }
                //         },
                //         SyncState::STOP =>{
                //             // Code used for internal purposes
                //             log::info!("Consensus Stop time: {:?}", SystemTime::now()
                //                 .duration_since(UNIX_EPOCH)
                //                 .unwrap()
                //                 .as_millis());
                //             log::info!("Termination signal received by the server. Exiting.");
                //             break
                //         },
                //         _=>{}
                //     }
                // },
                // acss_msg = self.acss_out_recv.recv() => {
                //     let acss_msg = acss_msg.ok_or_else(||
                //         anyhow!("Networking layer has closed")
                //     )?;
                //     log::debug!("Received message from CTRBC channel {:?}", acss_msg);
                //     self.process_acss_event(acss_msg.0, acss_msg.1, acss_msg.2, acss_msg.3).await;
                // },
                term_event = self.event_recv_channel.recv() => {
                    let term_event = term_event.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    log::debug!("Received termination event: {:?}", term_event);
                    // Process the termination event
                    self.process_termination_event(term_event.1).await;
                },
                ctrbc_msg = self.ctrbc_out_recv.recv() => {
                    let ctrbc_msg = ctrbc_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;

                    log::debug!("Received message from CTRBC channel {:?}", ctrbc_msg);
                    self.process_ctrbc_event(ctrbc_msg.1, ctrbc_msg.0, ctrbc_msg.2).await;
                },
                asks_msg = self.asks_out_recv.recv() =>{
                    let asks_msg = asks_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;

                    log::debug!("Received message from ASKS channel {:?}", asks_msg);
                    if asks_msg.2.is_none(){
                        self.process_asks_termination(asks_msg.0, asks_msg.1, asks_msg.2).await;
                    }
                    else{
                        self.process_asks_reconstruction_result(asks_msg.0, asks_msg.1, asks_msg.2.unwrap()).await;
                    }
                },
                ra_msg = self.ra_out_recv.recv() => {
                    let ra_msg = ra_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;

                    log::debug!("Received message from RA channel {:?}", ra_msg);
                    self.process_ra_termination(ra_msg.1, ra_msg.0, ra_msg.2).await;
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
