use std::{
    collections::{HashMap},
    net::{SocketAddr, SocketAddrV4},
};

use anyhow::{anyhow, Result};
use config::Node;

use consensus::LargeFieldSer;
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

use crate::{msg::ProtMsg, IBFTState, Handler};

pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica, WrapperMsg<ProtMsg>, Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg<ProtMsg>>,
    //pub sync_send: TcpReliableSender<Replica, SyncMsg, Acknowledgement>,
    //pub sync_recv: UnboundedReceiver<SyncMsg>,
    /// Data context
    pub num_nodes: usize,

    pub consensus_threshold: usize,
    pub myid: usize,
    pub num_faults: usize,
    _byz: bool,

    pub leader_id: usize,
    /// Secret Key map
    pub sec_key_map: HashMap<Replica, Vec<u8>>,

    /// Cancel Handlers
    pub cancel_handlers: HashMap<u64, Vec<CancelHandler<Acknowledgement>>>,
    exit_rx: oneshot::Receiver<()>,
    
    pub ibft_state_map: HashMap<usize, IBFTState>,
    
    /// Channels to interact with other services

    //pub acss_req: Sender<(usize, Vec<LargeFieldSer>)>,
    //pub acss_out_recv: Receiver<(usize, usize, Hash, Vec<LargeFieldSer>)>,

    pub event_recv_channel: Receiver<(usize, usize, Vec<LargeFieldSer>)>,
    pub acs_out_channel: Sender<(usize, Vec<usize>)>,

    pub ctrbc_req: Sender<Vec<u8>>,
    pub ctrbc_out_recv: Receiver<(usize, usize, Vec<u8>)>,
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
        acs_out_channel: Sender<(usize, Vec<usize>)>,
        consensus_threshold: usize,
        byz: bool
    ) -> anyhow::Result<(oneshot::Sender<()>, Vec<Result<oneshot::Sender<()>>>)> {
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

        // Prepare ACSS context
        //let (acss_req_send_channel, acss_req_recv_channel) = channel(10000);
        //let (acss_out_send_channel, acss_out_recv_channel) = channel(10000);
        // Prepare RBC config
        let (ctrbc_req_send_channel, ctrbc_req_recv_channel) = channel(10000);
        let (ctrbc_out_send_channel, ctrbc_out_recv_channel) = channel(10000);
        
        tokio::spawn(async move {
            let mut c = Context {
                net_send: consensus_net,
                net_recv: rx_net_to_consensus,
                //sync_send: sync_net,
                //sync_recv: rx_net_from_client,
                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),

                myid: config.id,
                _byz: byz,
                num_faults: config.num_faults,
                leader_id: 0 as usize,

                consensus_threshold: consensus_threshold,

                cancel_handlers: HashMap::default(),
                exit_rx: exit_rx,
                
                //avid_context:HashMap::default(),

                //num_batches: num_batches,
                //per_batch: per_batch, 
                ibft_state_map: HashMap::default(),

                //acss_req: acss_req_send_channel,
                //acss_out_recv: acss_out_recv_channel,
                event_recv_channel: term_event_channel,
                acs_out_channel: acs_out_channel,

                ctrbc_req: ctrbc_req_send_channel,
                ctrbc_out_recv: ctrbc_out_recv_channel,
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
        // This is so that the inner contexts are not dropped by the compiler
        let mut statuses = Vec::new();

        let _rbc_serv_status = ctrbc::Context::spawn(
            rbc_config,
            ctrbc_req_recv_channel, 
            ctrbc_out_send_channel, 
            false
        );

        statuses.push(_rbc_serv_status);
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
                term_event = self.event_recv_channel.recv() => {
                    let (term_party, instance_id, _randomness) = term_event.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    log::debug!("Received ACSS termination event: {:?} for instance id {}", term_party, instance_id);
                    // Process the termination event
                    self.init_acss_term_procedure(term_party, instance_id).await;
                },
                ctrbc_msg = self.ctrbc_out_recv.recv() => {
                    let ctrbc_msg = ctrbc_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    log::debug!("Received message from CTRBC channel {:?}", ctrbc_msg);
                    self.process_ctrbc_termination(ctrbc_msg.2).await;
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
