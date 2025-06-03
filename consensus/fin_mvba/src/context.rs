use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{SocketAddr, SocketAddrV4},
};

use config::Node;

use fnv::FnvHashMap;
use network::{
    plaintcp::{CancelHandler, TcpReceiver, TcpReliableSender},
    Acknowledgement,
};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, Receiver, Sender, channel},
    oneshot,
};
// use tokio_util::time::DelayQueue;
use types::{Replica, WrapperMsg};

use consensus::{LargeFieldSer};

use crypto::{aes_hash::HashState};

use crate::{msg::{ProtMsg, Handler}, protocol::{MVBAExecState}};

pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica, WrapperMsg<ProtMsg>, Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg<ProtMsg>>,
    
    /// Data context
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    _byz: bool,

    /// Secret Key map
    pub sec_key_map: HashMap<Replica, Vec<u8>>,

    /// Hardware acceleration context
    pub hash_context: HashState,

    /// Cancel Handlers
    pub cancel_handlers: HashMap<u64, Vec<CancelHandler<Acknowledgement>>>,
    exit_rx: oneshot::Receiver<()>,
    
    /// State for MVBA
    pub round_state: HashMap<usize,MVBAExecState>,
    pub coin_shares: HashMap<usize, VecDeque<LargeFieldSer>>,
    pub terminated_rounds: HashSet<usize>,
    pub instance_id_bin_aa_map: HashMap<usize, (usize, usize)>,

    pub bin_aa_req: Sender<(usize, i64, Vec<LargeFieldSer>)>,
    pub bin_aa_out_recv: Receiver<(usize, i64)>,

    pub ra_aa_req: Sender<(usize, usize, usize)>,
    pub ra_aa_out_recv: Receiver<(usize, usize, usize)>,

    pub ctrbc_req: Sender<Vec<u8>>,
    pub ctrbc_out_recv: Receiver<(usize, usize, Vec<u8>)>,

    /// Input and output request channels
    /// First: Instance id, Second: Number of secrets, Third: Reconstruction to all or none, Fourth: Request for reconstruction/sharing, Fifth: Reconstruction ID
    pub inp_mvba_requests: Receiver<(usize, usize, Vec<LargeFieldSer>)>,
    pub out_mvba_values: Sender<(usize, Vec<usize>)>
}

impl Context {
    pub fn spawn(config: Node,
        input_reqs: Receiver<(usize, usize, Vec<LargeFieldSer>)>, 
        output_shares: Sender<(usize, Vec<usize>)>,
        byz: bool) -> anyhow::Result<(oneshot::Sender<()>, Vec<anyhow::Result<oneshot::Sender<()>>>)> {
        // Add a separate configuration for RBC service. 

        let mut consensus_addrs: FnvHashMap<Replica, SocketAddr> = FnvHashMap::default();
        
        let mut rbc_config = config.clone();
        let mut ba_config = config.clone();
        let mut ra_config = config.clone();

        let port_rbc: u16 = 150;
        let port_bba: u16 = 300;
        let port_ra: u16 = 450;

        for (replica, address) in config.net_map.iter() {
            let address: SocketAddr = address.parse().expect("Unable to parse address");
            
            let rbc_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_rbc);
            let bba_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_bba);
            let ra_address: SocketAddr = SocketAddr::new(address.ip(), address.port() + port_ra);

            rbc_config.net_map.insert(*replica, rbc_address.to_string());
            ba_config.net_map.insert(*replica, bba_address.to_string());
            ra_config.net_map.insert(*replica, ra_address.to_string());

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

        let (ctrbc_req_send_channel, ctrbc_req_recv_channel) = channel(10000);
        let (ctrbc_out_send_channel, ctrbc_out_recv_channel) = channel(10000);

        let (bin_aa_req, bin_aa_req_recv) = channel(10000);
        let (bin_aa_out_send, bin_aa_out_recv) = channel(10000);

        let (ra_aa_req, ra_aa_req_recv) = channel(10000);
        let (ra_aa_out_send, ra_aa_out_recv) = channel(10000);
        tokio::spawn(async move {
            let mut c = Context {
                net_send: consensus_net,
                net_recv: rx_net_to_consensus,
                
                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                hash_context: hashstate,
                myid: config.id,
                _byz: byz,
                num_faults: config.num_faults,
                cancel_handlers: HashMap::default(),
                exit_rx: exit_rx,
                
                round_state: HashMap::default(),
                terminated_rounds: HashSet::default(),
                coin_shares: HashMap::default(),
                instance_id_bin_aa_map: HashMap::default(),

                ctrbc_req: ctrbc_req_send_channel,
                ctrbc_out_recv: ctrbc_out_recv_channel,

                bin_aa_req: bin_aa_req,
                bin_aa_out_recv: bin_aa_out_recv,

                ra_aa_req: ra_aa_req,
                ra_aa_out_recv: ra_aa_out_recv,

                inp_mvba_requests: input_reqs,
                out_mvba_values: output_shares
            };

            // Populate secret keys from config
            for (id, sk_data) in config.sk_map.clone() {
                c.sec_key_map.insert(id, sk_data.clone());
            }

            // Run the consensus context
            c.run().await
        });

        let mut statuses = Vec::new();

        let _rbc_serv_status = ctrbc::Context::spawn(
            rbc_config,
            ctrbc_req_recv_channel, 
            ctrbc_out_send_channel, 
            false
        );

        statuses.push(_rbc_serv_status);

        let _ba_serv_status = binary_ba::Context::spawn(
            ba_config,
            bin_aa_req_recv,
            bin_aa_out_send,
            false
        );

        statuses.push(_ba_serv_status);

        let _ra_serv_status = ra::Context::spawn(
            ra_config,
            ra_aa_req_recv,
            ra_aa_out_send,
            false
        );

        statuses.push(_ra_serv_status);

        // Initialize ctrbc context and binary ba contexts
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

    pub async fn run(&mut self){
        // The process starts listening to messages in this process.
        // First, the node sends an alive message
        loop {
            tokio::select! {
                // Receive exit handlers
                _exit_tx = &mut self.exit_rx => {
                    log::info!("Termination signal received by the server. Exiting.");
                    break
                },
                msg = self.net_recv.recv() => {
                    // Received messages are processed here
                    log::trace!("Got a consensus message from the network: {:?}", msg);
                    if msg.is_none(){
                        log::error!("Got none from the consensus layer, most likely it closed");
                        return;
                    }
                    self.process_msg(msg.unwrap()).await;
                },
                req_msg = self.inp_mvba_requests.recv() =>{
                    if req_msg.is_none(){
                        log::error!("Request channel closed");
                        return;
                    }
                    let req_msg = req_msg.unwrap();
                    // Save coins first
                    self.coin_shares.insert(req_msg.0, VecDeque::from(req_msg.2.clone()));
                    self.start_fin_mvba(req_msg.0, 1, Some(req_msg.1)).await;
                },
                ctrbc_msg = self.ctrbc_out_recv.recv() => {
                    if ctrbc_msg.is_none(){
                        log::error!("Request channel closed");
                        return;
                    }
                    let ctrbc_msg = ctrbc_msg.unwrap();

                    let sender_party = ctrbc_msg.1;
                    let main_msg = ctrbc_msg.2;

                    let deser_msg: (usize, usize, usize, Vec<usize>) = bincode::deserialize(&main_msg).unwrap();
                    if deser_msg.2 == 1{
                        self.process_l1_rbc_termination(
                            deser_msg.0, 
                            deser_msg.1, 
                            sender_party, 
                            deser_msg.3[0]
                        ).await;
                    }
                    else if deser_msg.2 == 2{
                        self.process_l2_rbc_termination(
                            deser_msg.0,
                            deser_msg.1,
                            sender_party,
                            deser_msg.3
                        ).await;
                    }
                },
                bin_aa_msg = self.bin_aa_out_recv.recv() =>{
                    if bin_aa_msg.is_none(){
                        log::error!("Request channel closed");
                        return;
                    }
                    let bin_aa_msg = bin_aa_msg.unwrap();
                    self.process_bba_termination(bin_aa_msg.0, bin_aa_msg.1 as usize).await;
                },
                ra_msg = self.ra_aa_out_recv.recv() =>{
                    if ra_msg.is_none(){
                        log::error!("Request channel closed");
                        return;
                    }
                    let ra_aa_msg = ra_msg.unwrap();
                    self.process_ra_termination(ra_aa_msg.1, ra_aa_msg.2 as usize).await;
                }
            };
        }
    }
}



pub fn to_socket_address(ip_str: &str, port: u16) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}
