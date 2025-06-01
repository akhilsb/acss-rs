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
    mpsc::{unbounded_channel, UnboundedReceiver, Receiver, Sender},
    oneshot,
};
// use tokio_util::time::DelayQueue;
use types::{Replica, WrapperMsg};

use consensus::{LargeFieldSer};

use crypto::{aes_hash::HashState};

use crate::{msg::{ProtMsg, Handler}, protocol::{RoundStateBin, Val}};

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
    
    /// State for Binary AA
    pub round_state: HashMap<usize,(HashMap<usize,RoundStateBin>, HashSet<usize>)>,
    pub coin_shares: HashMap<usize, VecDeque<LargeFieldSer>>,
    pub terminated_rounds: HashSet<usize>,

    /// Input and output request channels
    /// First: Instance id, Second: Number of secrets, Third: Reconstruction to all or none, Fourth: Request for reconstruction/sharing, Fifth: Reconstruction ID
    pub inp_bin_ba_requests: Receiver<(usize,Val, Vec<LargeFieldSer>)>,
    pub out_bin_ba_values: Sender<(usize, Val)>
}

impl Context {
    pub fn spawn(config: Node,
        input_reqs: Receiver<(usize, Val, Vec<LargeFieldSer>)>, 
        output_shares: Sender<(usize,Val)>,
        byz: bool) -> anyhow::Result<oneshot::Sender<()>> {
        // Add a separate configuration for RBC service. 

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

                inp_bin_ba_requests: input_reqs,
                out_bin_ba_values: output_shares
            };

            // Populate secret keys from config
            for (id, sk_data) in config.sk_map.clone() {
                c.sec_key_map.insert(id, sk_data.clone());
            }

            // Run the consensus context
            c.run().await;
        });

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
                req_msg = self.inp_bin_ba_requests.recv() =>{
                    if req_msg.is_none(){
                        log::error!("Request channel closed");
                        return;
                    }
                    let req_msg = req_msg.unwrap();
                    // Save coins first
                    self.coin_shares.insert(req_msg.0, VecDeque::from(req_msg.2.clone()));
                    self.start_baa(req_msg.0, 0, req_msg.1, false).await;
                },
            };
        }
    }
}



pub fn to_socket_address(ip_str: &str, port: u16) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}
