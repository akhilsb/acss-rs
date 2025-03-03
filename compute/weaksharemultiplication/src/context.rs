use std::{collections::HashMap, net::{SocketAddr, SocketAddrV4}, time::{SystemTime, UNIX_EPOCH}};

use anyhow::{Result, anyhow};
use config::Node;
use fnv::FnvHashMap;
use network::{plaintcp::{TcpReceiver, TcpReliableSender, CancelHandler}, Acknowledgement};
use tokio::sync::{oneshot, mpsc::{unbounded_channel, UnboundedReceiver}};
// use tokio_util::time::DelayQueue;
use types::{{WrapperMsg, Replica, ProtMsg}, SyncMsg, SyncState};

use std::collections::{HashSet};
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use crypto::LargeField;
use crate::sync_handler::SyncHandler;
use crate::handler::Handler;
use crate::serialize::WeakShareMultiplicationResult;

impl Context {
    pub fn spawn(
        config:Node,
        message: Vec<u8>,
        byz: bool
    )->anyhow::Result<oneshot::Sender<()>>{
        let mut consensus_addrs :FnvHashMap<Replica,SocketAddr>= FnvHashMap::default();
        for (replica,address) in config.net_map.iter(){
            let address:SocketAddr = address.parse().expect("Unable to parse address");
            consensus_addrs.insert(*replica, SocketAddr::from(address.clone()));
        }
        let my_port = consensus_addrs.get(&config.id).unwrap();
        let my_address = to_socket_address("0.0.0.0", my_port.port());
        let mut syncer_map:FnvHashMap<Replica,SocketAddr> = FnvHashMap::default();
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
        let (tx_net_to_client,rx_net_from_client) = unbounded_channel();
        TcpReceiver::<Acknowledgement,SyncMsg,_>::spawn(
            syncer_l_address,
            SyncHandler::new(tx_net_to_client)
        );
        let consensus_net = TcpReliableSender::<Replica,WrapperMsg<ProtMsg>,Acknowledgement>::with_peers(
            consensus_addrs.clone()
        );

        let sync_net = TcpReliableSender::<Replica,SyncMsg,Acknowledgement>::with_peers(syncer_map);
        let (exit_tx, exit_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut c = Context {
                net_send:consensus_net,
                net_recv:rx_net_to_consensus,
                sync_send: sync_net,
                sync_recv: rx_net_from_client,
                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                myid: config.id,
                byz: byz,
                num_faults: config.num_faults,
                cancel_handlers:HashMap::default(),
                exit_rx: exit_rx,

                inp_message:message,

                evaluation_point: HashMap::new(),
                // modulus: 97,
                N: 100, // TODO
                a_vec_shares: Vec::new(),
                b_vec_shares: Vec::new(),
                r_shares: Vec::new(),
                o_shares: Vec::new(),

                a_vec_shares_grouped: Vec::new(),
                b_vec_shares_grouped: Vec::new(),
                r_shares_grouped: Vec::new(),
                o_shares_grouped: Vec::new(),

                received_fx_shares: HashMap::new(),
                received_reconstruction_shares: HashMap::new(),

                Z: HashMap::new(),
                coefficients_z: HashMap::new(),
                received_Z: HashMap::new(),
                result: HashMap::new(),
                zs: Vec::new(),
                cs: Vec::new(),

                reconstruction_result: HashMap::new(),
            };
            for (id, sk_data) in config.sk_map.clone() {
                c.sec_key_map.insert(id, sk_data.clone());
            }
            //c.invoke_coin.insert(100, Duration::from_millis(sleep_time.try_into().unwrap()));
            if let Err(e) = c.run().await {
                log::error!("Consensus error: {}", e);
            }
        });
        Ok(exit_tx)
    }

    pub async fn broadcast(&mut self, protmsg:ProtMsg){
        let sec_key_map = self.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if self.byz && replica%3 == 0{
                // Simulates a crash fault
                continue;
            }
            if replica != self.myid{
                let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice());
                let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
                self.add_cancel_handler(cancel_handler);
            }
        }
    }

    pub async fn broadcast_all(&mut self, protmsg:ProtMsg){
        let sec_key_map = self.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if self.byz && replica%2 == 0{
                // Simulates a crash fault
                continue;
            }
            //if replica != self.myid{
                let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice());
                let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
                self.add_cancel_handler(cancel_handler);
            //}
        }
    }

    pub fn add_cancel_handler(&mut self, canc: CancelHandler<Acknowledgement>){
        self.cancel_handlers
            .entry(0)
            .or_default()
            .push(canc);
    }

    pub async fn send(&mut self, replica:Replica, wrapper_msg:WrapperMsg<ProtMsg>){
        let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
        self.add_cancel_handler(cancel_handler);
    }

    pub async fn run(&mut self)-> Result<()>{
        // The process starts listening to messages in this process.
        // First, the node sends an alive message
        let cancel_handler = self.sync_send.send(0,
            SyncMsg { sender: self.myid, state: SyncState::ALIVE,value:"".to_string().into_bytes()}
        ).await;
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
                    log::debug!("Got a message from the network: {:?}", msg);
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
                            log::error!("Multiplication Start time: {:?}", SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis());

                            // Start your protocol from here
                            self.start_multiplication().await;

                            // TODO: change signature of sync_send
                            let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::STARTED, value:"".to_string().into_bytes()}).await;
                            self.add_cancel_handler(cancel_handler);
                        },
                        SyncState::STOP =>{
                            // Code used for internal purposes
                            log::error!("Multiplication Stop time: {:?}", SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis());
                            log::info!("Termination signal received by the server. Exiting.");
                            break
                        },
                        _=>{}
                    }
                },
            };
        }
        Ok(())
    }
}

pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica,WrapperMsg<ProtMsg>,Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg<ProtMsg>>,
    pub sync_send:TcpReliableSender<Replica,SyncMsg,Acknowledgement>,
    pub sync_recv: UnboundedReceiver<SyncMsg>,
    /// Data context
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    pub inp_message:Vec<u8>,
    byz: bool,

    /// Secret Key map
    pub sec_key_map:HashMap<Replica, Vec<u8>>,

    /// Cancel Handlers
    pub cancel_handlers: HashMap<u64,Vec<CancelHandler<Acknowledgement>>>,
    exit_rx: oneshot::Receiver<()>,

    //
    // Public Weak Reconstruction
    //
    // pub shares_a: Vec<Option<i64>>,
    // pub shares_b: Vec<Option<i64>>,
    // pub shares_r: Vec<Option<i64>>,
    // pub o_shares_for_group: Vec<Vec<Option<i64>>>,
    // pub grouped_shares: Vec<Vec<Option<i64>>>,
    //pub expanded_o_shares_for_group: Vec<Vec<i64>>,
    // pub received_fx_share_messages: HashMap<usize, Option<i64>>,
    // pub sharings: Vec<Option<i64>>,

    pub a_vec_shares: Vec<Vec<Option<FieldElement<Stark252PrimeField>>>>,
    pub b_vec_shares: Vec<Vec<Option<FieldElement<Stark252PrimeField>>>>,
    pub r_shares: Vec<Option<FieldElement<Stark252PrimeField>>>,
    pub o_shares: Vec<FieldElement<Stark252PrimeField>>,

    pub a_vec_shares_grouped: Vec<Vec<Vec<Option<i64>>>>,
    pub b_vec_shares_grouped: Vec<Vec<Vec<Option<i64>>>>,
    pub r_shares_grouped: Vec<Vec<Option<FieldElement<Stark252PrimeField>>>>,
    pub o_shares_grouped: Vec<Vec<Option<i64>>>,

    pub reconstruction_result: HashMap<usize, Option<FieldElement<Stark252PrimeField>>>,
    pub received_fx_shares: HashMap<usize, Vec<(FieldElement<Stark252PrimeField>, Option<FieldElement<Stark252PrimeField>>)>>,
    pub received_reconstruction_shares: HashMap<usize, HashMap<FieldElement<Stark252PrimeField>, Option<FieldElement<Stark252PrimeField>>>>,
    pub Z: HashMap<usize, Vec<u8>>,
    pub coefficients_z: HashMap<usize, Vec<FieldElement<Stark252PrimeField>>>,
    pub received_Z: HashMap<usize, Vec<Option<Vec<u8>>>>,
    pub result: HashMap<usize, WeakShareMultiplicationResult>,
    pub zs: Vec<Vec<FieldElement<Stark252PrimeField>>>,
    pub cs: Vec<Vec<Option<FieldElement<Stark252PrimeField>>>>,

    pub N: usize,
    pub evaluation_point: HashMap<usize, i64>,
}

pub fn to_socket_address(
    ip_str: &str,
    port: u16,
) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}