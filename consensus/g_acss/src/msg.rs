use consensus::{LargeFieldSer};
use crypto::{hash::Hash};
use serde::{Serialize, Deserialize};
use types::Replica;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommDZKMsg{
    pub comm: Vec<Vec<Hash>>,
    pub blinding_comm: Vec<Vec<Hash>>,

    pub dzk_poly: Vec<Vec<LargeFieldSer>>,
    
    pub tot_shares: usize,
    
    pub src: Replica,
    pub instance_id: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcssSKEShares{
    // Share and Nonce
    pub evaluations: (Vec<LargeFieldSer>,LargeFieldSer),
    pub blinding_evaluations: (LargeFieldSer, LargeFieldSer),
    pub rep: Replica,
    pub batch: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg{
    PubRec(usize, AcssSKEShares),
    PubRecL1(usize,AcssSKEShares),
    PubRecL2(usize, Replica,Vec<LargeFieldSer>),
}

use async_trait::async_trait;
use futures_util::SinkExt;
use network::Acknowledgement;
use tokio::sync::mpsc::UnboundedSender;

use types::WrapperMsg;

#[derive(Debug, Clone)]
pub struct Handler {
    consensus_tx: UnboundedSender<WrapperMsg<ProtMsg>>,
}

impl Handler {
    pub fn new(consensus_tx: UnboundedSender<WrapperMsg<ProtMsg>>) -> Self {
        Self { consensus_tx }
    }
}

#[async_trait]
impl network::Handler<Acknowledgement, WrapperMsg<ProtMsg>> for Handler {
    async fn dispatch(&self, msg: WrapperMsg<ProtMsg>, writer: &mut network::Writer<Acknowledgement>) {
        // Forward the message
        let status = self.consensus_tx
            .send(msg);
        if status.is_err(){
            log::error!("Failed to send consensus message to the channel because of {:?}", status.err().unwrap());
        }
        // Acknowledge
        let status = writer
            .send(Acknowledgement::Pong)
            .await;
        if status.is_err(){
            log::error!("Failed to send consensus message to the channel because of {:?}", status.err().unwrap());
        }
    }
}