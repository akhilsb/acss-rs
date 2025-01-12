use types::Replica;

use crate::Context;

impl Context{
    pub async fn init_rbc(&mut self, input: Vec<Replica>){
        let ser_input = bincode::serialize(&input).unwrap();
        log::info!("Broadcasting the first value and beginning the ACS protocol");
        let _status = self.ctrbc_req.send(ser_input).await;   
    }
}