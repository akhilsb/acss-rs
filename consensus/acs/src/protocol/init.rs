use types::Replica;

use crate::Context;

impl Context{
    pub async fn init_rbc(&mut self, input: Vec<Replica>){
        let ser_input = bincode::serialize(&input).unwrap();
        let _status = self.ctrbc_req.send(ser_input).await;
    }
}