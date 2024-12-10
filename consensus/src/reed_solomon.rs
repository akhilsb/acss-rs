use reed_solomon_erasure::{galois_8::ReedSolomon, Error};

pub fn get_shards(data:Vec<u8>,shards:usize,parity_shards:usize)->Vec<Vec<u8>>{
    let reed_solomon:ReedSolomon<> = ReedSolomon::new(shards,parity_shards).unwrap();
    let mut vec_vecs = Vec::new();
    let size_of_vec = (data.len()/shards)+1;
    for b in 0..shards{
        let mut indi_vec:Vec<u8> = Vec::new();
        for x in 0..size_of_vec{
            if b*size_of_vec+x >= data.len(){
                // Padding until filling up all shards
                indi_vec.push(0);
            }
            else {
                // Fill each shard
                indi_vec.push(data[b*size_of_vec+x]);
            }
        }
        vec_vecs.push(indi_vec);
    }
    // Fill parity shards with zeros
    for _b in 0..parity_shards{
        let mut parity_vec = Vec::new();
        for _x in 0..size_of_vec{
            parity_vec.push(0);
        }
        vec_vecs.push(parity_vec);
    }
    // Use Reed solomon library to generate parity shards. 
    reed_solomon.encode(&mut vec_vecs).unwrap();
    log::trace!("Vec_vecs for Erasure codes: {:?}",vec_vecs);
    vec_vecs
}

// The shards are reconstructed inline with the variable data
pub fn reconstruct_data(data:&mut Vec<Option<Vec<u8>>>, shards:usize, parity_shards:usize) -> Result<(),Error>{
    let reed_solomon:ReedSolomon<> = ReedSolomon::new(shards,parity_shards).unwrap();
    if let Err(error) = reed_solomon.reconstruct(data) {
        return Err(error)
    } else {
        return Ok(());
    };
}