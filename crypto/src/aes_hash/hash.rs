use aes::{cipher::{generic_array::GenericArray, KeyInit, BlockEncrypt}, Aes128Enc};
//use sha2::{Sha256, Digest};

//use crate::hash::Hash;

// pub struct HashState{
    
// }

// impl HashState{
//     pub fn new(_k1: [u8;16],_k2: [u8;16],_k3:[u8;16])->HashState{
//         HashState{}
//     }

//     pub fn hash_two(&self, one:Hash, two: Hash)-> Hash{
//         let mut sha256 = Sha256::new();
//         //sha256.update(&[0x00]);
//         sha256.update(one);
//         sha256.update(two);
//         sha256.clone().finalize().into()
//     }

//     pub fn hash_batch(&self, one: Vec<Hash>, two: Vec<Hash>)-> Vec<Hash>{
//         let mut sha256 = Sha256::new();
//         let mut hv = Vec::new();
//         for (o,t) in one.into_iter().zip(two.into_iter()){
//             sha256.reset();
//             sha256.update(o);
//             sha256.update(t);
//             hv.push(sha256.clone().finalize().into())
//         }
//         hv
//     }
// }

pub struct HashState{
    pub aes0: Aes128Enc,
    pub aes1: Aes128Enc,
    pub aes2: Aes128Enc
}

impl HashState{
    pub fn new(key0: [u8;16],key1: [u8;16], key2: [u8;16])-> HashState{
        let key0 = GenericArray::from(key0);
        let key1 = GenericArray::from(key1);
        let key2 = GenericArray::from(key2);
        
        let aes_state = HashState{
            aes0: Aes128Enc::new(&key0),
            aes1: Aes128Enc::new(&key1),
            aes2: Aes128Enc::new(&key2)
        };
        aes_state
    }
    // AES is a 128 bit block cipher. 
    // AES 256 just has a 256 bit key. It is not a 256-bit block cipher. Hence, have to split each SHA256 Hash to multiple layers
    pub fn hash_two(&self, one: [u8;32],two:[u8;32])->[u8;32]{
        let mut x_11 = [0u8;16];
        let mut x_12 = [0u8;16];
        for i in 0..16{
            x_11[i] = one[i].wrapping_add(two[i].wrapping_mul(2));
            x_12[i] = one[16+i].wrapping_add(two[16+i].wrapping_mul(2));
        }
        let blk_11 = GenericArray::from(x_11);
        let blk_12 = GenericArray::from(x_12);
        self.aes0.encrypt_blocks(&mut [blk_11,blk_12]);

        let mut x_21 = [0u8;16];
        let mut x_22 = [0u8;16];
        for i in 0..16{
            x_21[i] = (one[i].wrapping_mul(2)).wrapping_add(two[i].wrapping_mul(2)).wrapping_add(blk_11[i]);
            x_22[i] = (one[16+i].wrapping_mul(2)).wrapping_add(two[16+i].wrapping_mul(2)).wrapping_add(blk_12[i]);
        }
        let blk_21 = GenericArray::from(x_21);
        let blk_22 = GenericArray::from(x_22);
        self.aes1.encrypt_blocks(&mut [blk_21,blk_22]);

        let mut x_31 = [0u8;16];
        let mut x_32 = [0u8;16];
        
        for i in 0..16{
            x_31[i] = (one[i].wrapping_mul(2)).wrapping_add(two[i]).wrapping_add(blk_21[i]);
            x_32[i] = (one[16+i].wrapping_mul(2)).wrapping_add(two[16+i]).wrapping_add(blk_22[i]);
        }
        let blk_31 = GenericArray::from(x_31);
        let blk_32 = GenericArray::from(x_32);
        self.aes2.encrypt_blocks(&mut [blk_31,blk_32]);

        let mut w_1 = [0u8;32];
        for i in 0..16{
            w_1[i] = one[i].wrapping_add(blk_11[i]).wrapping_add(blk_21[i]).wrapping_add(blk_31[i].wrapping_mul(2));
        }
        for i in 0..16{
            w_1[16+i] = one[16+i].wrapping_add(blk_12[i]).wrapping_add(blk_22[i]).wrapping_add(blk_32[i].wrapping_mul(2));
        }
        return w_1;
    }

    pub fn hash_batch(&self, one: Vec<[u8;32]>, two: Vec<[u8;32]>)-> Vec<[u8;32]>{
        // Final output vector
        let mut fin_vec = one.clone();
        // Iterator for going over Hash functions
        let it = one.iter().zip(two.iter());
        
        let mut o1_vec = Vec::new();
        let mut o2_vec = Vec::new();
        for (_,(o,t)) in it.clone().enumerate(){
            let mut x_11 = [0u8;16];
            let mut x_12 = [0u8;16];
            for i in 0..16{
                x_11[i] = o[i].wrapping_add(t[i].wrapping_mul(2));
                x_12[i] = o[16+i].wrapping_add(t[16+i].wrapping_mul(2));
            }
            o1_vec.push(GenericArray::from(x_11));
            o2_vec.push(GenericArray::from(x_12));
        }
        self.aes0.encrypt_blocks(&mut o1_vec);
        self.aes0.encrypt_blocks(&mut o2_vec);
        
        let mut p1_vec = Vec::new();
        let mut p2_vec = Vec::new();
        let it2 = fin_vec.iter_mut().zip(it.clone().zip(o1_vec.iter().zip(o2_vec.iter())));
        for(_, (f, m)) in it2.enumerate(){
            let o = m.0;
            let t = m.1;
            let mut x_21 = [0u8;16];
            let mut x_22 = [0u8;16];
            for i in 0..16{
                x_21[i] = (o.0[i].wrapping_mul(2)).wrapping_add(o.1[i].wrapping_mul(2)).wrapping_add(t.0[i]);
                x_22[i] = (o.0[16+i].wrapping_mul(2)).wrapping_add(o.1[16+i].wrapping_mul(2)).wrapping_add(t.1[i]);
                // Aggregate final output too
                f[i] = f[i].wrapping_add(t.0[i]);
                f[16+i] = f[16+i].wrapping_add(t.1[i]); 
            }
            p1_vec.push(GenericArray::from(x_21));
            p2_vec.push(GenericArray::from(x_22));
        }
        self.aes1.encrypt_blocks(&mut p1_vec);
        self.aes1.encrypt_blocks(&mut p2_vec);

        let mut q1_vec= Vec::new();
        let mut q2_vec = Vec::new();
        let it3 = fin_vec.iter_mut().zip(it.zip(p1_vec.iter().zip(p2_vec.iter())));
        for(_, (f,m)) in it3.enumerate(){
            let o = m.0;
            let t = m.1;
            let mut x_31 = [0u8;16];
            let mut x_32 = [0u8;16];
            for i in 0..16{
                x_31[i] = (o.0[i].wrapping_mul(2)).wrapping_add(o.1[i]).wrapping_add(t.0[i]);
                x_32[i] = (o.0[16+i].wrapping_mul(2)).wrapping_add(o.1[16+i]).wrapping_add(t.1[i]);
                // Aggregate vectors
                f[i] = f[i].wrapping_add(t.0[i]);
                f[16+i] = f[16+i].wrapping_add(t.1[i]);
            }
            q1_vec.push(GenericArray::from(x_31));
            q2_vec.push(GenericArray::from(x_32));
        }
        self.aes2.encrypt_blocks(&mut q1_vec);
        self.aes2.encrypt_blocks(&mut q2_vec);
        
        let it4 = fin_vec.iter().zip(q1_vec.iter().zip(q1_vec.iter()));
        let mut output_vec = Vec::new();
        for (_,(f,(o,t))) in it4.enumerate(){
            let mut w_1 = [0u8;32];
            for i in 0..16{
                w_1[i] = f[i].wrapping_add(o[i].wrapping_mul(2));
            }
            for i in 0..16{
                w_1[16+i] = f[16+i].wrapping_add(t[i].wrapping_mul(2));
            }
            output_vec.push(w_1);
        }
        return output_vec;
    }
}