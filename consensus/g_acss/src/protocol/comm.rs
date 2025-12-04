use consensus::LargeField;
use ha_crypto::{aes_hash::HashState, hash::Hash};

use crate::Context;

impl Context{
    pub fn gen_commitments(
        bv_polys: &Vec<Vec<Vec<LargeField>>>, 
        nonce_poly: &Vec<Vec<LargeField>>,
        num_nodes: usize,
        hc:&HashState
    )-> Vec<Vec<Hash>>{
        let mut app_vectors: Vec<Vec<Vec<u8>>> = vec![vec![vec![];num_nodes]; num_nodes];
        for poly_group in bv_polys.iter(){
            for (i,poly) in poly_group.iter().enumerate(){
                for (j,eval) in poly.iter().enumerate(){
                    app_vectors[i][j].extend_from_slice(&eval.to_bytes_be());
                }
            }
        }
        for (i,poly) in nonce_poly.iter().enumerate(){
            for (j,eval) in poly.iter().enumerate(){
                app_vectors[i][j].extend_from_slice(&eval.to_bytes_be());
            }
        }
        let commitments: Vec<Vec<Hash>> = app_vectors.into_iter().map(|vecs|{
            return vecs.into_iter().map(|v| hc.do_hash_aes(&v)).collect();
        }).collect();

        return commitments;
    }

    pub fn root_commitment(
        commitments: &Vec<Vec<Hash>>,
        hc: &HashState
    )-> Hash{
        let mut agg_vector = Vec::new();
        for comm_row in commitments{
            for hash in comm_row{
                agg_vector.extend(hash);
            }
        }
        return hc.do_hash_aes(agg_vector.as_slice());
    }
}