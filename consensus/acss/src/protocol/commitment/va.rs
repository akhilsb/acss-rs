use crypto::{LargeFieldSer, aes_hash::{Proof, MerkleTree}, hash::{Hash, do_hash}};
use num_bigint_dig::BigInt;

use crate::Context;

impl Context{
    pub fn verify_row_commitments(self: &Context,shares: Vec<(LargeFieldSer, LargeFieldSer, Proof)>, roots: Vec<Hash>) -> bool{
        for ((share, nonce, proof), root) in shares.into_iter().zip(roots.into_iter()){
            let mut app_val = Vec::new();
            app_val.extend(share.clone());
            app_val.extend(nonce);

            let commitment = do_hash(app_val.as_slice());
            if !proof.validate(&self.hash_context) || 
                proof.item() != commitment || 
                proof.root() != root{
                log::error!("Commitment verification failed");
                log::error!("Proof validation: {}", proof.validate(&self.hash_context));
                log::error!("Proof item and commitment: {:?} {:?}", proof.item(), commitment);
                log::error!("Root and proof root: {:?} {:?}",root, proof.root());
                return false;
            }
        }
        true
    }

    pub fn verify_column_commitments(self: &Context, shares: Vec<BigInt>, nonces: Vec<BigInt>, root: Hash)-> bool{
        let mut commitments = Vec::new();
        for rep in 0..self.num_nodes{
            let mut app_share = Vec::new();
            app_share.extend(shares[rep+1].clone().to_signed_bytes_be());
            app_share.extend(nonces[rep+1].clone().to_signed_bytes_be());
            commitments.push(do_hash(app_share.as_slice()));
        }
        // Construct Merkle Tree
        let mt = MerkleTree::new(commitments, &self.hash_context);
        if mt.root() != root{
            log::error!("Error verifying column polynomial root");
            return false;
        }
        true
    }    
}