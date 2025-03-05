use crypto::{LargeFieldSer, aes_hash::{Proof, MerkleTree}, hash::{Hash, do_hash}};
//use num_bigint_dig::BigInt;
use consensus::LargeField;
use lambdaworks_math::traits::ByteConversion;
use crate::Context;

impl Context{
    pub fn verify_commitments_rows(self: &Context, shares: (Vec<Vec<LargeFieldSer>>, Vec<LargeFieldSer>, Vec<Proof>), roots: Vec<Hash>) -> bool{
        let mut appended_share_vec = Vec::new();
        for _ in 0..self.num_nodes{
            let row = Vec::new();
            appended_share_vec.push(row);
        }

        let row_shares = shares.0;
        for row_poly in row_shares{
            for (index, point) in (0..self.num_nodes).zip(row_poly.into_iter()){
                appended_share_vec[index].extend(point);
            }
        }
        for (app_share_vec, nonce_vec) in appended_share_vec.iter_mut().zip(shares.1.into_iter()){
            app_share_vec.extend(nonce_vec);
        }
        // Compute Commitments
        let commitments: Vec<Hash> = appended_share_vec.into_iter().map(|el| do_hash(el.as_slice())).collect();
        for (comm, (proof, root)) in commitments.into_iter().zip(shares.2.into_iter().zip(roots.into_iter())){
            if !proof.validate(&self.hash_context) || 
                proof.item() != comm || 
                proof.root() != root{
                log::error!("Commitment verification failed");
                log::error!("Proof validation: {}", proof.validate(&self.hash_context));
                log::error!("Proof item and commitment: {:?} {:?}", proof.item(), comm);
                log::error!("Root and proof root: {:?} {:?}",root, proof.root());
                return false;
            }
        }
        true
    }

    pub fn verify_blinding_row_commitments(self: &Context,shares: Vec<(LargeFieldSer, LargeFieldSer, Proof)>, roots: Vec<Hash>) -> bool{
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

    pub fn verify_column_share_commitments(self: &Context, shares: &Vec<Vec<LargeField>>, nonces: &Vec<LargeField>, root: Hash)-> bool{
        let mut commitments = Vec::new();
        let mut appended_share_vec = Vec::new();

        for _ in 0..self.num_nodes+1{
            let row = Vec::new();
            appended_share_vec.push(row);
        }

        for col_poly in shares{
            for (index, point) in (0..self.num_nodes+1).zip(col_poly.into_iter()){
                appended_share_vec[index].extend(point.to_bytes_be().to_vec());
            }
        }
        for (app_share_vec, nonce_vec) in appended_share_vec.iter_mut().zip(nonces.into_iter()){
            app_share_vec.extend(nonce_vec.to_bytes_be().to_vec());
        }

        for rep in 0..self.num_nodes{
            commitments.push(do_hash(appended_share_vec[rep+1].as_slice()));
        }
        // Construct Merkle Tree
        let mt = MerkleTree::new(commitments, &self.hash_context);
        if mt.root() != root{
            log::error!("Error verifying column polynomial root");
            return false;
        }
        true
    }

    pub fn verify_blinding_column_commitments(self: &Context, shares: &Vec<LargeField>, nonces: &Vec<LargeField>, root: Hash)-> bool{
        let mut commitments = Vec::new();
        for rep in 0..self.num_nodes{
            let mut app_share = Vec::new();
            app_share.extend(shares[rep+1].clone().to_bytes_be().to_vec());
            app_share.extend(nonces[rep+1].clone().to_bytes_be().to_vec());
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