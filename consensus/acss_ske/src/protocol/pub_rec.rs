use std::ops::{Add, Mul};

use consensus::{LargeField, LargeFieldSer, DZKProof};
use crypto::{aes_hash::{MerkleTree, HashState}, hash::{Hash, do_hash}};
use lambdaworks_math::{polynomial::Polynomial};
use rayon::prelude::{IntoParallelIterator, ParallelIterator, IntoParallelRefIterator, IndexedParallelIterator};

use crate::Context;

impl Context{
    pub fn group_polynomials_for_public_reconstruction(
        polynomials: Vec<Polynomial<LargeField>>,
        evaluation_points: Vec<LargeField>,
        group_degree: usize
    )-> Vec<Vec<Polynomial<LargeField>>>{
        let coefficients_grouped: Vec<Vec<Polynomial<LargeField>>> = polynomials.chunks(group_degree).map(|el_vec| el_vec.to_vec()).collect();
        
        let collection_evaluation_points: Vec<Vec<Polynomial<LargeField>>> = evaluation_points.into_par_iter().map(|element|{
            // Compute t+1 powers
            let mut powers = vec![element];
            let mut element_power = element;
            for _ in 0..group_degree-1{
                element_power = element_power*element;
                powers.push(element_power.clone());
            }
            // Use these powers zipped with the coefficients
            let agg_polys: Vec<Polynomial<LargeField>> = coefficients_grouped.par_iter().map(|group| {
                let dot_product: Vec<Polynomial<LargeField>> 
                    = group.iter().zip(powers.iter()).map(|(poly,power)| poly*power).collect();
                let sum: Polynomial<LargeField> = dot_product.iter().fold(Polynomial::zero(), |acc, poly| acc + poly);
                return sum;
            }).collect();
            return agg_polys;
        }).collect();

        collection_evaluation_points
    }

    pub fn compute_commitments(
        coefficients: Vec<Vec<Polynomial<LargeField>>>,
        evaluation_points: Vec<LargeField>,
        nonce_evaluations: Vec<Vec<LargeField>>,
        hash_context: &HashState
    )-> Vec<MerkleTree> {
        let merkle_trees: Vec<MerkleTree> = coefficients.par_iter().zip(nonce_evaluations.par_iter()).map(|(eval_vec, nonce_vec)|{
            let evaluations: Vec<Vec<LargeFieldSer>> = eval_vec.into_par_iter().map(|poly| {
                let evaluations: Vec<LargeFieldSer> = evaluation_points.iter().map(|point| poly.evaluate(point).clone().to_bytes_be()).collect();
                return evaluations;
            }).collect();
            let mut appended_shares: Vec<Vec<u8>> = vec![vec![]; evaluation_points.len()];
            for evaluation_single_poly in evaluations.into_iter(){
                for (index,eval_serialized) in evaluation_single_poly.into_iter().enumerate(){
                    appended_shares[index].extend(eval_serialized);
                }
            }
            // append nonce shares to appended_shares
            for (index, nonce_share) in nonce_vec.iter().enumerate(){
                appended_shares[index].extend(nonce_share.to_bytes_be());
            }
            // Build Merkle tree on these appended shares
            let hashes: Vec<Hash> = appended_shares.into_iter().map(|share|{
                do_hash(share.as_slice())
            }).collect();

            MerkleTree::new(hashes, hash_context)
        }).collect();
        merkle_trees
    }

    pub fn aggregate_polynomials_for_dzk(
        polys: Vec<Vec<Polynomial<LargeField>>>,
        blinding_polys: Vec<Polynomial<LargeField>>,
        root_fes: Vec<LargeField>
    )-> Vec<Polynomial<LargeField>>{
        let agg_poly_vector: Vec<Polynomial<LargeField>> = (polys.into_par_iter().zip(
            blinding_polys.into_par_iter()
        )).zip(root_fes.into_par_iter()).map(|((poly_group, b_poly), root_fe)|{
            // Start aggregation
            let mut agg_poly = b_poly.clone();
            let mut root_fe_iter_mul = root_fe.clone();
            for poly in poly_group.into_iter(){
                agg_poly = agg_poly.add(poly.mul(&root_fe_iter_mul));
                root_fe_iter_mul *= &root_fe;
            }
            return agg_poly.clone();
        }).collect();
        agg_poly_vector
    }

    pub fn compute_dzk_proofs(
        &self,
        dzk_share_polynomials: Vec<Polynomial<LargeField>>,
        column_wise_roots: Vec<LargeField>
    ) -> (Vec<Vec<DZKProof>>, Vec<Vec<LargeFieldSer>>, Vec<Vec<LargeFieldSer>>){
        // (Replica, (g_0 values), (g_1 values), (Vector of Merkle Proofs for each g_0,g_1 value))
        let mut shares_proofs_dzk: Vec<Vec<DZKProof>> = Vec::new();
        let mut dzk_broadcast_polys = Vec::new();
        let mut hashes = Vec::new();
        for _ in 0..dzk_share_polynomials.len(){
            shares_proofs_dzk.push(Vec::new());
        }
        for (dzk_poly,column_root) in dzk_share_polynomials.into_iter().zip(column_wise_roots.into_iter()){
            
            let mut merkle_roots = Vec::new();
            let mut eval_points = Vec::new();
            
            let mut trees: Vec<MerkleTree> = Vec::new();
            //trees.push(mts[rep].clone());
            
            let coefficients = dzk_poly.clone();
            
            let iteration = 1;
            let root = column_root;
            //merkle_roots.push(root.clone());

            // Reliably broadcast these coefficients
            let coeffs_const_size: Vec<LargeFieldSer> = self.folding_dzk_context.gen_dzk_proof(
                &mut eval_points, 
                &mut trees, 
                coefficients.coefficients, 
                iteration, 
                root.to_bytes_be()
            ).into_iter().map(|x| x.to_bytes_be()).collect();
            
            for tree in trees.iter(){
                merkle_roots.push(tree.root());
            }
            dzk_broadcast_polys.push(coeffs_const_size);

            let mut dzk_proofs_all_nodes = Vec::new();
            for _ in 0..self.num_nodes{
                dzk_proofs_all_nodes.push(DZKProof{
                    g_0_x: Vec::new(),
                    g_1_x: Vec::new(),
                    proof: Vec::new(),
                });
            }

            
            for (g_0_g_1_shares,mt) in eval_points.into_iter().zip(trees.into_iter()){                
                for (rep,g) in (0..self.num_nodes).into_iter().zip(g_0_g_1_shares.into_iter()){
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().g_0_x.push(g.0.to_bytes_be());
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().g_1_x.push(g.1.to_bytes_be());
                    dzk_proofs_all_nodes.get_mut(rep).unwrap().proof.push(mt.gen_proof(rep));
                }
            }

            for (rep,proof) in (0..self.num_nodes).into_iter().zip(dzk_proofs_all_nodes.into_iter()){
                shares_proofs_dzk[rep].push(proof);
            }
            hashes.push(merkle_roots);
        }
        (shares_proofs_dzk,dzk_broadcast_polys,hashes)
    }
}