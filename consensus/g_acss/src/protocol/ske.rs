use std::collections::HashMap;

use consensus::{interpolate_shares, inverse_vandermonde, matrix_vector_multiply, vandermonde_matrix, LargeField};
use crypto::{decrypt};
use lambdaworks_math::{polynomial::Polynomial, unsigned_integer::element::UnsignedInteger};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use types::Replica;

use crate::{Context, msg::AcssSKEShares};

impl Context{
    pub async fn interpolate_shares(&mut self, sender_rep: Replica, instance_id: usize){
        if !self.acss_ab_state.contains_key(&instance_id){
            return;
        }
        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        
        if acss_ab_state.shares.contains_key(&sender_rep){
            log::info!("Shares already interpolated for sender {} in instance_id {}", sender_rep, instance_id);
            return;
        }
        if !acss_ab_state.commitments.contains_key(&sender_rep) ||
            !self.symmetric_keys_avid.keys_to_me.contains_key(&sender_rep) {
                log::warn!("No commitments or keys found for sender {} in instance_id {}", sender_rep, instance_id);
                return;
        }
        
        let comm_dzk_vals = acss_ab_state.commitments.get(&sender_rep).unwrap().clone();
        
        if !acss_ab_state.batch_wise_shares.contains_key(&sender_rep){
            acss_ab_state.batch_wise_shares.insert(sender_rep.clone(), HashMap::default());
        }
        
        let batch_wise_shares_map = acss_ab_state.batch_wise_shares.get_mut(&sender_rep).unwrap();
        // Interpolate shares here for first t parties
        if !self.use_fft && self.myid < self.num_faults{
            // Interpolate your shares in this case
            let secret_key = self.symmetric_keys_avid.keys_to_me.get(&sender_rep).clone().unwrap().clone();
            let shares: Vec<LargeField> = interpolate_shares(secret_key.clone(), comm_dzk_vals.tot_shares, false, 1).into_iter().map(|el| el).collect();

            let mut expanded_shares = shares.chunks(self.num_faults+1).map(|chunk| chunk.to_vec()).collect::<Vec<Vec<LargeField>>>();
            
            let evaluation_curr_points: Vec<LargeField> = (1..self.num_faults+2).into_iter().map(|i| LargeField::new(UnsignedInteger::from(i as u64))).collect();
            let vdm_matrix = vandermonde_matrix(evaluation_curr_points);
            let inv_vdm_matrix = inverse_vandermonde(vdm_matrix);
            
            let evaluation_new_points: Vec<LargeField> = (self.num_faults+2..self.num_nodes+1).into_iter().map(|i| LargeField::new(UnsignedInteger::from(i as u64))).collect();
            
            expanded_shares.par_iter_mut().for_each(|grp| {
                let coefficients = matrix_vector_multiply(&inv_vdm_matrix, &grp);
                let poly = Polynomial::new(&coefficients);
                
                let new_evaluations = evaluation_new_points.iter().map(|pt| poly.evaluate(pt)).collect::<Vec<LargeField>>();
                grp.extend(new_evaluations);
            });

            let mut batch_wise_shares = vec![vec![]; self.num_nodes];

            for poly_evaluation in expanded_shares.into_iter(){
                for (i, share) in poly_evaluation.into_iter().enumerate(){
                    batch_wise_shares[i].push(share.to_bytes_be());
                }
            }

            let mut expanded_nonce_shares = vec![interpolate_shares(secret_key.clone(),self.num_faults+1, true, 1u8)];
            
            expanded_nonce_shares.par_iter_mut().for_each(|grp| {
                let coefficients = matrix_vector_multiply(&inv_vdm_matrix, &grp);
                let poly = Polynomial::new(&coefficients);
                
                let new_evaluations = evaluation_new_points.iter().map(|pt| poly.evaluate(pt)).collect::<Vec<LargeField>>();
                grp.extend(new_evaluations);
            });
            

            let mut expanded_blinding_shares = vec![interpolate_shares(secret_key.clone(), self.num_faults+1, true, 2u8)];
            expanded_blinding_shares.par_iter_mut().for_each(|grp| {
                let coefficients = matrix_vector_multiply(&inv_vdm_matrix, &grp);
                let poly = Polynomial::new(&coefficients);
                
                let new_evaluations = evaluation_new_points.iter().map(|pt| poly.evaluate(pt)).collect::<Vec<LargeField>>();
                grp.extend(new_evaluations);
            });

            let mut expanded_blinding_nonce_shares = vec![interpolate_shares(secret_key, self.num_faults+1, true, 3u8)];
            expanded_blinding_nonce_shares.par_iter_mut().for_each(|grp| {
                let coefficients = matrix_vector_multiply(&inv_vdm_matrix, &grp);
                let poly = Polynomial::new(&coefficients);
                
                let new_evaluations = evaluation_new_points.iter().map(|pt| poly.evaluate(pt)).collect::<Vec<LargeField>>();
                grp.extend(new_evaluations);
            });
            
            for batch in 0..self.num_nodes{
                let acss_ske_shares = AcssSKEShares{
                    evaluations: (batch_wise_shares[batch].clone(),expanded_nonce_shares[0][batch].to_bytes_be()),
                    blinding_evaluations: (expanded_blinding_shares[0][batch].to_bytes_be(), expanded_blinding_nonce_shares[0][batch].to_bytes_be()),
                    rep: sender_rep,
                    batch: batch
                };
                batch_wise_shares_map.insert(batch, acss_ske_shares);
            }
        }
        self.verify_shares(sender_rep,instance_id).await;
    }

    pub async fn decrypt_shares(&mut self, sender_rep: Replica, instance_id: usize) {
        if self.myid < self.num_faults{
            self.interpolate_shares(sender_rep, instance_id).await;
            return;
        }
        if !self.acss_ab_state.contains_key(&instance_id) {
            return;
        }
        let acss_ab_state = self.acss_ab_state.get_mut(&instance_id).unwrap();
        
        if !acss_ab_state.enc_shares.contains_key(&sender_rep) ||
            !self.symmetric_keys_avid.keys_to_me.contains_key(&sender_rep){
            return;
        }
        
        let sec_key = self.symmetric_keys_avid.keys_to_me.get(&sender_rep).unwrap().clone();
        let enc_shares = acss_ab_state.enc_shares.get_mut(&sender_rep).unwrap();
        
        if !acss_ab_state.batch_wise_shares.contains_key(&sender_rep){
            acss_ab_state.batch_wise_shares.insert(sender_rep, HashMap::default());
        }

        let batch_wise_shares = acss_ab_state.batch_wise_shares.get_mut(&sender_rep).unwrap();
        for (batch, encrypted_shares) in enc_shares.clone().into_iter(){
            let dec_shares = decrypt(sec_key.as_slice(), encrypted_shares.clone());
            let shares : AcssSKEShares = bincode::deserialize(dec_shares.as_slice()).unwrap();
            batch_wise_shares.insert(batch, shares);

            enc_shares.remove(&batch);
        }
        
        if batch_wise_shares.len() % self.avid_throttling_quant == 0 && sender_rep == self.myid{
            // Schedule next batch of AVID instances
            let avid_status = self.throttle_avid_instances(instance_id).await;
            if avid_status{
                log::info!("All AVID instances completed for ACSS instance id {}", instance_id);
            }
        }
        self.verify_shares(sender_rep, instance_id).await;
    }

    pub async fn decrypt_shares_all_instances(&mut self, party: Replica){
        let mut encrypted_instances = Vec::new();
        for (instance_id, acss_ab_state) in self.acss_ab_state.iter_mut() {
            if acss_ab_state.enc_shares.contains_key(&party) && !acss_ab_state.shares.contains_key(&party) {
                encrypted_instances.push(instance_id.clone());
            }
        }
        for instance_id in encrypted_instances {
            self.decrypt_shares(party, instance_id).await;
        }
    }
}