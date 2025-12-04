use consensus::{LargeFieldSSS, RBCSyncMsg, inverse_vandermonde, matrix_vector_multiply, vandermonde_matrix};
use crypto::{LargeField, LargeFieldSer};
use lambdaworks_math::{traits::ByteConversion, polynomial::Polynomial};
use rayon::prelude::IntoParallelIterator;
use types::{WrapperMsg, Replica, SyncMsg, SyncState};
use rayon::prelude::{ParallelIterator};

use crate::{Context, msg::ProtMsg};

impl Context{
    pub async fn process_consensus_output(&mut self, mut acs_output: Vec<Replica>){
        self.dpss_state.acs_output.extend(acs_output.clone());
        acs_output.sort();
        self.ba_state.acs_output_sorted.extend(acs_output);
        // Generate random shares
        self.gen_rand_shares().await;
    }

    pub async fn gen_rand_shares(&mut self){
        if self.dpss_state.acs_output.len() == 0{
            return;
        }

        if self.ba_state.shares_generated{
            return;
        }

        let mut ht_indices = Vec::new();
        let mut shares_to_be_combined = Vec::new();
        
        let mut coin_shares_to_be_combined = Vec::new();
        let per_batch = self.per_batch + (self.num_faults+1) - (self.per_batch)%(self.num_faults+1);
        
        for _ in 0..self.num_batches*per_batch{
            shares_to_be_combined.push(Vec::new());
        }

        for _ in 0..self.coin_batch{
            coin_shares_to_be_combined.push(Vec::new());
        }
        
        for rep in 0..self.num_nodes{
            if self.dpss_state.acs_output.contains(&rep){
                // Fetch shares
                if !self.dpss_state.acss_map.contains_key(&rep){
                    log::info!("ACSS did not terminate yet, will retry later for share generation");
                    return;
                }
                let share_inst_map = self.dpss_state.acss_map.get(&rep).unwrap();
                let mut index = 0;
                for batch in 1..self.num_batches+2{
                    if !share_inst_map.contains_key(&batch){
                        log::info!("ACSS did not terminate yet, will retry later for share generation");
                        return;
                    }
                    let batch_shares = share_inst_map.get(&batch).unwrap().0.clone();
                    if batch_shares.is_none(){
                        log::info!("ACSS did not terminate yet, will retry later for share generation");
                        return;
                    }
                    if batch == self.num_batches+1{
                        // Coin shares
                        for (coin_index,share) in batch_shares.unwrap().0.clone().into_iter().enumerate(){
                            coin_shares_to_be_combined[coin_index].push(share);
                        }
                    }
                    else{
                        for share in batch_shares.unwrap().0.clone(){
                            shares_to_be_combined[index].push(share);
                            index +=1;
                        }
                    }
                }
                // Add coin shares
                ht_indices.push(LargeField::from((rep+1) as u64));
            }
        }
        let vandermonde = LargeFieldSSS::vandermonde_matrix(ht_indices);
        let combined_shares: Vec<Vec<LargeField>> = shares_to_be_combined.into_par_iter().map(|vec| {
            let mut mult_shares = LargeFieldSSS::matrix_vector_multiply(&vandermonde, &vec);
            mult_shares.truncate(self.num_faults+1);
            mult_shares
        }).collect();

        let coin_shares: Vec<LargeField> = coin_shares_to_be_combined.into_par_iter().map(|vec| {
            let mut mult_shares = LargeFieldSSS::matrix_vector_multiply(&vandermonde, &vec);
            mult_shares.truncate(self.num_faults+1);
            mult_shares
        }).flatten().collect();

        
        // Encode and reconstruct these combined shares
        // Efficient Public Reconstruction
        let mut party_wise_shares = Vec::new();
        for _ in 0..self.num_nodes{
            party_wise_shares.push(Vec::new());
        }
        for share_comb in combined_shares{
            // Create polynomial
            for rep in 0..self.num_nodes{
                party_wise_shares[rep].push(self.large_field_shamir_ss.mod_evaluate_at_lf(share_comb.as_slice(), LargeField::from((rep+1) as u64)));
            }
        }

        for (rep,shares) in (0..self.num_nodes).into_iter().zip(party_wise_shares.into_iter()){
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            let shares_ser = shares.into_iter().map(|x| x.to_bytes_be()).collect();
            let prot_msg = ProtMsg::PubRecEcho1(shares_ser);
            let wrapper = WrapperMsg::new(prot_msg, self.myid, secret_key.as_slice());
            let cancel_handler = self.net_send.send(rep, wrapper).await;
            self.add_cancel_handler(cancel_handler);
        }
        log::info!("Prepared {} coin shares", coin_shares.len());
        self.coin_shares.extend(coin_shares);
        
        self.ba_state.shares_generated = true;
        self.verify_start_binary_ba().await;
    }

    pub async fn process_pub_rec_echo1_msg(&mut self, shares_ser: Vec<LargeFieldSer>, sender: Replica){
        let shares: Vec<LargeField> = shares_ser.into_iter().map(|x| LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
        // Utilize shares for error correction
        let shares_len = shares.len();
        self.dpss_state.pub_rec_echo1s.insert(sender, shares);
        if self.dpss_state.pub_rec_echo1s.len() == self.num_faults + 1{
            // Reconstruct all shares for polynomials
            let mut evaluation_indices = Vec::new();
            let mut vec_shares_indices = Vec::new();
            for _ in 0..shares_len{
                vec_shares_indices.push(Vec::new());
            }
            for rep in 0..self.num_nodes{
                if self.dpss_state.pub_rec_echo1s.contains_key(&rep){
                    evaluation_indices.push(LargeField::from((rep+1) as u64));
                    let shares_sub_poly = self.dpss_state.pub_rec_echo1s.get(&rep).unwrap().clone();
                    for (index, shares_ind) in (0..shares_len).into_iter().zip(shares_sub_poly.into_iter()){
                        vec_shares_indices[index].push(shares_ind);
                    }
                }
            }

            // Interpolate polynomials
            let secret_evaluation_point= LargeField::from(0 as u64);

            // Generate vandermonde matrix
            let vandermonde = vandermonde_matrix(evaluation_indices.clone());
            let inverse_vandermonde = inverse_vandermonde(vandermonde);

            let l2_shares : Vec<LargeFieldSer> = vec_shares_indices.into_par_iter().map(|evals|{
                let coefficients = matrix_vector_multiply(&inverse_vandermonde, &evals);
                return Polynomial::new(&coefficients).evaluate(&secret_evaluation_point).to_bytes_be();
            }).collect();
            
            // Broadcast secrets
            self.broadcast(ProtMsg::PubRecEcho2(l2_shares)).await;
        }
    }

    pub async fn process_pub_rec_echo2_msg(&mut self, shares_ser: Vec<LargeFieldSer>, sender: Replica){
        let shares: Vec<LargeField> = shares_ser.into_iter().map(|x| LargeField::from_bytes_be(x.as_slice()).unwrap()).collect();
        // Utilize shares for error correction
        let shares_len = shares.len();
        self.dpss_state.pub_rec_echo2s.insert(sender, shares);
        if self.dpss_state.pub_rec_echo2s.len() == self.num_faults + 1{
            // Reconstruct all shares for polynomials
            let mut vec_shares_indices = Vec::new();
            for _ in 0..shares_len{
                vec_shares_indices.push(Vec::new());
            }

            let mut ht_indices = Vec::new();
            for rep in 0..self.num_nodes{
                if self.dpss_state.pub_rec_echo2s.contains_key(&rep){
                    let shares_sub_poly = self.dpss_state.pub_rec_echo2s.get(&rep).unwrap().clone();
                    for (index, shares_ind) in (0..shares_len).into_iter().zip(shares_sub_poly.into_iter()){
                        vec_shares_indices[index].push(shares_ind);
                    }
                    ht_indices.push(LargeField::from((rep+1) as u64));
                }
            }

            // Interpolate entire polynomial
            let vandermonde_matrix = vandermonde_matrix(ht_indices);
            let vandermonde_inverse = inverse_vandermonde(vandermonde_matrix);
            
            let secrets_blinded: Vec<LargeField> = vec_shares_indices.into_par_iter().map(|evals|{
                let coefficients = matrix_vector_multiply(&vandermonde_inverse, &evals);
                return Polynomial::new(&coefficients).coefficients;
            }).flatten().collect();

            log::info!("Finished reconstruction of secrets, total length: {}", secrets_blinded.len());
            self.ba_state.secrets_reconstructed = true;
            self.verify_start_binary_ba().await;
            //self.terminate("Term".to_string()).await;
        }
    }

    // Invoke this function once you terminate the protocol
    pub async fn terminate(&mut self, data: String) {
        if !self.terminated{
            self.terminated = true;
            let rbc_sync_msg = RBCSyncMsg{
                id: 1,
                msg: data,
            };

            let ser_msg = bincode::serialize(&rbc_sync_msg).unwrap();
            let cancel_handler = self
                .sync_send
                .send(
                    0,
                    SyncMsg {
                        sender: self.myid,
                        state: SyncState::COMPLETED,
                        value: ser_msg,
                    },
                )
                .await;
            self.add_cancel_handler(cancel_handler);
        }
    }
}