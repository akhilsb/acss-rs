use consensus::LargeFieldSSS;
use crypto::{LargeField, LargeFieldSer};
use types::{WrapperMsg, Replica};

use crate::{Context, msg::ProtMsg};

impl Context{
    pub async fn gen_rand_shares(&mut self){
        if self.acs_state.acs_output.len() == 0{
            return;
        }

        let mut ht_indices = Vec::new();
        let mut shares_to_be_combined = Vec::new();
        let per_batch = self.per_batch + (self.num_faults+1) - (self.per_batch)%(self.num_faults+1);
        for _ in 0..self.num_batches*per_batch{
            shares_to_be_combined.push(Vec::new());
        }
        for rep in 0..self.num_nodes{
            if self.acs_state.acs_output.contains(&rep){
                // Fetch shares
                let share_inst_map = self.acss_map.get(&rep).unwrap();
                let mut index = 0;
                for batch in 1..self.num_batches+1{
                    if !share_inst_map.contains_key(&batch){
                        log::info!("ACSS did not terminate yet, will retry later for share generation");
                        return;
                    }
                    let batch_shares = share_inst_map.get(&batch).unwrap().0.clone().unwrap().0;
                    for share in batch_shares{
                        shares_to_be_combined[index].push(share);
                        index +=1;
                    }
                }
                ht_indices.push(LargeField::from(rep+1));
            }
        }
        let vandermonde = self.large_field_shamir_ss.vandermonde_matrix(&ht_indices);
        let mut combined_shares = Vec::new();
        for vec_shares in shares_to_be_combined{
            let mut mult_shares = LargeFieldSSS::matrix_vector_multiply(&vandermonde, &vec_shares, &self.large_field_prime);
            mult_shares.truncate(self.num_faults+1);
            combined_shares.push(mult_shares);
        }
        // Encode and reconstruct these combined shares
        // Efficient Public Reconstruction
        let mut party_wise_shares = Vec::new();
        for _ in 0..self.num_nodes{
            party_wise_shares.push(Vec::new());
        }
        for share_comb in combined_shares{
            // Create polynomial
            for rep in 0..self.num_nodes{
                party_wise_shares[rep].push(self.large_field_shamir_ss.mod_evaluate_at_lf(share_comb.as_slice(), LargeField::from(rep+1)));
            }
        }

        for (rep,shares) in (0..self.num_nodes).into_iter().zip(party_wise_shares.into_iter()){
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap();
            let shares_ser = shares.into_iter().map(|x| x.to_signed_bytes_be()).collect();
            let prot_msg = ProtMsg::PubRecEcho1(shares_ser);
            let wrapper = WrapperMsg::new(prot_msg, self.myid, secret_key.as_slice());
            let cancel_handler = self.net_send.send(rep, wrapper).await;
            self.add_cancel_handler(cancel_handler);
        }
    }

    pub async fn process_pub_rec_echo1_msg(&mut self, shares_ser: Vec<LargeFieldSer>, sender: Replica){
        let shares: Vec<LargeField> = shares_ser.into_iter().map(|x| LargeField::from_signed_bytes_be(x.as_slice())).collect();
        // Utilize shares for error correction
        let shares_len = shares.len();
        self.acs_state.pub_rec_echo1s.insert(sender, shares);
        if self.acs_state.pub_rec_echo1s.len() == self.num_faults + 1{
            // Reconstruct all shares for polynomials
            let mut vec_shares_indices = Vec::new();
            for _ in 0..shares_len{
                vec_shares_indices.push(Vec::new());
            }
            for rep in 0..self.num_nodes{
                if self.acs_state.pub_rec_echo1s.contains_key(&rep){
                    let shares_sub_poly = self.acs_state.pub_rec_echo1s.get(&rep).unwrap().clone();
                    for (index, shares_ind) in (0..shares_len).into_iter().zip(shares_sub_poly.into_iter()){
                        vec_shares_indices[index].push(((rep+1), shares_ind));
                    }
                }
            }

            // Reconstruct secret
            let mut secrets = Vec::new();
            for shares in vec_shares_indices{
                secrets.push(self.large_field_shamir_ss.recover(shares.as_slice()));
            }

            // Broadcast secrets
            let secrets_ser = secrets.into_iter().map(|x| x.to_signed_bytes_be()).collect();
            self.broadcast(ProtMsg::PubRecEcho2(secrets_ser)).await;
        }
    }

    pub async fn process_pub_rec_echo2_msg(&mut self, shares_ser: Vec<LargeFieldSer>, sender: Replica){
        let shares: Vec<LargeField> = shares_ser.into_iter().map(|x| LargeField::from_signed_bytes_be(x.as_slice())).collect();
        // Utilize shares for error correction
        let shares_len = shares.len();
        self.acs_state.pub_rec_echo2s.insert(sender, shares);
        if self.acs_state.pub_rec_echo2s.len() == self.num_faults + 1{
            // Reconstruct all shares for polynomials
            let mut vec_shares_indices = Vec::new();
            for _ in 0..shares_len{
                vec_shares_indices.push(Vec::new());
            }

            let mut ht_indices = Vec::new();
            for rep in 0..self.num_nodes{
                if self.acs_state.pub_rec_echo2s.contains_key(&rep){
                    let shares_sub_poly = self.acs_state.pub_rec_echo2s.get(&rep).unwrap().clone();
                    for (index, shares_ind) in (0..shares_len).into_iter().zip(shares_sub_poly.into_iter()){
                        vec_shares_indices[index].push(shares_ind);
                    }
                    ht_indices.push(LargeField::from(rep+1));
                }
            }

            // Interpolate entire polynomial
            let vandermonde_matrix = self.large_field_shamir_ss.vandermonde_matrix(&ht_indices);
            let vandermonde_inverse = self.large_field_shamir_ss.inverse_vandermonde(vandermonde_matrix);
            
            let mut secrets_blinded = Vec::new();
            for shares in vec_shares_indices{
                secrets_blinded.extend(self.large_field_shamir_ss.polynomial_coefficients_with_vandermonde_matrix(&vandermonde_inverse, &shares));
            }
            log::info!("Finished reconstruction of secrets, total length: {}", secrets_blinded.len());
            self.terminate("Term".to_string()).await;
        }
    }
}