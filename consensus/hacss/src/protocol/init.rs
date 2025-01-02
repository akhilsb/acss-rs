use crypto::{encrypt, pseudorandom_lf, LargeField, SmallField, decrypt};
use crypto::hash::{do_hash};
use network::Acknowledgement;
use network::plaintcp::CancelHandler;
// use network::Acknowledgement;
// use network::plaintcp::CancelHandler;
use num_bigint_dig::RandBigInt;
use num_bigint_dig::{BigInt};
use types::{WrapperMsg, Replica};

use crate::{Commitment, Shares, ProtMsg, VSSCommitments};
use crate::{context::Context};

impl Context{
    /**
     * ACSS protocol layout.
     * 
     * 1. Shamir secret sharing. Split secrets into shares. 
     * 2. Sample random blinding (b(x)), nonce (y(x)), and blinding nonce polynomials(y_0(x))
     * 3. Generate commitments to shares and the blinding polynomial. 
     * 4. Compute succinct commitment
     * 5. Generate distributed ZK polynomial
     * 6. Encrypt shares and broadcast commitments.  
    */
    // For now, do all interpolation in large fields. 
    // We convert large field to small field using ring reduction process. 
    pub async fn init_acss(self: &mut Context, secrets: Vec<SmallField>, instance_id: usize){
        
        let num_secrets = secrets.len();
        // 1. Shamir secret sharing

        let zero = BigInt::from(0);
        //let one = BigInt::from(1);

        let mut shares: Vec<Vec<LargeField>> = Vec::new();
        
        for _i in 0..self.num_nodes{
            shares.push(Vec::new());
        }
        
        let mut polynomial_evaluations = Vec::new();
        
        for secret in secrets.into_iter(){
            
            let mut poly = Vec::new();
            //poly.push(secret%self.small_field_prime);
            poly.push(BigInt::from(secret));
            polynomial_evaluations.push(poly);
            
        }

        // 2. Sample blinding, nonce, and blinding nonce polynomials
        let mut nonce_poly = Vec::new();
        let mut blinding_poly = Vec::new();
        let mut blinding_nonce_poly = Vec::new();

        let rand1 = rand::thread_rng().gen_bigint_range(&zero, &self.large_field_prime.clone());
        let rand2 = rand::thread_rng().gen_bigint_range(&zero, &self.large_field_prime.clone());
        let rand3 = rand::thread_rng().gen_bigint_range(&zero, &self.large_field_prime.clone());

        nonce_poly.push(rand1);
        blinding_poly.push(rand2);
        blinding_nonce_poly.push(rand3);
        
        for rep in 0..self.num_faults{

            let mut secret_key = self.sec_key_map.get(&rep).clone().unwrap().clone();
            // Create a new seed from the secret key and the instance id
            secret_key.extend(instance_id.to_be_bytes());
            let rand_eval = pseudorandom_lf(secret_key.as_slice(), polynomial_evaluations.len());
            let mut index = 0;
            for mut share in rand_eval.into_iter(){
                // Ensure all shares are greater than zero. TODO: Maybe use BigUInt? 
                share = &share%&self.large_field_prime;
                if share < zero{
                    share += &self.large_field_prime;
                }
                polynomial_evaluations.get_mut(index).unwrap().push(share);
                index = index + 1;
            }

            // Sample blinding, nonce, and blinding nonce shares as well
            secret_key.extend(instance_id.to_be_bytes());
            let rand_eval: Vec<LargeField> = pseudorandom_lf(secret_key.as_slice(), 3);
            let mut index = 0;
            for mut elem in rand_eval.into_iter(){
                // Ensure all shares are greater than 0 for positive modulus
                if elem < zero{
                    elem += &self.large_field_prime;
                }
                if index == 0{
                    nonce_poly.push(elem % &self.large_field_prime);
                }
                else if index == 1{
                    blinding_poly.push(elem% &self.large_field_prime);
                }
                else if index == 2{
                    blinding_nonce_poly.push(elem % &self.large_field_prime);
                }
                else{
                    break;
                }
                index = index+1;
            }
        }
        for poly in polynomial_evaluations.iter_mut(){
            self.large_field_sss.fill_evaluation_at_all_points(poly);
        }
        self.large_field_sss.fill_evaluation_at_all_points(&mut nonce_poly);
        self.large_field_sss.fill_evaluation_at_all_points(&mut blinding_poly);
        self.large_field_sss.fill_evaluation_at_all_points(&mut blinding_nonce_poly);
        
        // Is it degree t? 
        // let mut recon_shares = Vec::new();
        // for rep in 2*self.num_faults..self.num_nodes{
        //     recon_shares.push((rep,blinding_poly[rep].clone()));
        // }
        // assert_eq!(blinding_poly[0].clone(),self.large_field_sss.recover(recon_shares.as_slice()));
        // Drain the secret from nonce and blinding polynomials - Inefficient but clean
        // nonce_poly.drain(..1);
        // blinding_poly.drain(..1);
        // blinding_nonce_poly.drain(..1);
        // 3. Generate Commitments to shares and blinding polynomials
        let mut party_wise_shares = Vec::new();

        let mut poly_comm: Commitment = Vec::new();
        let mut blinding_poly_comm: Commitment = Vec::new();
        for party in 0..self.num_nodes{
            
            let mut party_shares = Vec::new();
            let mut appended_share: Vec<u8> = Vec::new();
            // Adding 1 to index because the first element is the secret
            for evaluation in polynomial_evaluations.iter(){
                party_shares.push(evaluation.get(party+1).unwrap().clone());
                appended_share.extend(evaluation.get(party+1).unwrap().to_signed_bytes_be());
            }
            party_wise_shares.push(party_shares);
            
            // Generate commitment for shares
            // Adding 1 to index because the first element is the secret
            
            appended_share.extend(nonce_poly.get(party+1).unwrap().to_signed_bytes_be());
            poly_comm.push(do_hash(appended_share.as_slice()));

            // Generate commitment for blinding polynomial
            // Adding 1 to index because the first element is the secret
            let mut appended_blinding_shares = Vec::new();
            appended_blinding_shares.extend(blinding_poly.get(party+1).unwrap().to_signed_bytes_be());
            appended_blinding_shares.extend(blinding_nonce_poly.get(party+1).unwrap().to_signed_bytes_be());
            blinding_poly_comm.push(do_hash(appended_blinding_shares.as_slice()));

        }
        
        // 4. Compute Succinct Commitment
        let mut succinct_vec_appended_shares = Vec::new();
        for comm in poly_comm.iter().zip(blinding_poly_comm.iter()){

            succinct_vec_appended_shares.extend(comm.0.clone());
            succinct_vec_appended_shares.extend(comm.1.clone());
        }

        let succinct_comm = do_hash(succinct_vec_appended_shares.as_slice());
        
        // 5. Compute distributed Zero-Knowledge Polynomial
        // Polynomial R(x) = B(x) - \sum_{i\in 1..L} d^i F_i(x)
        // Construct $t+1$ evaluations instead of coefficients
        blinding_poly.truncate(self.num_faults+1);
        let mut r_x = blinding_poly.clone();
        let comm_lf = BigInt::from_signed_bytes_be(&succinct_comm.clone().to_vec()) % &self.large_field_prime;
        let mut pow_comm_lf = comm_lf.clone();
        let mut share_contributions: Vec<BigInt> = Vec::new();
        for _ in 0..blinding_poly.len(){
            share_contributions.push(zero.clone());
        }
        for poly in polynomial_evaluations.into_iter(){
            
            //poly.truncate(self.num_faults+1);
            for index in 0..blinding_poly.len(){
                share_contributions[index] = (&share_contributions[index] + (&pow_comm_lf * &poly[index]) % &self.large_field_prime)% &self.large_field_prime;
                if share_contributions[index] < zero.clone(){
                    share_contributions[index] += &self.large_field_prime;
                }
            }
            pow_comm_lf = (&pow_comm_lf* &comm_lf) % &self.large_field_prime;
        }
        for index in 0..share_contributions.len(){
            r_x[index] = (&r_x[index] - &share_contributions[index])% &self.large_field_prime;
            if r_x[index] < BigInt::from(0){
                r_x[index] += &self.large_field_prime;
            }
        }
        //assert!(self.large_field_sss.verify_degree(&mut r_x));


        // Truncate polynomial to t+1 points
        let mut r_x: Vec<Vec<u8>> = r_x.into_iter().map(|x| x.to_signed_bytes_be()).collect();
        r_x.truncate(self.num_faults+1);


        // 6. Encrypt Shares and Broadcast commitments
        for (rep,shares) in (0..self.num_nodes).into_iter().zip(party_wise_shares.into_iter()){
            let secret_key = self.sec_key_map.get(&rep).clone().unwrap().clone();
            let enc_shares;
            if rep > self.num_faults-1{

                let shares_ser = shares.into_iter().map(|x| x.to_signed_bytes_be()).collect();
                let shares = Shares{
                    poly_shares: Some(shares_ser),
                    nonce_shares: Some((nonce_poly.get(rep+1).unwrap().to_signed_bytes_be().to_vec(),blinding_nonce_poly.get(rep+1).unwrap().to_signed_bytes_be().to_vec()))
                };

                let status = bincode::serialize(&shares);
                if status.is_err(){
                    log::error!("FATAL: Unable to serialize shares because {:?}, exiting...", status.err().unwrap());
                    return;
                }
                else{
                    let ser_msg = status.unwrap();
                    // Encrypt messages
                    let encrypted_msg = encrypt(secret_key.as_slice(), ser_msg);
                    enc_shares = encrypted_msg;
                }
            }
            else{
                enc_shares = Vec::new();
            }
            let prot_msg = ProtMsg::InitAB(
                enc_shares, 
                num_secrets,
                (poly_comm.clone(),blinding_poly_comm.clone()), 
                r_x.clone(), 
                self.myid, 
                instance_id
            );
            let wrapper_msg = WrapperMsg::new(prot_msg.clone(),self.myid,&secret_key);
            let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(rep, wrapper_msg).await;
            self.add_cancel_handler(cancel_handler);
        }
    }

    pub async fn process_acss_init(self: &mut Context, encrypted_shares: Vec<u8>, num_secrets: usize, comm: VSSCommitments, dzk_poly: Vec<Vec<u8>>, sender: Replica, instance_id: usize){
        // 1. If shares are None, derive shares from PRF
        let shares;
        let nonce_share;
        let blinding_nonce_share;
        let shares_comm = comm.0;
        let blinding_comm = comm.1;
        if encrypted_shares.len() > 0{
            // On receiving encrypted shares, decrypt them first
            let secret_key = self.sec_key_map.get(&sender).unwrap().clone();
            let dec_shares = decrypt(secret_key.as_slice(), encrypted_shares);

            // Then deserialize the received message
            let des_shares: Result<Shares, Box<bincode::ErrorKind>> = bincode::deserialize(dec_shares.as_slice());
            if des_shares.is_err(){
                log::error!("Unable to deserialize shares message, exiting ACSS instance {}",instance_id);
                return;
            }
            let all_shares = des_shares.unwrap();
            shares = all_shares.poly_shares.unwrap().into_iter().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
            let (nonce_share_vec, blinding_nonce_share_vec) = all_shares.nonce_shares.unwrap();

            nonce_share = BigInt::from_signed_bytes_be(nonce_share_vec.as_slice());
            blinding_nonce_share = BigInt::from_signed_bytes_be(blinding_nonce_share_vec.as_slice());
        }
        else{
            // Generate shares locally using PRF
            let mut secret_key = self.sec_key_map.get(&sender).clone().unwrap().clone();
            secret_key.extend(instance_id.to_be_bytes());

            shares = pseudorandom_lf(secret_key.as_slice(), num_secrets);

            secret_key.extend(instance_id.to_be_bytes());
            let nonces = pseudorandom_lf(secret_key.as_slice(), 3);

            nonce_share = nonces.get(0).unwrap().clone() % &self.large_field_prime;
            blinding_nonce_share = nonces.get(2).unwrap().clone()% &self.large_field_prime;
        }

        // 2. Match commitments
        let mut appended_shares = Vec::new();
        for share in shares.iter(){
            appended_shares.extend(share.to_signed_bytes_be());
        }
        appended_shares.extend(nonce_share.to_signed_bytes_be());

        let share_comm = do_hash(appended_shares.as_slice());
        if share_comm != shares_comm[self.myid]{
            log::error!("Commitments sent by dealer did not match for ACSS instance {}",instance_id);
            return ;
        }
        
        // 3. dZK polynomial check
        let mut succinct_vec_appended_shares = Vec::new();
        for comm in shares_comm.iter().zip(blinding_comm.iter()){

            succinct_vec_appended_shares.extend(comm.0.clone());
            succinct_vec_appended_shares.extend(comm.1.clone());
        }
        let succinct_comm = do_hash(succinct_vec_appended_shares.as_slice());
        let comm_lf = BigInt::from_signed_bytes_be(&succinct_comm.clone().to_vec()) % &self.large_field_prime;
        
        // Interpolate dZK polynomial
        let mut r_x: Vec<BigInt> = dzk_poly.into_iter().map(|x| BigInt::from_signed_bytes_be(x.as_slice())).collect();
        self.large_field_sss.fill_evaluation_at_all_points(&mut r_x);
        
        let mut dzk_eval = r_x.get(self.myid+1).unwrap().clone();
        // Powers of the succinct commitment d
        let mut iter_comm_lf = comm_lf.clone();
        let mut share_contribution = BigInt::from(0);
        for share in shares.clone().into_iter(){
            share_contribution  = (share_contribution + (&iter_comm_lf * BigInt::from(share)))% &self.large_field_prime;
            iter_comm_lf = (iter_comm_lf* &comm_lf)% &self.large_field_prime;
        }
        dzk_eval = (dzk_eval + share_contribution)%&self.large_field_prime;
        if dzk_eval < BigInt::from(0){
            dzk_eval += &self.large_field_prime;
        }
        // Check matching commitments
        let mut appended_blinding_shares = Vec::new();
        appended_blinding_shares.extend(dzk_eval.to_signed_bytes_be());
        appended_blinding_shares.extend(blinding_nonce_share.to_signed_bytes_be());

        let blinding_share_comm = do_hash(appended_blinding_shares.as_slice());
        if blinding_share_comm != blinding_comm[self.myid]{
            log::error!("Blinding polynomial shares do not match, aborting execution of acss {}",instance_id);
            return;
        }
        log::info!("Share verification successful!");
    }
}