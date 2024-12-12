use crypto::encrypt;
use crypto::hash::{do_hash, HASH_SIZE};
use network::Acknowledgement;
use network::plaintcp::CancelHandler;
use num_bigint_dig::RandBigInt;
use num_bigint_dig::{BigInt, Sign};
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore};
use types::WrapperMsg;

use crate::{Commitment, Shares, ProtMsg};
use crate::{context::Context, SmallField, LargeField};

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
    pub async fn init_acss(self: &mut Context, secrets: Vec<SmallField>, instance_id: usize){
        
        // 1. Shamir secret sharing

        let mut shares: Vec<Vec<SmallField>> = Vec::new();
        
        for _i in 0..self.num_nodes{
            shares.push(Vec::new());
        }
        
        let mut polynomial_evaluations = Vec::new();
        
        for secret in secrets.into_iter(){
            
            let mut poly = Vec::new();
            poly.push(secret);
            polynomial_evaluations.push(poly);
            
        }

        // 2. Sample blinding, nonce, and blinding nonce polynomials
        let mut nonce_poly = Vec::new();
        let mut blinding_poly = Vec::new();
        let mut blinding_nonce_poly = Vec::new();

        let zero = BigInt::from(0u64);
        let rand1 = rand::thread_rng().gen_bigint_range(&zero, &self.large_field_prime.clone());
        let rand2 = rand::thread_rng().gen_bigint_range(&zero, &self.large_field_prime.clone());
        let rand3 = rand::thread_rng().gen_bigint_range(&zero, &self.large_field_prime.clone());

        nonce_poly.push(rand1);
        blinding_poly.push(rand2);
        blinding_nonce_poly.push(rand3);
        

        for (rep,mut secret_key) in self.sec_key_map.clone().into_iter(){
            
            if rep > self.num_faults{
                break;
            }
            // Create a new seed from the secret key and the instance id
            secret_key.extend(instance_id.to_be_bytes());
            let rand_eval = self.pseudorandom_sf(secret_key.clone(), polynomial_evaluations.len());
            let mut index = 0;
            for share in rand_eval.into_iter(){
                polynomial_evaluations.get_mut(index).unwrap().push(share);
                index = index + 1;
            }

            // Sample blinding, nonce, and blinding nonce shares as well
            secret_key.extend(instance_id.to_be_bytes());
            let rand_eval: Vec<LargeField> = self.pseudorandom_lf(secret_key, 3);
            let mut index = 0;
            for elem in rand_eval.into_iter(){
                if index == 0{
                    nonce_poly.push(elem);
                }
                else if index == 1{
                    blinding_poly.push(elem);
                }
                else if index == 2{
                    blinding_nonce_poly.push(elem);
                }
                else{
                    break;
                }
                index = index+1;
            }
        }

        for poly in polynomial_evaluations.iter_mut(){
            self.small_field_sss.fill_evaluation_at_all_points(poly);
        }

        self.large_field_sss.fill_evaluation_at_all_points(&mut nonce_poly);
        self.large_field_sss.fill_evaluation_at_all_points(&mut blinding_poly);
        self.large_field_sss.fill_evaluation_at_all_points(&mut blinding_nonce_poly);
        
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
                party_shares.push(*evaluation.get(party).unwrap());
                appended_share.extend(evaluation.get(party+1).unwrap().to_be_bytes());
            }
            party_wise_shares.push(party_shares);
            
            // Generate commitment for shares
            // Adding 1 to index because the first element is the secret
            appended_share.extend(nonce_poly.get(party+1).unwrap().to_signed_bytes_be());
            poly_comm.push(do_hash(&appended_share));

            // Generate commitment for blinding polynomial
            // Adding 1 to index because the first element is the secret
            let mut appended_blinding_shares = Vec::new();
            appended_blinding_shares.extend(blinding_poly.get(party+1).unwrap().to_signed_bytes_be());
            appended_blinding_shares.extend(blinding_nonce_poly.get(party+1).unwrap().to_signed_bytes_be());
            blinding_poly_comm.push(do_hash(&appended_blinding_shares));

        }
        
        // 4. Compute Succinct Commitment
        let mut succinct_vec_appended_shares = Vec::new();
        for comm in poly_comm.iter().zip(blinding_poly_comm.iter()){

            succinct_vec_appended_shares.extend(comm.0.clone());
            succinct_vec_appended_shares.extend(comm.1.clone());
        }

        let succinct_comm = do_hash(&succinct_vec_appended_shares);
        
        // 5. Compute distributed Zero-Knowledge Polynomial
        // Polynomial R(x) = B(x) - \sum_{i\in 1..L} d^i F_i(x)
        // Construct $t+1$ evaluations instead of coefficients
        blinding_poly.truncate(self.num_faults+1);
        let mut r_x = blinding_poly;
        
        let comm_lf = BigInt::from_signed_bytes_be(&succinct_comm.clone().to_vec()) % &self.large_field_prime;
        let mut pow_comm_lf = comm_lf.clone();
        for mut poly in polynomial_evaluations{
            
            poly.truncate(self.num_faults+1);
            for index in 0..poly.len(){
                r_x[index] = (&r_x[index] - &pow_comm_lf * BigInt::from(poly[index])) % &self.large_field_prime;
            }

            pow_comm_lf = (&pow_comm_lf* &comm_lf) % &self.large_field_prime;
        }

        let r_x: Vec<Vec<u8>> = r_x.into_iter().map(|x| x.to_signed_bytes_be()).collect();
        // 6. Encrypt Shares and Broadcast commitments
        for ((rep,secret_key), shares) in self.sec_key_map.clone().into_iter().zip(party_wise_shares.into_iter()){
            let enc_shares;
            if rep > self.num_faults{

                let shares = Shares{
                    poly_shares: Some(shares),
                    nonce_shares: Some((nonce_poly.get(rep).unwrap().to_signed_bytes_be().to_vec(),blinding_nonce_poly.get(rep).unwrap().to_signed_bytes_be().to_vec()))
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
            let prot_msg = ProtMsg::Init(
                enc_shares, 
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

    pub fn pseudorandom_sf(&self, rng_seed: Vec<u8>, num: usize)->Vec<SmallField>{
        let mut rng = ChaCha20Rng::from_seed(do_hash(rng_seed.as_slice()));
        let mut all_nodes = Vec::new();
        for i in 0..self.num_nodes{
            all_nodes.push(i);
        }
        let mut random_numbers: Vec<SmallField> = Vec::new();
        for _i in 0..num{
            let rand_num = rng.next_u64();
            random_numbers.push(rand_num);
        }
        random_numbers
    }

    pub fn pseudorandom_lf(&self, rng_seed: Vec<u8>, num: usize)->Vec<LargeField>{
        let mut rng = ChaCha20Rng::from_seed(do_hash(rng_seed.as_slice()));
        let mut all_nodes = Vec::new();
        for i in 0..self.num_nodes{
            all_nodes.push(i);
        }
        let mut random_numbers: Vec<LargeField> = Vec::new();
        for _i in 0..num{
            let mut rnd_bytes = [0u8;HASH_SIZE];
            rng.fill_bytes(&mut rnd_bytes);
            let bigint_rand = BigInt::from_bytes_be(Sign::Plus, &rnd_bytes);
            random_numbers.push(bigint_rand);
        }
        random_numbers
    }
}