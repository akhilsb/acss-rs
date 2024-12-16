use crypto::SmallField;
/**
 * Cloned from https://github.com/bitrocks/verifiable-secret-sharing
 * Author: bitrocks: https://github.com/bitrocks
 */

 use num_traits::{One, Zero};
 use rand::{self, Rng};
/// The `ShamirSecretSharing` stores threshold, share_amount and the prime of finite field.
  #[derive(Clone, Debug)]
  pub struct SmallFieldSSS {
     /// the threshold of shares to recover the secret.
     pub threshold: usize,
      /// the total number of shares to generate from the secret.
     pub share_amount: usize,
      /// the characteristic of finite field.
     pub prime: SmallField,
     /// Lagrange coefficients for points 1 through f
     pub lag_coeffs: Vec<Vec<SmallField>> 
  }
  
  // 64-bit variant of shamir SS mainly because of efficiency
  impl SmallFieldSSS {
 
     pub fn new(threshold: usize, share_amount: usize, prime: SmallField)-> SmallFieldSSS{
 
         let lag_coeffs = Self::lagrange_coefficients(prime, threshold, share_amount);
         SmallFieldSSS { 
             threshold: threshold, 
             share_amount: share_amount, 
             prime: prime, 
             lag_coeffs: lag_coeffs 
         }
     }
 
     pub fn fill_evaluation_at_all_points(&self, values: &mut Vec<SmallField>){
         let mut all_values = Vec::new();
         for coefficients in self.lag_coeffs.iter(){
             let mut sum: SmallField = 0;
             for (coefficient,point) in coefficients.into_iter().zip(values.clone().into_iter()){
                 sum = (sum + (coefficient*point)%self.prime)%self.prime;
             }
             all_values.push(sum);
         }
         values.extend(all_values);
     }

     pub fn verify_degree(&self, values: &mut Vec<SmallField>) -> bool{
        let mut shares_interp = Vec::new();
        
        for rep in self.share_amount - self.threshold .. self.share_amount{
            shares_interp.push((rep+1,values[rep+1].clone()));
        }
        
        let secret = self.recover(&shares_interp);
        println!("Degree verification : {:?} {:?}",secret,values[0].clone());
        secret == values[0].clone()%&self.prime
    }

     /// Split a secret according to the config.
     pub fn split(&self, secret: SmallField) -> Vec<(usize, SmallField)> {
         assert!(self.threshold < self.share_amount);
         let polynomial = self.sample_polynomial(secret);
         // println!("polynomial: {:?}", polynomial);
         self.evaluate_polynomial(polynomial)
     }
  
      fn sample_polynomial(&self, secret: SmallField) -> Vec<SmallField> {
          let mut coefficients: Vec<SmallField> = vec![secret];
          let mut rng = rand::thread_rng();
          let low = SmallField::from(0u32);
          let high = &self.prime - SmallField::from(1u32);
          let random_coefficients: Vec<SmallField> = (0..(self.threshold - 1))
              .map(|_| rng.gen_range(&low, &high))
              .collect();
          coefficients.extend(random_coefficients);
          coefficients
      }
  
      fn evaluate_polynomial(&self, polynomial: Vec<SmallField>) -> Vec<(usize, SmallField)> {
          (1..=self.share_amount)
              .map(|x| (x, self.mod_evaluate_at(&polynomial, x)))
              .collect()
      }
  
      fn mod_evaluate_at(&self, polynomial: &[SmallField], x: usize) -> SmallField {
          let x_sf = x as SmallField;
          polynomial.iter().rev().fold(Zero::zero(), |sum, item| {
              (&x_sf * sum + item) % &self.prime
          })
      }
  
      /// Recover the secret by the shares.
      pub fn recover(&self, shares: &[(usize, SmallField)]) -> SmallField {
          assert!(shares.len() == self.threshold, "wrong shares number");
          let (xs, ys): (Vec<usize>, Vec<SmallField>) = shares.iter().cloned().unzip();
          let result = self.lagrange_interpolation(Zero::zero(), xs, ys);
          if result < Zero::zero() {
              result + &self.prime
          } else {
              result
          }
      }
  
      fn lagrange_interpolation(&self, x: SmallField, xs: Vec<usize>, ys: Vec<SmallField>) -> SmallField {
          let len = xs.len();
          // println!("x: {}, xs: {:?}, ys: {:?}", x, xs, ys);
          let x_sf: Vec<SmallField> = xs.iter().map(|x| *x as SmallField).collect();
          // println!("sx_SmallField: {:?}", xs_SmallField);
          (0..len).fold(Zero::zero(), |sum, item| {
              let numerator = (0..len).fold(One::one(), |product: SmallField, i| {
                  if i == item {
                      product
                  } else {
                      product * (&x + &self.prime - &x_sf[i]) % &self.prime
                  }
              });
              let denominator = (0..len).fold(One::one(), |product: SmallField, i| {
                  if i == item {
                      product
                  } else {
                      product * (&x_sf[item] + &self.prime - &x_sf[i]) % &self.prime
                  }
              });
              // println!(
              // "numerator: {}, donominator: {}, y: {}",
              // numerator, denominator, &ys[item]
              // );
              (sum + (((numerator * Self::mod_reverse(self.prime, denominator))%self.prime) * ys[item])% self.prime) % &self.prime
              //(sum + (numerator * Self::mod_reverse(self.prime, denominator))* ys[item]) % &self.prime
              //(sum + numerator * Self::mod_reverse(self.prime, denominator) * ys[item]) % self.prime
          })
      }
  
      fn mod_reverse(prime: SmallField, num: SmallField) -> SmallField {
          let num1 = if num < Zero::zero() {
              num + &prime
          } else {
              num
          };
          let (_gcd, _, inv) = Self::extend_euclid_algo(prime, num1);
          // println!("inv:{}", inv);
          inv
      }
  
      /**
       * https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
       *
       * a*s + b*t = gcd(a,b) a > b
       * r_0 = a*s_0 + b*t_0    s_0 = 1    t_0 = 0
       * r_1 = a*s_1 + b*t_1    s_1 = 0    t_1 = 1
       * r_2 = r_0 - r_1*q_1
       *     = a(s_0 - s_1*q_1) + b(t_0 - t_1*q_1)   s_2 = s_0 - s_1*q_1     t_2 = t_0 - t_1*q_1
       * ...
       * stop when r_k = 0
       */
     fn extend_euclid_algo(prime: SmallField, num: SmallField) -> (SmallField, SmallField, SmallField) {
         let (mut r, mut next_r, mut s, mut next_s, mut t, mut next_t) = (
             prime.clone() as i64,
             num.clone() as i64,
             1i64,
             0i64,
             0i64,
             1i64,
         );
         let mut quotient;
         let mut tmp;
         while next_r > Zero::zero() {
             quotient = r.clone() / next_r.clone();
             tmp = next_r.clone();
             next_r = r.clone() - next_r.clone() * quotient.clone();
             r = tmp.clone();
             tmp = next_s.clone();
             next_s = s - next_s.clone() * quotient.clone();
             s = tmp;
             tmp = next_t.clone();
             next_t = t - next_t * quotient;
             t = tmp;
         }
         // println!(
         // "{} * {} + {} * {} = {} mod {}",
         // num, t, &self.prime, s, r, &self.prime
         // );
         let r_ret : SmallField;
         let s_ret : SmallField;
         let t_ret : SmallField;
         if r < 0{
            // Prevent overflow of i64
            r_ret = (r+(prime as i64)) as u64;
         }
         else{
            r_ret = r as u64;
         }
         if s < 0{
            // Prevent overflow of i64
            s_ret = (s+(prime as i64)) as u64;
         }
         else{
            s_ret = s as u64;
         }
         if t < 0{
            // Prevent overflow of i64
            t_ret = (t+(prime as i64)) as u64;
         }
         else{
            t_ret = t as u64;
         }
         (r_ret, s_ret, t_ret)
     }
 
     fn lagrange_coefficients(prime: SmallField, threshold: usize, tot_shares: usize)->Vec<Vec<SmallField>>{
         // Construct denominators first
         let mut denominators = Vec::new();
         for i in 0 as SmallField .. threshold as SmallField{
             let mut denominator_prod: SmallField =1;
             for j in 0 as SmallField..threshold as SmallField{
                 if j != i{
                     denominator_prod = denominator_prod * (i + prime - j) % prime;
                 }
             }
             denominators.push(Self::mod_reverse(prime, denominator_prod));
         }
         let mut numerators = Vec::new();
         for i in ((threshold) as SmallField)..((tot_shares+1) as SmallField){
 
             let mut num_prod:SmallField = 1;
             for j in 0 as SmallField .. threshold as SmallField{
                 num_prod = num_prod * (i + prime - j) % prime;
             }
             let mut num_vec = Vec::new();
             for j in 0 as SmallField .. threshold as SmallField{
                 num_vec.push((num_prod * Self::mod_reverse(prime, i-j))%prime);
             }
 
             numerators.push(num_vec);
         }
         let mut quotients = Vec::new();
         for numerator_poly in numerators.into_iter(){
             let mut poly_quo = Vec::new();
             for (n,d) in numerator_poly.into_iter().zip(denominators.clone().into_iter()){
                 poly_quo.push((n*d)%prime);
             }
             quotients.push(poly_quo);
         }
         quotients
     }
 }