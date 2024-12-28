use consensus::{LargeFieldSSS, DZKProof};
use crypto::{LargeField, aes_hash::{Proof, HashState, MerkleTree}, LargeFieldSer, hash::{Hash, do_hash}};
use ctrbc::CTRBCMsg;
use serde::{Serialize, Deserialize};
use types::Replica;


// List of coefficients for the row polynomials
pub struct RowPolynomialsBatch{
    pub coefficients: Vec<Vec<LargeField>>,
    pub blinding_evaluation: LargeField,
    pub nonce_coefficients: Vec<LargeField>,
    pub blinding_nonce_evaluation: LargeField,

    pub num_bv_polys: usize,
    pub proofs: Vec<Proof>,
    //pub dzk_proof: DZKProof,

    pub blinding_poly_proof: Proof
}

impl RowPolynomialsBatch{
    
    pub fn points(&self, large_field_shamir_ss: &LargeFieldSSS, eval_points: Vec<usize>) -> Vec<Vec<LargeField>>{
        let mut orig_polys = Vec::new();
        //let mut blinding_poly = Vec::new();

        for poly in self.coefficients.iter(){
            let mut orig_poly = Vec::new();
            for point in eval_points.clone().into_iter(){
                orig_poly.push(large_field_shamir_ss.mod_evaluate_at(poly.as_slice(), point));
            }
            orig_polys.push(orig_poly);
        }

        // for point in eval_points.into_iter(){
        //     blinding_poly.push(large_field_shamir_ss.mod_evaluate_at(self.blinding_evaluation.clone(), point));
        // }
        orig_polys
    }

    pub fn verify_commitments(&self, 
        hc: &HashState, 
        lf_sss: &LargeFieldSSS,
        eval_points: Vec<usize>, 
        root: Hash
    ) -> bool{
        let tot_points = eval_points.len().clone();

        let evaluations = self.points(lf_sss, eval_points.clone()); 
        let evaluations_ser: Vec<Vec<LargeFieldSer>> = evaluations.clone().into_iter().map(|el| {
            el.into_iter().map(|el2| el2.to_signed_bytes_be()).collect()
        }).collect();
        
        let mut appended_vec_vecs = Vec::new();
        for _ in 0..tot_points{
            appended_vec_vecs.push(Vec::new());
        }
        for evaluation_bv in evaluations_ser.into_iter(){
            for (rep, eval_p) in (0..tot_points).into_iter().zip(evaluation_bv.into_iter()){
                appended_vec_vecs[rep].extend(eval_p);
            }
        }

        let nonce_evaluations: Vec<LargeFieldSer> = eval_points.into_iter().map(|el| {
            let point =  lf_sss.mod_evaluate_at(&self.nonce_coefficients, el);
            return point.to_signed_bytes_be();
        }).collect();

        for (rep,nonce_eval) in (0..tot_points).into_iter().zip(nonce_evaluations.into_iter()){
            appended_vec_vecs[rep].extend(nonce_eval);
        }

        let commitments: Vec<Hash> = appended_vec_vecs.into_iter().map(|el| do_hash(el.as_slice())).collect();
        let mut vector_roots = Vec::new();
        for (proof,item) in self.proofs.iter().zip(commitments.into_iter()){
            vector_roots.push(proof.root());
            if !proof.validate(hc) && proof.item() != item{
                log::error!("Merkle proof verification failed because of mismatched proof MP Item: {:?} Generated Commitment{:?}", proof.item(), item);
                return false;
            }
        }

        let mut appended_vec = Vec::new();
        appended_vec.extend(self.blinding_evaluation.clone().to_signed_bytes_be());
        appended_vec.extend(self.blinding_nonce_evaluation.clone().to_signed_bytes_be());

        let blinding_commitment = do_hash(appended_vec.as_slice());
        if !self.blinding_poly_proof.validate(hc) || self.blinding_poly_proof.item() != blinding_commitment{
            log::error!("Merkle proof verification for blinding polynomial failed because of mismatched proof MP Item: {:?} Generated Commitment{:?}", self.blinding_poly_proof.item(), blinding_commitment);
            return false;
        }

        let master_root = MerkleTree::new(vector_roots, hc);
        let combined_root = hc.hash_two(master_root.root(), self.blinding_poly_proof.root());
        if combined_root != root{
            log::error!("Batch Merkle root verification failed because of mismatched proof MP Item: {:?} Generated Commitment{:?}", master_root.root(), self.blinding_poly_proof.root());
            return false;
        }
        true
    }

    pub fn verify_shares_with_dzk(&self, 
        dzk_poly: LargeField, 
        eval_points: Vec<LargeField>,
        lf_uv_sss: &LargeFieldSSS,
        hc: &HashState
    ) -> bool{
        // verify dzk proof
        let mut col_root = self.batch_root(&hc) % &lf_uv_sss.prime;
        
        if col_root < LargeField::from(0){
            col_root += &lf_uv_sss.prime;
        }

        let evaluations: Vec<Vec<LargeField>> = self.coefficients.iter().map(|poly| {
            return eval_points.clone().into_iter().map(|el|
                lf_uv_sss.mod_evaluate_at_lf(poly , el)).collect();
        }).collect();

        let mut evaluations_expanded= Vec::new();
        for evaluation_vec in evaluations.into_iter(){
            evaluations_expanded.extend(evaluation_vec);
        }

        // Folding not necessary for proof verification
        let mut agg_point = self.blinding_evaluation.clone();

        let mut root_mult = col_root.clone();
        for evaluation in evaluations_expanded{
            agg_point = (&agg_point + &root_mult*evaluation)%&lf_uv_sss.prime;
            root_mult = (&root_mult*&col_root)%&lf_uv_sss.prime;
        }
        if agg_point < LargeField::from(0){
            agg_point += &lf_uv_sss.prime;
        }
        dzk_poly == agg_point
    }

    fn batch_root(&self, hc: &HashState)-> LargeField{
        // TODO: Change this for when multiple batches exist
        let roots: Vec<Hash> = self.proofs.iter().map(|proof| proof.item()).collect();
        let mr = MerkleTree::new(roots,hc);
        let hash_two = hc.hash_two(mr.root() , self.blinding_poly_proof.root());

        LargeField::from_signed_bytes_be(hash_two.as_slice())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RowPolynomialsBatchSer{
    pub coefficients: Vec<Vec<LargeFieldSer>>,
    pub blinding_evaluation: LargeFieldSer,
    pub nonce_coefficients: Vec<LargeFieldSer>,
    pub blinding_nonce_evaluation: LargeFieldSer,

    pub num_bv_polys: usize,
    pub proofs: Vec<Proof>,
    //pub dzk_proof: DZKProof,

    pub blinding_poly_proof: Proof
}

impl RowPolynomialsBatchSer{
    pub fn from_deser(rows: RowPolynomialsBatch)-> RowPolynomialsBatchSer{
        let ser_coeffs: Vec<Vec<LargeFieldSer>> = rows.coefficients.iter().map(|coefficients| 
            coefficients.iter().map(|element| element.to_signed_bytes_be()).collect()
        ).collect();
        let blind_eval: LargeFieldSer = rows.blinding_evaluation.to_signed_bytes_be();
        let nonce_coeffs: Vec<LargeFieldSer> = rows.nonce_coefficients.iter().map(|el| el.to_signed_bytes_be()).collect();
        let blinding_nonce_eval: LargeFieldSer = rows.blinding_nonce_evaluation.to_signed_bytes_be();

        RowPolynomialsBatchSer { 
            coefficients: ser_coeffs, 
            blinding_evaluation: blind_eval, 
            nonce_coefficients: nonce_coeffs, 
            blinding_nonce_evaluation: blinding_nonce_eval,

            num_bv_polys: rows.num_bv_polys,
            proofs: rows.proofs,
            //dzk_proof: rows.dzk_proof.clone(),
            blinding_poly_proof: rows.blinding_poly_proof
        }
    }

    pub fn to_deser(&self) -> RowPolynomialsBatch{
        let deser_coeffs: Vec<Vec<LargeField>> = self.coefficients.iter().map(|coefficients| 
            coefficients.iter().map(|element| LargeField::from_signed_bytes_be(element)).collect()
        ).collect();
        let blind_eval: LargeField = LargeField::from_signed_bytes_be(self.blinding_evaluation.as_slice());
        let nonce_coeffs: Vec<LargeField> = self.nonce_coefficients.iter().map(|el| LargeField::from_signed_bytes_be(el)).collect();
        let blinding_nonce_eval: LargeField = LargeField::from_signed_bytes_be(self.blinding_nonce_evaluation.as_slice());

        RowPolynomialsBatch { 
            coefficients: deser_coeffs, 
            blinding_evaluation: blind_eval, 
            nonce_coefficients: nonce_coeffs, 
            blinding_nonce_evaluation: blinding_nonce_eval, 

            num_bv_polys: self.num_bv_polys,
            proofs: self.proofs.clone(),
            //dzk_proof: self.dzk_proof.clone(),

            blinding_poly_proof: self.blinding_poly_proof.clone()
        }
    }
}


pub struct PointsBV{
    pub evaluations: Vec<Vec<LargeField>>,
    pub nonce_evaluation: Vec<LargeField>,
    pub proof: Vec<Proof>,
}

pub struct PointsBVSer{
    pub evaluations: Vec<Vec<LargeFieldSer>>,
    pub nonce_evaluation: Vec<LargeFieldSer>,
    pub proofs: Vec<Proof>,
}

impl PointsBV{
    pub fn verify_points(&self, roots: Vec<Hash>, hc: &HashState)->bool{
        for (evaluations, (nonce,(proof, root))) in self.evaluations.iter().zip(self.nonce_evaluation.iter().zip(self.proof.iter().zip(roots.into_iter()))){
            let mut appended_vec = Vec::new();
            for eval in evaluations{
                appended_vec.extend(eval.to_signed_bytes_be());
            }
            appended_vec.extend(nonce.to_signed_bytes_be());
            let hash = do_hash(appended_vec.as_slice());
            if !proof.validate(hc) || proof.item() != hash || proof.root() != root{
                log::error!("Error verifying point on column");
                return false;
            }
        }
        true
    }

    pub fn to_ser(&self)-> PointsBVSer{
        let evaluations_ser: Vec<Vec<LargeFieldSer>> = self.evaluations.clone().into_iter().map(|el| {
            return el.into_iter().map(|deser| deser.to_signed_bytes_be()).collect();
        }).collect();
        let nonce_ser: Vec<LargeFieldSer> = self.nonce_evaluation.clone().into_iter().map(|el|{
            el.to_signed_bytes_be()
        }).collect();

        PointsBVSer{
            evaluations: evaluations_ser,
            nonce_evaluation: nonce_ser,
            proofs: self.proof.clone()
        }
    }

    pub fn from_ser(pt: PointsBVSer)-> PointsBV{
        let evaluations: Vec<Vec<LargeField>> = pt.evaluations.into_iter().map(|el| {
            return el.into_iter().map(|ser| LargeField::from_signed_bytes_be(ser.as_slice())).collect();
        }).collect();
        let eval_nonce = pt.nonce_evaluation.into_iter().map(|el| LargeField::from_signed_bytes_be(el.as_slice())).collect();
        PointsBV { evaluations: evaluations, nonce_evaluation: eval_nonce, proof: pt.proofs }
    }
}

pub struct ColPolynomialsBatch{
    pub coefficients: Vec<Vec<LargeField>>,
    pub blinding_coefficients: Vec<LargeField>,
    pub nonce_coefficients: Vec<LargeField>,
    pub blinding_nonce_coefficients: Vec<LargeField>,

    pub root_proof: Proof
}

impl ColPolynomialsBatch{
    pub fn points(&self, large_field_shamir_ss: LargeFieldSSS, eval_points: Vec<usize>) -> (Vec<Vec<LargeField>>, Vec<LargeField>){
        let mut orig_polys = Vec::new();
        let mut blinding_poly = Vec::new();

        for poly in self.coefficients.iter(){
            let mut orig_poly = Vec::new();
            for point in eval_points.clone().into_iter(){
                orig_poly.push(large_field_shamir_ss.mod_evaluate_at(poly.as_slice(), point));
            }
            orig_polys.push(orig_poly);
        }

        for point in eval_points.into_iter(){
            blinding_poly.push(large_field_shamir_ss.mod_evaluate_at(self.blinding_coefficients.as_slice(), point));
        }
        (orig_polys,blinding_poly)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ColPolynomialsBatchSer{
    pub coefficients: Vec<Vec<LargeFieldSer>>,
    pub blinding_coefficients: Vec<LargeFieldSer>,
    pub nonce_coefficients: Vec<LargeFieldSer>,
    pub blinding_nonce_coefficients: Vec<LargeFieldSer>,

    pub root_proof: Proof
}

impl ColPolynomialsBatchSer{
    pub fn from_deser(rows: &ColPolynomialsBatch)-> ColPolynomialsBatchSer{
        let ser_coeffs: Vec<Vec<LargeFieldSer>> = rows.coefficients.iter().map(|coefficients| 
            coefficients.iter().map(|element| element.to_signed_bytes_be()).collect()
        ).collect();
        let blind_coeffs: Vec<LargeFieldSer> = rows.blinding_coefficients.iter().map(|element| element.to_signed_bytes_be()).collect();
        let nonce_coeffs: Vec<LargeFieldSer> = rows.nonce_coefficients.iter().map(|el| el.to_signed_bytes_be()).collect();
        let blinding_nonce_coeffs: Vec<LargeFieldSer> = rows.blinding_nonce_coefficients.iter().map(|el| el.to_signed_bytes_be()).collect();

        ColPolynomialsBatchSer { 
            coefficients: ser_coeffs, 
            blinding_coefficients: blind_coeffs, 
            nonce_coefficients: nonce_coeffs, 
            blinding_nonce_coefficients: blinding_nonce_coeffs,

            root_proof: rows.root_proof.clone()
        }
    }

    pub fn to_deser(&self) -> ColPolynomialsBatch{
        let deser_coeffs: Vec<Vec<LargeField>> = self.coefficients.iter().map(|coefficients| 
            coefficients.iter().map(|element| LargeField::from_signed_bytes_be(element)).collect()
        ).collect();
        let blind_coeffs: Vec<LargeField> = self.blinding_coefficients.iter().map(|element| LargeField::from_signed_bytes_be(element)).collect();
        let nonce_coeffs: Vec<LargeField> = self.nonce_coefficients.iter().map(|el| LargeField::from_signed_bytes_be(el)).collect();
        let blinding_nonce_coeffs: Vec<LargeField> = self.blinding_nonce_coefficients.iter().map(|el| LargeField::from_signed_bytes_be(el)).collect();

        ColPolynomialsBatch { 
            coefficients: deser_coeffs, 
            blinding_coefficients: blind_coeffs, 
            nonce_coefficients: nonce_coeffs, 
            blinding_nonce_coefficients: blinding_nonce_coeffs, 

            root_proof: self.root_proof.clone()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Shares{
    pub row_polys: Vec<RowPolynomialsBatchSer>,
    pub col_polys: Vec<ColPolynomialsBatchSer>,
    pub dzk_iters: Vec<DZKProof>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Commitment{
    pub roots: Vec<Vec<Hash>>,
    pub blinding_roots: Vec<Vec<Hash>>,
    pub dzk_poly: Vec<Vec<LargeFieldSer>>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg{
    Init(
        Vec<u8>, // Encrypted shares
        Commitment, // dZK polynomial
        Replica, // Dealer
        usize // ACSS Instance ID (For PRF and share generation)
    ),
    Echo(
        CTRBCMsg,
        Vec<u8>, // Encrypted shares on row and column
        usize // ACSS Instance ID 
    ),
    Ready(
        CTRBCMsg,
        Vec<u8>, // Encrypted shares on row and column
        usize // ACSS Instance ID
    )
}