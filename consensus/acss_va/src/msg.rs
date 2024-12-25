use consensus::{LargeFieldSSS, DZKProof};
use crypto::{LargeField, aes_hash::{Proof}, LargeFieldSer, hash::Hash};
use ctrbc::CTRBCMsg;
use serde::{Serialize, Deserialize};
use types::Replica;


// List of coefficients for the row polynomials
pub struct RowPolynomialsBatch{
    pub coefficients: Vec<Vec<LargeField>>,
    pub blinding_evaluation: LargeField,
    pub nonce_coefficients: Vec<LargeField>,
    pub blinding_nonce_evaluation: LargeField,

    pub proofs: Vec<Proof>,
    pub dzk_proof: DZKProof,
    pub root_proofs: Vec<Proof>,

    pub blinding_poly_proof: Proof
}

impl RowPolynomialsBatch{
    
    pub fn points(&self, large_field_shamir_ss: LargeFieldSSS, eval_points: Vec<usize>) -> Vec<Vec<LargeField>>{
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

    // pub fn verify_proofs_with_roots(&self, hc: &HashState, roots: Vec<Hash>) -> bool{
    //     let mut commitments_orig = Vec::new();
    //     let mut commitments_blinding = Vec::new();

    //     for evaluation in self.evaluations.iter(){
            
    //         if !evaluation.0.2.validate(hc) || !evaluation.1.2.validate(hc){
    //             return false;
    //         }

    //         let mut appended_vec = Vec::new();
    //         appended_vec.extend(evaluation.0.0.clone());
    //         appended_vec.extend(evaluation.0.1.clone());

    //         commitments_orig.push(do_hash(appended_vec.as_slice()));

    //         let mut appended_vec = Vec::new();
    //         appended_vec.extend(evaluation.1.0.clone());
    //         appended_vec.extend(evaluation.1.1.clone());

    //         commitments_blinding.push(do_hash(appended_vec.as_slice()));
    //     }

    //     for 
    //     true
    // }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RowPolynomialsBatchSer{
    pub coefficients: Vec<Vec<LargeFieldSer>>,
    pub blinding_evaluation: LargeFieldSer,
    pub nonce_coefficients: Vec<LargeFieldSer>,
    pub blinding_nonce_evaluation: LargeFieldSer,

    pub proofs: Vec<Proof>,
    pub dzk_proof: DZKProof,
    pub root_proofs: Vec<Proof>,

    pub blinding_poly_proof: Proof
}

impl RowPolynomialsBatchSer{
    pub fn from_deser(rows: &RowPolynomialsBatch)-> RowPolynomialsBatchSer{
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

            proofs: rows.proofs.clone(),
            dzk_proof: rows.dzk_proof.clone(),
            root_proofs: rows.root_proofs.clone(),

            blinding_poly_proof: rows.blinding_poly_proof.clone()
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

            proofs: self.proofs.clone(),
            dzk_proof: self.dzk_proof.clone(),
            root_proofs: self.root_proofs.clone(),

            blinding_poly_proof: self.blinding_poly_proof.clone()
        }
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
    pub roots: Vec<Hash>,
    pub blinding_roots: Vec<Hash>,
    pub dzk_roots: Vec<Vec<Vec<Hash>>>,
    pub dzk_polys: Vec<Vec<Vec<LargeFieldSer>>>
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