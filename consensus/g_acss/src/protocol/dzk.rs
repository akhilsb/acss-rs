use consensus::LargeField;

use crate::Context;

impl Context{
    pub fn gen_dzk_proof_polynomial(
        shares: &Vec<Vec<Vec<LargeField>>>,
        blinding_poly: &Vec<Vec<LargeField>>,
        fiat_shamir_root_comm_fe: LargeField
    )-> Vec<Vec<LargeField>>{
        let mut b_poly = blinding_poly.clone();
        let mut root_comm_fe = fiat_shamir_root_comm_fe.clone();
        for bv_poly in shares{
            for (i, poly) in bv_poly.iter().enumerate(){
                for (j, eval) in poly.iter().enumerate(){
                    b_poly[i][j] += root_comm_fe* eval;
                }
            }
            root_comm_fe = root_comm_fe * fiat_shamir_root_comm_fe;
        }
        b_poly
    }
}