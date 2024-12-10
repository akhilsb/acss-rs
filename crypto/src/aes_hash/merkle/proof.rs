extern crate alloc;

use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use crate::{aes_hash::HashState, hash::Hash};

/// Merkle tree inclusion proof for data element, for which item = Leaf(Hash(Data Item)).
///
/// Lemma layout:
///
/// ```text
/// [ item h1x h2y h3z ... root ]
/// ```
///
/// Proof validation is positioned hash against lemma path to match root hash.
#[derive(Debug, Clone, Eq, PartialEq,Serialize,Deserialize)]
pub struct Proof {
    lemma: Vec<Hash>,
    path: Vec<bool>,
}

impl Proof {
    /// Creates new MT inclusion proof
    pub fn new(hash: Vec<Hash>, path: Vec<bool>) -> Proof {
        //assert!(hash.len() > 2);
        //assert_eq!(hash.len() - 2, path.len());
        Proof { lemma: hash, path }
    }

    /// Return proof target leaf
    pub fn item(&self) -> Hash {
        self.lemma.first().unwrap().clone()
    }

    /// Return tree root
    pub fn root(&self) -> Hash {
        self.lemma.last().unwrap().clone()
    }

    /// Verifies MT inclusion proof
    pub fn validate(&self,hc: &HashState) -> bool {
        let size = self.lemma.len();
        if size < 2 {
            return false;
        }

        let mut h = self.item();
        //let mut a = A::default();

        for i in 1..size - 1 {
            //a.reset();
            h = if self.path[i - 1] {
                hc.hash_two(h, self.lemma[i].clone())
                //a.node(h, self.lemma[i].clone())
            } else {
                hc.hash_two(self.lemma[i].clone(), h)
                //a.node(self.lemma[i].clone(), h)
            };
        }

        h == self.root()
    }

    pub fn validate_batch(pfs:&Vec<Proof>, hc: &HashState) -> bool{
        let mut init_hash_vec:Vec<Hash> = Vec::new();
        for p in pfs{
            init_hash_vec.push(p.item());
        }
        let size = init_hash_vec.len();
        let size_each = pfs[0].lemma.len();
        if size_each < 2 {
            return false;
        }
        for i in 1..size_each - 1 {
            //a.reset();
            let mut one = Vec::new();
            let mut two = Vec::new();
            let mut ind = 0;
            for pf in pfs{
                if pf.path[i-1]{
                    one.push(init_hash_vec[ind]);
                    two.push(pf.lemma[i].clone());
                }
                else {
                    one.push(pf.lemma[i].clone());
                    two.push(init_hash_vec[ind]);
                }
                ind +=1;
            }
            init_hash_vec = hc.hash_batch(one, two);
        }
        for i in 0..size{
            if init_hash_vec[i] != pfs[i].root(){
                return false;
            }
        }
        return true;
    }

    /// Returns the path of this proof.
    pub fn path(&self) -> &[bool] {
        &self.path
    }

    /// Returns the lemma of this proof.
    pub fn lemma(&self) -> &[Hash] {
        &self.lemma
    }
}