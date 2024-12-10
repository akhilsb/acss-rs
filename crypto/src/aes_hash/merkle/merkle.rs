extern crate alloc;

pub const HASH_SIZE:usize = 32;

use alloc::vec::Vec;
// use core::iter::FromIterator;
// use core::marker::PhantomData;
// use core::ops;

use crate::{aes_hash::HashState, hash::Hash};

use super::Proof;

/// Merkle Tree.
///
/// All leafs and nodes are stored in a linear array (vec).
///
/// A merkle tree is a tree in which every non-leaf node is the hash of its
/// children nodes. A diagram depicting how it works:
///
/// ```text
///         root = h1234 = h(h12 + h34)
///        /                           \
///  h12 = h(h1 + h2)            h34 = h(h3 + h4)
///   /            \              /            \
/// h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
/// ```
///
/// In memory layout:
///
/// ```text
///     [h1 h2 h3 h4 h12 h34 root]
/// ```
///
/// Merkle root is always the last element in the array.
///
/// The number of inputs is not always a power of two which results in a
/// balanced tree structure as above.  In that case, parent nodes with no
/// children are also zero and parent nodes with only a single left node
/// are calculated by concatenating the left node with itself before hashing.
/// Since this function uses nodes that are pointers to the hashes, empty nodes
/// will be nil.
///
/// TODO: Ord
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleTree {
    data: Vec<Hash>,
    leafs: usize,
    height: usize,
}

impl MerkleTree {
    /// Creates new merkle from a sequence of hashes.
    pub fn new(data: Vec<Hash>, hc: &HashState) -> MerkleTree {
        Self::from_iter(data,hc)
    }

    /// Creates new merkle tree from a list of hashable objects.
    pub fn from_data(data: Vec<Hash>, hc: &HashState) -> MerkleTree {
        Self::from_iter(data,hc)
    }

    pub fn build_trees(mut data: Vec<Vec<Hash>>,hc: &HashState) -> Vec<MerkleTree>{
        let mut width = data[0].len();
        let each_size = width.clone();
        let size = data.len();
        if size < 1{
            return Vec::new();
        }
        // build tree
        let mut i: usize = 0;
        let mut j: usize = width;
        while width > 1 {
            // if there is odd num of elements, fill in to the even
            if width & 1 == 1 {
                for k in 0..size{
                    let size_v = data[k].len();
                    let he = data[k][size_v - 1].clone();
                    data[k].push(he);
                }
                width += 1;
                j += 1;
            }

            // next shift
            while i < j {
                let mut one = Vec::new();
                let mut two = Vec::new();
                for k in 0..size{
                    one.push(data[k][i].clone());
                    two.push(data[k][i+1].clone());
                }
                // Batching for batched encryption
                let h = hc.hash_batch(one, two);
                for k in 0..size{
                    data[k].push(h[k]);
                }
                //self.data.push(h);
                i += 2;
            }
            width >>= 1;
            j += width;
        }
        let mut ret_vec = Vec::new();
        let leafs = each_size;
        let pow = next_pow2(leafs);
        let size = 2 * pow - 1;
        for data_ind in data.into_iter(){
            ret_vec.push(MerkleTree{
                data: data_ind,
                leafs: leafs,
                height: log2_pow2(size + 1)
            })
        }
        return ret_vec;
    }

    fn build(&mut self,hc:&HashState) {
        let mut width = self.leafs;

        // build tree
        let mut i: usize = 0;
        let mut j: usize = width;
        while width > 1 {
            // if there is odd num of elements, fill in to the even
            if width & 1 == 1 {
                let he = self.data[self.len() - 1].clone();
                self.data.push(he);
                width += 1;
                j += 1;
            }

            // next shift
            while i < j {
                let h = hc.hash_two(self.data[i].clone(), self.data[i + 1].clone());
                self.data.push(h);
                i += 2;
            }

            width >>= 1;
            j += width;
        }
    }

    /// Generate merkle tree inclusion proof for leaf `i`
    pub fn gen_proof(&self, i: usize) -> Proof {
        assert!(i < self.leafs); // i in [0 .. self.leafs)

        let mut lemma: Vec<Hash> = Vec::with_capacity(self.height + 1); // path + root
        let mut path: Vec<bool> = Vec::with_capacity(self.height - 1); // path - 1

        let mut base = 0;
        let mut j = i;

        // level 1 width
        let mut width = self.leafs;
        if width & 1 == 1 {
            width += 1;
        }

        lemma.push(self.data[j].clone());
        while base + 1 < self.len() {
            lemma.push(if j & 1 == 0 {
                // j is left
                self.data[base + j + 1].clone()
            } else {
                // j is right
                self.data[base + j - 1].clone()
            });
            path.push(j & 1 == 0);

            base += width;
            width >>= 1;
            if width & 1 == 1 {
                width += 1;
            }
            j >>= 1;
        }

        // root is final
        lemma.push(self.root());
        Proof::new(lemma, path)
    }

    /// Creates new merkle tree from an iterator over hashable objects.
    fn from_iter(into: Vec<Hash>,hc: &HashState) -> Self {
        let iter = into.into_iter();
        let mut data: Vec<Hash> = match iter.size_hint().1 {
            Some(e) => {
                let pow = next_pow2(e);
                let size = 2 * pow - 1;
                Vec::with_capacity(size)
            }
            None => Vec::new(),
        };

        // leafs
        for item in iter {
            data.push(item);
        }

        let leafs = data.len();
        let pow = next_pow2(leafs);
        let size = 2 * pow - 1;

        assert!(leafs > 1);

        let mut mt: MerkleTree = MerkleTree {
            data,
            leafs,
            height: log2_pow2(size + 1),
        };

        mt.build(hc);
        mt
    }

    /// Returns merkle root
    pub fn root(&self) -> Hash {
        self.data[self.data.len() - 1].clone()
    }

    /// Returns number of elements in the tree.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the vector contains no elements.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns height of the tree
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns original number of elements the tree was built upon.
    pub fn leafs(&self) -> usize {
        self.leafs
    }
}

/// `next_pow2` returns next highest power of two from a given number if
/// it is not already a power of two.
///
/// [](http://locklessinc.com/articles/next_pow2/)
/// [](https://stackoverflow.com/questions/466204/rounding-up-to-next-power-of-2/466242#466242)
pub fn next_pow2(mut n: usize) -> usize {
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    #[cfg(target_pointer_width = "64")]
    {
        n |= n >> 32;
    }
    n + 1
}

/// find power of 2 of a number which is power of 2
pub fn log2_pow2(n: usize) -> usize {
    n.trailing_zeros() as usize
}