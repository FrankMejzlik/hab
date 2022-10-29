use sha3::Digest;
use std::fmt::Debug;
use std::fmt::{Display, Formatter, Result};
// ---
use log::debug;
// ---

#[derive(Debug)]
pub struct MerkleTree<const BLOCK_SIZE: usize> {
    data: Vec<[u8; BLOCK_SIZE]>,
    t: usize,
    h: usize,
    size: usize,
}

impl<const BLOCK_SIZE: usize> MerkleTree<BLOCK_SIZE> {
    pub fn construct<Hash: Digest>(leaves: Vec<[u8; BLOCK_SIZE]>) -> Self {
        let t = leaves.len();
        let h = (t as f32).log2();

        // Power of 2 check
        assert_eq!(
            h.ceil() as usize,
            h as usize,
            "Number of leaves is not power of 2!"
        );
        let h = (h as usize) + 1;

        // Overflow check
        assert!(h <= std::u32::MAX as usize);

        let size = 2_usize.pow(h as u32) - 1;
        let mut data = vec![[0u8; BLOCK_SIZE]; size];

        let base = 2_usize.pow((h - 1) as u32) - 1;

        for (i, d) in leaves.into_iter().enumerate() {
            data[base + i] = d;
        }

        let mut t = MerkleTree { data, t, h, size };

        for l in (0_u32..(h - 1) as u32).rev() {
            let num_idxs = 2_usize.pow(l as u32);
            let base_prev = 2_usize.pow((l + 1) as u32) - 1;
            let base = 2_usize.pow(l as u32) - 1;
            for i in 0_usize..num_idxs {
                debug!("base: {}, i: {}", base, i);

                let mut concat = t.data[base_prev + 2 * i].to_vec();
                concat.append(&mut t.data[base_prev + 2 * i + 1].to_vec());

                let r = Hash::digest(concat);

                t.data[base + i].copy_from_slice(&r[..BLOCK_SIZE]);
            }
        }

        t
    }

    pub fn get(&self, layer: u32, idx: usize) -> &[u8; BLOCK_SIZE] {
        debug!("l: {}, idx: {}", layer, idx);
        let i = (2_usize.pow(layer) - 1) + idx;
        &self.data[i]
    }
}

impl<const BLOCK_SIZE: usize> Display for MerkleTree<BLOCK_SIZE> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        writeln!(
            f,
            r#"
--- MerkleTree ---
t:    {}
h:    {}
size: {}
"#,
            self.t, self.h, self.size
        )?;

        for l in 0_u32..self.h as u32 {
            let num_idxs = 2_usize.pow(l as u32);
            for i in 0_usize..num_idxs {
                for (i, b) in self.get(l, i).into_iter().enumerate() {
                    if i >= 2 {
                        break;
                    }
                    write!(f, "{:0>2x?}", b)?;
                }
                write!(f, "..\t")?;
            }
            writeln!(f)?;
        }
        writeln!(f)
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;
    // ---
    use sha3::{Digest, Sha3_256};
    use std::println as debug;

    // ---
    use super::*;
    use crate::utils;

    #[test]
    fn test_construct() {
        const T: usize = 4;
        const BLOCK_SIZE: usize = 32;

        //
        // Arrange
        //

        // Leaves in vectors
        let leaf_numbers = utils::gen_byte_blocks_from::<BLOCK_SIZE>(&(0_u64..T as u64).collect());
        let leaves: Vec<[u8; BLOCK_SIZE]> = leaf_numbers
            .into_iter()
            .map(|i| Sha3_256::digest(i).try_into().unwrap())
            .collect();

        // Depth of the tree
        let h = ((leaves.len() as f32).log2()) as usize + 1;

        println!("Layer {}:", h - 1);
        for l in leaves.iter() {
            debug!("\t=> {}", utils::to_hex(l));
        }
        let mut exp_tree: Vec<Vec<[u8; BLOCK_SIZE]>> = vec![leaves.clone()];
        // For each layer, h-2 -> 0
        for i in (0_usize..h - 1).rev() {
            println!("Layer {}:", i);
            let mut new_layer: Vec<[u8; BLOCK_SIZE]> = vec![];

            let prev_idx = exp_tree.len() - 1;
            let prev_layer = &exp_tree[prev_idx];

            // Concat & hash
            for j in 0_usize..(prev_layer.len() / 2) {
                debug!("\tL:{}", utils::to_hex(&prev_layer[2 * j]));
                debug!("\tR:{}", utils::to_hex(&prev_layer[2 * j + 1]));
                let mut concatenated = prev_layer[2 * j].to_vec();
                concatenated.append(&mut prev_layer[2 * j + 1].to_vec());

                // Cut the first BLOCK_SIZE bytes
                let mut arr = [0_u8; BLOCK_SIZE];
                arr.copy_from_slice(&(Sha3_256::digest(concatenated)[..BLOCK_SIZE]));
                debug!("\t=> {}", utils::to_hex(&arr));
                new_layer.push(arr);
            }
            exp_tree.push(new_layer)
        }
        exp_tree.reverse();

        //
        // Act
        //

        // Build the tree
        let act_tree = MerkleTree::construct::<Sha3_256>(leaves);

        //
        // Assert
        //
        for (l, layer) in exp_tree.into_iter().enumerate() {
            for (i, exp_val) in layer.into_iter().enumerate() {
                let idx = (2_usize.pow(l as u32) - 1) + i;
                assert_eq!(
                    act_tree.data[idx], exp_val,
                    "The tree node value does not match!"
                );
            }
        }
    }

    #[test]
    fn test_construct_large() {
        const T: usize = 2048;
        const BLOCK_SIZE: usize = 32;

        let leaf_numbers = utils::gen_byte_blocks_from::<BLOCK_SIZE>(&(0_u64..T as u64).collect());
        let leaves: Vec<[u8; BLOCK_SIZE]> = leaf_numbers
            .into_iter()
            .map(|i| Sha3_256::digest(i).try_into().unwrap())
            .collect();

        // Build the tree
        let act_tree = MerkleTree::construct::<Sha3_256>(leaves);

        assert_eq!(
            utils::to_hex(&act_tree.data[0]),
            "c9f43b64630ddced98a3a9b2054b0c0d5d0c27f160ae84bdd23d6c1cf6ca6c81"
        )
    }
}
