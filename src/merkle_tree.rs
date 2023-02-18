//!
//! Implementation of a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) used for hash-based signatures.
//!
use sha3::Digest;
use std::fmt::Debug;
use std::fmt::{Display, Formatter, Result};
// ---
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
// ---

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerkleTree<const BLOCK_SIZE: usize> {
    data: Vec<Vec<u8>>,
    t: usize,
    h: usize,
    size: usize,
}

impl<const BLOCK_SIZE: usize> MerkleTree<BLOCK_SIZE> {
    pub fn new<Hash: Digest>(leaves: Vec<Vec<u8>>) -> Self {
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
        let mut data = vec![vec![0u8; BLOCK_SIZE]; size];

        let base = 2_usize.pow((h - 1) as u32) - 1;

        // Hash the SK for the tree leaves
        for (i, d) in leaves.into_iter().enumerate() {
            let hash = Hash::digest(d);
            data[base + i].copy_from_slice(&hash[..BLOCK_SIZE])
        }

        let mut t = MerkleTree { data, t, h, size };

        for l in (0_u32..(h - 1) as u32).rev() {
            let num_idxs = 2_usize.pow(l);
            let base_prev = 2_usize.pow(l + 1) - 1;
            let base = 2_usize.pow(l) - 1;
            for i in 0_usize..num_idxs {
                let mut hasher = Hash::new();
                hasher.update(t.data[base_prev + 2 * i].clone());
                hasher.update(t.data[base_prev + 2 * i + 1].clone());
                let r = hasher.finalize();

                t.data[base + i].copy_from_slice(&r[..BLOCK_SIZE]);
            }
        }

        t
    }

    pub fn get(&self, layer: u32, idx: usize) -> &[u8; BLOCK_SIZE] {
        let i = (2_usize.pow(layer) - 1) + idx;
        self.data[i]
            .as_slice()
            .try_into()
            .expect("The size should be `BLOCK_SIZE`!")
    }

    pub fn root(&self) -> &[u8; BLOCK_SIZE] {
        self.get(0, 0)
    }

    pub fn get_auth_path(&self, leaf_idx: usize) -> Vec<[u8; BLOCK_SIZE]> {
        if leaf_idx >= self.t {
            panic!("Leaf index out of range!");
        }

        let mut res = vec![];
        let mut i = leaf_idx;
        for h in (1..self.h).rev() {
            // Take the sibling node
            // even -> take +1
            // odd -> take -1
            let diff = -(((i % 2) * 2) as i32 - 1);
            i = (i as i32 + diff) as usize;

            // debug!("h: {}; i: {}", h, i);
            res.push(*self.get(h.try_into().unwrap(), i));

            i /= 2;
        }
        res
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
            let num_idxs = 2_usize.pow(l);
            for i in 0_usize..num_idxs {
                for (i, b) in self.get(l, i).iter().enumerate() {
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
    fn test_merkle_tree_get_auth_path_at_least_two_layers() {
        //
        // Assess
        //
        const T: usize = 8;
        const BLOCK_SIZE: usize = 32;
        let depth = ((T as f32).log2() as usize) + 1;

        let leaf_numbers =
            utils::gen_byte_blocks_from::<BLOCK_SIZE>(&(0_u64..T as u64).collect::<Vec<u64>>());

        //
        // Act
        //
        let tree = MerkleTree::new::<Sha3_256>(leaf_numbers);

        let ap_0: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(0);
        let ap_1: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(1);
        let ap_2: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(2);
        let ap_3: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(3);
        let ap_4: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(4);
        let ap_5: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(5);
        let ap_6: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(6);
        let ap_7: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(7);

        let total_ap_len = ap_0.len()
            + ap_1.len()
            + ap_2.len()
            + ap_3.len()
            + ap_4.len()
            + ap_5.len()
            + ap_6.len()
            + ap_7.len();
        //
        // Assert
        //
        assert_eq!(total_ap_len, (depth - 1) * T, "Wrong auth path sizes!");

        // Leaf 0
        assert_eq!(
            utils::to_hex(&ap_0[0]),
            "17cd8acc6c4e438664ef675e23dd274fed89954bc8e1e5ad0003f99332212603",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_0[1]),
            "63601b190f10841e7f27b0bf4c4d4662f56398d23c97c83f95f96734bc971aec",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_0[2]),
            "b1de61d350035ca91409bdb67a63cfdc561729e9ba2053a89e41aa0ab0f60651",
            "Wrong node value!"
        );

        // Leaf 1
        assert_eq!(
            utils::to_hex(&ap_1[0]),
            "9e6291970cb44dd94008c79bcaf9d86f18b4b49ba5b2a04781db7199ed3b9e4e",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_1[1]),
            "63601b190f10841e7f27b0bf4c4d4662f56398d23c97c83f95f96734bc971aec",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_1[2]),
            "b1de61d350035ca91409bdb67a63cfdc561729e9ba2053a89e41aa0ab0f60651",
            "Wrong node value!"
        );

        // Leaf 2
        assert_eq!(
            utils::to_hex(&ap_2[0]),
            "04527935532e92b92643e934da84bf65e789e245f4ca0b085b900bbdb81578da",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_2[1]),
            "64bd4e704974908722742b45691661618bb98ccf51e29cd14d7da0ab24a023ec",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_2[2]),
            "b1de61d350035ca91409bdb67a63cfdc561729e9ba2053a89e41aa0ab0f60651",
            "Wrong node value!"
        );

        // Leaf 3
        assert_eq!(
            utils::to_hex(&ap_3[0]),
            "e1fb0112e1ea3e72c8828d3024821a29a8637b94469e2f767f49cec25f24f1e3",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_3[1]),
            "64bd4e704974908722742b45691661618bb98ccf51e29cd14d7da0ab24a023ec",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_3[2]),
            "b1de61d350035ca91409bdb67a63cfdc561729e9ba2053a89e41aa0ab0f60651",
            "Wrong node value!"
        );

        // Leaf 4
        assert_eq!(
            utils::to_hex(&ap_4[0]),
            "381d42c8e1ded6d125eb1d33889210e6fb47b3907f4d85169cd8184bf6f0e9ca",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_4[1]),
            "1427288addf9731621c8770364eb6d73237c6bea8344e9cdadd221f74886bb37",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_4[2]),
            "06f9f538c00164fff766a636947465b374b090640f7b40958ba7472f28d8ae81",
            "Wrong node value!"
        );

        // Leaf 5
        assert_eq!(
            utils::to_hex(&ap_5[0]),
            "d7027bc25d82ac8d2c6419fed9692fa1a3001c98b97baec850241f6119b746c2",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_5[1]),
            "1427288addf9731621c8770364eb6d73237c6bea8344e9cdadd221f74886bb37",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_5[2]),
            "06f9f538c00164fff766a636947465b374b090640f7b40958ba7472f28d8ae81",
            "Wrong node value!"
        );

        // Leaf 6
        assert_eq!(
            utils::to_hex(&ap_6[0]),
            "4e23a1fc2364fb2186e7c82417bad6fbf7e818b9db672e4ce2a8fb0c1c967059",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_6[1]),
            "8de62de3761f3846ec0683545c49214255c2beef58be665334c068f33b399bd7",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_6[2]),
            "06f9f538c00164fff766a636947465b374b090640f7b40958ba7472f28d8ae81",
            "Wrong node value!"
        );

        // Leaf 7
        assert_eq!(
            utils::to_hex(&ap_7[0]),
            "3641b61b4ab1a475f543d5cff15505d0ddc1f7ee3bd24482fb71e01490eeb43d",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_7[1]),
            "8de62de3761f3846ec0683545c49214255c2beef58be665334c068f33b399bd7",
            "Wrong node value!"
        );
        assert_eq!(
            utils::to_hex(&ap_7[2]),
            "06f9f538c00164fff766a636947465b374b090640f7b40958ba7472f28d8ae81",
            "Wrong node value!"
        );
    }

    #[test]
    fn test_merkle_tree_get_auth_path_only_root() {
        //
        // Assess
        //
        const T: usize = 1;
        const BLOCK_SIZE: usize = 32;
        let depth = ((T as f32).log2() as usize) + 1;

        let leaf_numbers =
            utils::gen_byte_blocks_from::<BLOCK_SIZE>(&(0_u64..T as u64).collect::<Vec<u64>>());
        let leaves: Vec<[u8; BLOCK_SIZE]> = leaf_numbers
            .into_iter()
            .map(|i| Sha3_256::digest(i).try_into().unwrap())
            .collect();
        let leaves = leaves
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<Vec<u8>>>();
        for l in leaves.iter() {
            print!("{}", utils::to_hex(l));
        }

        //
        // Act
        //
        let tree = MerkleTree::new::<Sha3_256>(leaves);

        let ap_0: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(0);

        let total_ap_len = ap_0.len();
        //
        // Assert
        //
        assert_eq!(total_ap_len, (depth - 1) * T, "Wrong auth path sizes!");
    }

    #[test]
    #[should_panic]
    fn test_merkle_tree_get_auth_path_empty() {
        //
        // Assess
        //
        const T: usize = 0;
        const BLOCK_SIZE: usize = 32;

        let leaf_numbers =
            utils::gen_byte_blocks_from::<BLOCK_SIZE>(&(0_u64..T as u64).collect::<Vec<u64>>());
        let leaves: Vec<[u8; BLOCK_SIZE]> = leaf_numbers
            .into_iter()
            .map(|i| Sha3_256::digest(i).try_into().unwrap())
            .collect();
        let leaves = leaves
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<Vec<u8>>>();
        for l in leaves.iter() {
            print!("{}", utils::to_hex(l));
        }

        //
        // Act
        //
        let tree = MerkleTree::new::<Sha3_256>(leaves);

        let _ap_0: Vec<[u8; BLOCK_SIZE]> = tree.get_auth_path(0); //< Should panic
    }

    #[test]
    fn test_merkle_tree_general() {
        const T: usize = 256;
        const BLOCK_SIZE: usize = 32;

        let leaf_numbers =
            utils::gen_byte_blocks_from::<BLOCK_SIZE>(&(0_u64..T as u64).collect::<Vec<u64>>());
        let leaves: Vec<[u8; BLOCK_SIZE]> = leaf_numbers
            .into_iter()
            .map(|i| Sha3_256::digest(i).try_into().unwrap())
            .collect();
        let leaves = leaves
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<Vec<u8>>>();
        for l in leaves.iter() {
            print!("{}", utils::to_hex(l));
        }

        let tree: MerkleTree<BLOCK_SIZE> = MerkleTree::new::<Sha3_256>(leaves);
        debug!("{}", tree);
    }

    #[test]
    fn test_merkle_tree_construct() {
        const T: usize = 4;
        const BLOCK_SIZE: usize = 32;

        //
        // Arrange
        //

        // Leaves in vectors
        let leaf_numbers =
            utils::gen_byte_blocks_from::<BLOCK_SIZE>(&(0_u64..T as u64).collect::<Vec<u64>>());
        let leaves: Vec<[u8; BLOCK_SIZE]> = leaf_numbers
            .iter()
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
        let act_tree: MerkleTree<BLOCK_SIZE> = MerkleTree::new::<Sha3_256>(leaf_numbers);

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
    fn test_merkle_tree_construct_large() {
        const T: usize = 2048;
        const BLOCK_SIZE: usize = 32;

        let leaf_numbers =
            utils::gen_byte_blocks_from::<BLOCK_SIZE>(&(0_u64..T as u64).collect::<Vec<u64>>());

        // Build the tree
        let act_tree: MerkleTree<BLOCK_SIZE> = MerkleTree::new::<Sha3_256>(leaf_numbers);
        println!("{}", utils::to_hex(act_tree.root()));

        assert_eq!(
            utils::to_hex(&act_tree.data[0]),
            "c9f43b64630ddced98a3a9b2054b0c0d5d0c27f160ae84bdd23d6c1cf6ca6c81"
        )
    }
}
