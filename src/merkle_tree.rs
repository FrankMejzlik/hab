
use std::fmt::{write, Debug};
use std::fmt::{Display, Formatter, Result};
use sha3::{Digest};
// ---
use log::debug;

#[derive(Debug)]
pub struct MerkleTree<const BLOCK_SIZE:usize> {
    data: Vec<[u8; BLOCK_SIZE]>,
    t: usize,
    h: usize,
    size: usize,
}


impl<const BLOCK_SIZE:usize> MerkleTree<BLOCK_SIZE>
{
    pub fn construct<Hash:Digest>(leaves: Vec<[u8; BLOCK_SIZE]>) -> Self {
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
		println!("{}", h);
        let size = 2_usize.pow(h as u32) - 1;
        let mut data = vec![[0u8;BLOCK_SIZE]; size];

		let base = 2_usize.pow((h - 1) as u32) - 1;

		for (i,d) in leaves.into_iter().enumerate() {
			data[base + i] = d;
		}

		let mut t = MerkleTree { data, t, h, size };

		for l in (0_u32..(h-1) as u32).rev() {
			let num_idxs = 2_usize.pow(l as u32);
			let base_prev = 2_usize.pow((l+1) as u32) - 1;
			let base = 2_usize.pow(l as u32) - 1;
            for i in 0_usize..num_idxs {
				debug!("base: {}, i: {}",base, i);

				let mut l = t.data[base_prev+2*i].to_vec();
				let mut r = t.data[base_prev+2*i+1].to_vec();
				let mut concat = vec![0u8; 2*BLOCK_SIZE];
				concat.append(&mut l);
				concat.append(&mut r);

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

impl<const BLOCK_SIZE:usize> Display for MerkleTree<BLOCK_SIZE>
{
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
                for (i,b) in self.get(l, i).into_iter().enumerate() {
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
