use std::boxed::Box;
use std::fmt::{Display, Formatter, Result};
// ---
use hex::encode;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha3::{Digest, Keccak256, Keccak512};
// ---
use crate::signature_scheme::{Key, KeyPair, PrivateKey, PublicKey, SignatureScheme, SignedBlock};

//
// Implementation parameters
//
type ImplCsRng = ChaCha20Rng;
type ImplLargeHash = Keccak512;
type ImplSmallHash = Keccak256;
type ImplPrivateKey = LamportKey;
type ImplPublicKey = LamportKey;
// ---
const BLOCK_SIZE: usize = 32; // 256 bits
const W: usize = 256;
const NUM_BLOCKS: usize = W;
const SIGN_SIZE: usize = BLOCK_SIZE * W;
const PRIV_KEY_SIZE: usize = BLOCK_SIZE * W * 2;
const PUB_KEY_SIZE: usize = PRIV_KEY_SIZE;

type Block = [u8; BLOCK_SIZE];
type BlockArray = [Block; NUM_BLOCKS];

impl Display for KeyPair<ImplPrivateKey, ImplPublicKey> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        writeln!(
            f,
            "\n--- PRIVATE ---\n{}\n--- PUBLIC ---\n{}",
            self.private, self.public
        )
    }
}

#[derive(Debug, Clone)]
pub struct LamportKey {
    data: Box<[BlockArray; 2]>,
}
impl LamportKey {
    /// Takes the private key, generates and returns the matching public key.
    fn make_public(priv_key: &LamportKey) -> Self {
        type Hash = <LamportKey as Key>::Hash;

        // Allocate the memory
        let mut data = priv_key.data.clone();

        // Generate the key
        for blocks in data.iter_mut() {
            for block in blocks.iter_mut() {
                let hash = Hash::digest(&block);

                assert_eq!(
                    Hash::output_size(),
                    BLOCK_SIZE,
                    "Hash function has the different output size then the block size!"
                );
                block.copy_from_slice(&hash[..BLOCK_SIZE]);
            }
        }

        LamportKey { data }
    }
}
impl Key for LamportKey {
    type CsRng = ImplCsRng;
    type Hash = ImplSmallHash;

    fn new(rng: &mut Self::CsRng) -> Self {
        // Allocate the memory
        let mut data = Box::new([[[0u8; BLOCK_SIZE]; NUM_BLOCKS]; 2]);

        // Generate the key
        for blocks in data.iter_mut() {
            for block in blocks.iter_mut() {
                rng.fill_bytes(block);
            }
        }

        LamportKey { data }
    }
    fn data(&self) -> &[u8] {
        return &self.data[0][0];
    }
}

impl Display for LamportKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
        writeln!(f, "<<< LamportKey >>>")?;
        for (idx, blocks) in self.data.iter().enumerate() {
            writeln!(f, "{}:", idx)?;
            writeln!(f, "\t[{:0>3}]: {}", 0, encode(blocks[0]))?;
            writeln!(f, "\t[{:0>3}]: {}", 1, encode(blocks[1]))?;
            writeln!(f, "\t...")?;
            writeln!(
                f,
                "\t[{:0>3}]: {}",
                NUM_BLOCKS - 2,
                encode(blocks[NUM_BLOCKS - 2])
            )?;
            writeln!(
                f,
                "\t[{:0>3}]: {}",
                NUM_BLOCKS - 1,
                encode(blocks[NUM_BLOCKS - 1])
            )?;
        }

        Ok(())
    }
}

impl PrivateKey for LamportKey {}
impl PublicKey for LamportKey {}

pub struct LamportSignatureScheme {
    rng: <LamportSignatureScheme as SignatureScheme>::CsRng,
}

impl LamportSignatureScheme {}

impl SignatureScheme for LamportSignatureScheme {
    type CsRng = ImplCsRng;
    type LargeHash = ImplLargeHash;
    type SmallHash = ImplSmallHash;
    type PrivateKey = ImplPrivateKey;
    type PublicKey = ImplPublicKey;

    fn new(seed: u64) -> Self {
        let _small_hash = Self::SmallHash::new();
        let _large_hash = Self::LargeHash::new();
        let rng = Self::CsRng::seed_from_u64(seed);

        LamportSignatureScheme { rng }
    }

    fn sign(&mut self, _msg: &[u8], _priv_key: &LamportKey) -> Box<SignedBlock> {
        Box::new(SignedBlock::new(
            vec![1; BLOCK_SIZE],
            vec![2; SIGN_SIZE],
            vec![3; PUB_KEY_SIZE * 6],
        ))
    }

    fn verify(&self, _signature: &[u8], _pub_key: &LamportKey) -> bool {
        true
    }

    fn gen_key_pair(&mut self) -> Box<KeyPair<LamportKey, LamportKey>> {
        let private = LamportKey::new(&mut self.rng);
        let public = LamportKey::make_public(&private);
        Box::new(KeyPair { private, public })
    }
}
