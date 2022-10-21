use std::boxed::Box;
// ---
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
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
const BLOCK_SIZE: usize = 256;
const W: usize = 256;
const NUM_BLOCKS: usize = BLOCK_SIZE;
const SIGN_SIZE: usize = BLOCK_SIZE * W;
const PRIV_KEY_SIZE: usize = BLOCK_SIZE * W * 2;
const PUB_KEY_SIZE: usize = PRIV_KEY_SIZE;

type Block = [u8; BLOCK_SIZE];
type BlockArray = [Block; NUM_BLOCKS];

#[derive(Debug)]
pub struct LamportKey {
    data: [BlockArray; 2],
}

impl Key for LamportKey {
    type CsRng = ImplCsRng;
    fn new(_rng: &mut Self::CsRng) -> Self {
        LamportKey {
            data: [[[0; BLOCK_SIZE]; BLOCK_SIZE]; 2],
        }
    }
    fn data(&self) -> &[u8] {
        return &self.data[0][0];
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
        Box::new(KeyPair {
            private: LamportKey::new(&mut self.rng),
            public: LamportKey::new(&mut self.rng),
        })
    }
}
