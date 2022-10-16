// ---
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Keccak256, Keccak512};
// ---
use crate::signer::{Key, PrivateKey, PublicKey, SignedBlock, Signer};

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
    fn new() -> Self {
        LamportKey {
            data: [[[0; 256]; 256]; 2],
        }
    }
    fn data(&self) -> &[u8] {
        return &self.data[0][0];
    }
}

impl PrivateKey for LamportKey {}
impl PublicKey for LamportKey {}

pub struct LamportSigner {}

impl LamportSigner {}

impl Signer<Keccak512, Keccak256, LamportKey, LamportKey, ChaCha20Rng> for LamportSigner {
    fn new(seed: u64) -> Self {
        let _small_hash = Keccak256::new();
        let _large_hash = Keccak512::new();
        let _rng = ChaCha20Rng::seed_from_u64(seed);

        LamportSigner {}
    }

    fn sign(&self, _msg: &[u8], _priv_key: LamportKey) -> SignedBlock {
        SignedBlock::new(
            vec![1; BLOCK_SIZE],
            vec![2; SIGN_SIZE],
            vec![3; PUB_KEY_SIZE * 6],
        )
    }

    fn verify(&self, _signature: &[u8], _pub_key: LamportKey) -> bool {
        true
    }

    fn gen_key_pair(&self) -> (LamportKey, LamportKey) {
        (LamportKey::new(), LamportKey::new())
    }
}
