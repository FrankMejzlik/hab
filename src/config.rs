//!
//! General static config file where you can tune the desired protocol paramters.
//!

// ---
use cfg_if::cfg_if;
use rand_chacha::ChaCha20Rng;
use sha3::{Sha3_256, Sha3_512};
// ---
use crate::block_signer::BlockSigner;

/// A directory where the identity files lie (e.g. `BlockSigner` with secret & public keys).
pub const ID_DIR: &str = ".identity/";
/// A name of the file where the state of `BlockSigner` is serialized.
pub const ID_FILENAME: &str = "id.bin";
pub const ID_CHECK_FILENAME: &str = "id.txt";

pub const LOGS_DIR: &str = "logs/";
pub const INPUT_DBG_DIR: &str = "logs/input/";
pub const OUTPUT_DBG_DIR: &str = "logs/output/";

pub const SUBSCRIBER_LIFETIME: u128 = 10_000;
pub const BUFFER_SIZE: usize = 1024;
/// For debug: 0 -> valid, 1 -> invalid
pub const DUMMY_KEY_IDX: usize = 0;
pub const DATAGRAM_SIZE: usize = 512;

// ***************************************
//             PARAMETERS
// ***************************************
cfg_if! {
    // *** PRODUCTION ***
    if #[cfg(not(feature = "debug"))] {
        /// Size of the hashes in a Merkle tree
        const N: usize = 256 / 8;
        /// Number of SK segments in signature
        const K: usize = 32;
        /// Depth of the Merkle tree (without the root layer)
        const TAU: usize = 16;

        // --- Random generators ---
        /// A seedable CSPRNG used for number generation
        type CsPrng = ChaCha20Rng;

        // --- Hash functions ---
        // Hash fn for message hashing. msg: * -> N
        type MsgHashFn = Sha3_512;
        // Hash fn for tree & secret hashing. sk: 2N -> N & tree: N -> N
        type TreeHashFn = Sha3_256;
    }
    // *** DEBUG ***
    else {
        /// Size of the hashes in a Merkle tree
        const N: usize = 256 / 8;
        /// Number of SK segments in signature
        const K: usize = 128;
        /// Depth of the Merkle tree (without the root layer)
        const TAU: usize = 4;

        // --- Random generators ---
        /// A seedable CSPRNG used for number generation
        type CsPrng = ChaCha20Rng;

        // --- Hash functions ---
        // Hash fn for message hashing. msg: * -> N
        type MsgHashFn = Sha3_512;
        // Hash fn for tree & secret hashing. sk: 2N -> N & tree: N -> N
        type TreeHashFn = Sha3_256;
    }
}

// ---
const T: usize = 2_usize.pow(TAU as u32);
const MSG_HASH_SIZE: usize = (K * TAU) / 8;
const TREE_HASH_SIZE: usize = N;

// Alias for the specific signer we'll be using
pub type BlockSignerInst = BlockSigner<
    K,
    TAU,
    { TAU + 1 },
    T,
    MSG_HASH_SIZE,
    TREE_HASH_SIZE,
    CsPrng,
    MsgHashFn,
    TreeHashFn,
>;

// Alias for the specific verifier we'll be using
pub type BlockVerifierInst = BlockSigner<
    K,
    TAU,
    { TAU + 1 },
    T,
    MSG_HASH_SIZE,
    TREE_HASH_SIZE,
    CsPrng,
    MsgHashFn,
    TreeHashFn,
>;
