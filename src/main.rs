//!
//! <PROJECT_NAME> is an implementation of the hash-based authentication protocol for streamed data.
//!
mod block_signer;
mod broadcaster;
#[allow(clippy::assertions_on_constants)]
mod horst;
mod merkle_tree;
mod receiver;
mod signature_scheme;
mod signer_keystore;
mod utils;

// ---
use cfg_if::cfg_if;
use clap::Parser;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand_chacha::ChaCha20Rng;
use sha3::{Sha3_256, Sha3_512};
use simple_logger::SimpleLogger;
// ---
use block_signer::{BlockSigner, BlockSignerParams};
use broadcaster::{Broadcaster, BroadcasterError, BroadcasterParams};

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
const TAUPLUS: usize = TAU + 1;
const T: usize = 2_usize.pow(TAU as u32);
const MSG_HASH_SIZE: usize = (K * TAU) / 8;
const TREE_HASH_SIZE: usize = N;

type BlockSignerTyped = BlockSigner<
    N,
    K,
    TAU,
    TAUPLUS,
    T,
    MSG_HASH_SIZE,
    TREE_HASH_SIZE,
    CsPrng,
    MsgHashFn,
    TreeHashFn,
>;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// PRNG seed
    #[clap(short, long, default_value_t = 42)]
    seed: u64,
}

fn main() {
    SimpleLogger::new().without_timestamps().init().unwrap();
    let args = Args::parse();

    let params = BlockSignerParams { seed: args.seed };
    let bcaster_params = BroadcasterParams {};

    let msg = b"Hello, world!";

    let mut signer = BlockSignerTyped::new(params);

    let packet = match signer.sign(msg) {
        Ok(x) => x,
        Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
    };

    debug!("packet: {} B", std::mem::size_of_val(&packet));

    let bcaster = Broadcaster::new(bcaster_params);
    let packet_bytes = packet.to_bytes();
    match bcaster.broadcast(&packet_bytes) {
        Ok(()) => debug!("Packet broadcasted."),
        Err(e) => panic!("Failed to broadcast the data block!\nERROR: {:?}", e),
    };
}
