#[allow(clippy::assertions_on_constants)]
mod horst;
mod merkle_tree;
mod signature_scheme;
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
use horst::HorstSigScheme;
use signature_scheme::SignatureScheme;

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

type Signer = HorstSigScheme<
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

    let msg = b"Hello, world!";

    let mut alice_signer = Signer::new(args.seed);
    let mut eve_signer = Signer::new(args.seed + 1);

    //
    // Alice signs
    //
    let alice_key_pair = alice_signer.gen_key_pair();
    debug!("{}", alice_key_pair);
    let alice_sign = alice_signer.sign(msg);
    debug!("{}", alice_sign);

    //
    // Eve attacker signs
    //
    let _eve_key_pair = eve_signer.gen_key_pair();
    // debug!("{}", eve_key_pair);
    let eve_sign = eve_signer.sign(msg);
    // debug!("{}", eve_sign);

    //
    // Bob verifies
    //
    let bob_from_alice_valid = Signer::verify(msg, &alice_sign, &alice_key_pair.public);
    debug!("Valid signature check's result: {}", bob_from_alice_valid);
    assert!(bob_from_alice_valid, "The valid signature was rejected!");

    let bob_from_eve_valid = Signer::verify(msg, &eve_sign, &alice_key_pair.public);
    debug!("Invalid signature check's result: {}", bob_from_eve_valid);
    assert!(!bob_from_eve_valid, "The invalid signature was accepted!");
}
