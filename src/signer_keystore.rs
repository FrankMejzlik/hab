//!
//! Component managing keys for the broadcaster.
//!

use std::alloc::Layout;
use std::vec::Vec;
// ---
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha3::Digest;
// ---
use crate::horst::{HorstKeypair, HorstSecretKey, HorstSigScheme};
use crate::signature_scheme::SignatureScheme;
use crate::utils;
use crate::utils::UnixTimestamp;

pub use crate::horst::{HorstPublicKey as PublicKey, HorstSignature as Signature};

///
/// Wrapper for one key.
///
struct KeyCont<const N: usize, const T: usize> {
    key: HorstKeypair<N, T>,
    last_cerified: UnixTimestamp,
    signs: usize,
    lifetime: usize,
}

/// Struct holding parameters for the keystore.
pub struct SignerKeystoreParams {
    pub seed: u64,
}

pub struct SignerKeystore<
    const N: usize,
    const K: usize,
    const TAU: usize,
    const TAUPLUS: usize,
    const T: usize,
    const MSG_HASH_SIZE: usize,
    const TREE_HASH_SIZE: usize,
    CsPrng: CryptoRng + SeedableRng + RngCore,
    MsgHashFn: Digest,
    TreeHashFn: Digest,
> {
    signer: HorstSigScheme<
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
    >,
    layers: Vec<Vec<KeyCont<N, T>>>,
}

impl<
        const N: usize,
        const K: usize,
        const TAU: usize,
        const TAUPLUS: usize,
        const T: usize,
        const MSG_HASH_SIZE: usize,
        const TREE_HASH_SIZE: usize,
        CsPrng: CryptoRng + SeedableRng + RngCore,
        MsgHashFn: Digest,
        TreeHash: Digest,
    >
    SignerKeystore<
        N,
        K,
        TAU,
        TAUPLUS,
        T,
        MSG_HASH_SIZE,
        TREE_HASH_SIZE,
        CsPrng,
        MsgHashFn,
        TreeHash,
    >
{
    pub fn new(params: SignerKeystoreParams) -> Self {
        let signer = HorstSigScheme::new(params.seed);
        let layers = vec![];
        SignerKeystore { signer, layers }
    }
}
