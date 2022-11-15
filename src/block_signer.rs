//!
//! Module for broadcasting the signed data packets.
//!

// ---
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha3::Digest;
// ---
use crate::signer_keystore::*;

/// Struct holding parameters for the sender.
pub struct BlockSignerParams {
    pub seed: u64,
}

pub struct BlockSigner<
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
    keystore: SignerKeystore<
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
    > BlockSigner<N, K, TAU, TAUPLUS, T, MSG_HASH_SIZE, TREE_HASH_SIZE, CsPrng, MsgHashFn, TreeHash>
{
    pub fn new(params: BlockSignerParams) -> Self {
        let keystore_params = SignerKeystoreParams { seed: params.seed };
        let keystore = SignerKeystore::new(keystore_params);
        BlockSigner { keystore }
    }
}
