//!
//! Module for broadcasting the signed data packets.
//!

use std::marker::PhantomData;
// ---
use bincode::serialize;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use sha3::Digest;
// ---
pub use crate::horst::{
    HorstKeypair, HorstPublicKey as PublicKey, HorstSecretKey as SecretKey, HorstSigScheme,
    HorstSignature as Signature,
};
use crate::traits::SignatureScheme;
use crate::utils::UnixTimestamp;

///
/// Wrapper for one key.
///
#[derive(Clone)]
struct KeyCont<const T: usize, const N: usize> {
    key: HorstKeypair<T, N>,
    last_cerified: UnixTimestamp,
    signs: usize,
    lifetime: usize,
}

#[derive(Debug)]
pub enum BlockSignerError {
    FailedToSign(String),
}

/// Struct holding parameters for the sender.
pub struct BlockSignerParams {
    pub seed: u64,
}

/// Struct holding a data to send with the signature and piggy-backed public keys.
#[derive(Debug)]
pub struct SignedBlock<Signature: Serialize, PublicKey: Serialize> {
    pub data: Vec<u8>,
    pub signature: Signature,
    pub pub_keys: Vec<PublicKey>,
}
impl<Signature: Serialize, PublicKey: Serialize> SignedBlock<Signature, PublicKey> {
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(&self).unwrap()
    }
}

impl<Signature: Serialize, PublicKey: Serialize> Serialize for SignedBlock<Signature, PublicKey> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("SignedBlock", 3)?;
        state.serialize_field("data", &self.data)?;
        state.serialize_field("signature", &self.signature)?;
        state.serialize_field("pub_keys", &self.pub_keys)?;
        state.end()
    }
}

struct KeyLayers<const T: usize, const N: usize> {
    data: Vec<Vec<KeyCont<T, N>>>,
}

impl<const T: usize, const N: usize> KeyLayers<T, N> {
    pub fn new(depth: usize) -> Self {
        KeyLayers {
            data: vec![vec![]; depth],
        }
    }

    pub fn insert(&mut self, level: usize, keypair: HorstKeypair<T, N>) {
        let key_cont = KeyCont {
            key: keypair,
            last_cerified: 0,
            signs: 0,
            lifetime: 20,
        };

        self.data[level].push(key_cont);
    }
}

pub trait BlockSignerTrait<
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
>
{
    type Signer;

    fn new(params: BlockSignerParams) -> Self;
    fn sign(
        &mut self,
        data: &[u8],
    ) -> Result<SignedBlock<Signature<TREE_HASH_SIZE, K, TAUPLUS>, PublicKey<N>>, BlockSignerError>;
    fn next_key(&mut self) -> (&SecretKey<T, TREE_HASH_SIZE>, Vec<PublicKey<N>>);
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
    rng: CsPrng,
    layers: KeyLayers<T, TREE_HASH_SIZE>,
    // ---
    // To determine the type variance: https://stackoverflow.com/a/71276732
    phantom0: PhantomData<MsgHashFn>,
    phantom1: PhantomData<TreeHashFn>,
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
    BlockSignerTrait<
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
    for BlockSigner<
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
        TreeHash,
    >;

    /// Constructs and initializes a block signer with the given parameters.
    fn new(params: BlockSignerParams) -> Self {
        let mut rng = CsPrng::seed_from_u64(params.seed);
        let mut layers = KeyLayers::new(1);

        let keypair = Self::Signer::gen_key_pair(&mut rng);

        layers.insert(0, keypair);

        BlockSigner {
            rng,
            layers,
            phantom0: PhantomData,
            phantom1: PhantomData,
        }
    }

    fn sign(
        &mut self,
        data: &[u8],
    ) -> Result<SignedBlock<Signature<TREE_HASH_SIZE, K, TAUPLUS>, PublicKey<N>>, BlockSignerError>
    {
        let (sk, pub_keys) = self.next_key();

        let signature = Self::Signer::sign(data, sk);

        // --- check ---
        assert_eq!(
            Self::Signer::verify(data, &signature, &self.layers.data[0][0].key.public),
            true
        );
        info!("Signature check OK.");
        // --- check ---

        Ok(SignedBlock {
            data: data.to_vec(),
            signature,
            pub_keys,
        })
    }

    fn next_key(&mut self) -> (&SecretKey<T, TREE_HASH_SIZE>, Vec<PublicKey<N>>) {
        let pks = vec![PublicKey::new(&[0_u8; N])];

        // TODO: Implement
        (&self.layers.data[0][0].key.secret, pks)
    }
}
