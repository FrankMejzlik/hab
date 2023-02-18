//!
//! Module for broadcasting the signed data packets.
//!

use std::marker::PhantomData;
// ---
use bincode::{deserialize, serialize};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::de::Deserializer;
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use slice_of_array::SliceFlatExt;
use xxhash_rust::xxh3::xxh3_64;
// ---
use crate::common::Error;
pub use crate::horst::{
    HorstKeypair, HorstPublicKey as PublicKey, HorstSecretKey as SecretKey, HorstSigScheme,
    HorstSignature as Signature,
};
use crate::traits::{BlockSignerTrait, BlockVerifierTrait, SignatureSchemeTrait};
use crate::utils::UnixTimestamp;

///
/// Wrapper for one key.
///
#[derive(Clone, Serialize, Deserialize)]
struct KeyCont<const T: usize, const N: usize> {
    key: HorstKeypair<T, N>,
    #[allow(dead_code)]
    last_cerified: UnixTimestamp,
    #[allow(dead_code)]
    signs: usize,
    #[allow(dead_code)]
    lifetime: usize,
}

/// Struct holding parameters for the sender.
pub struct BlockSignerParams {
    pub seed: u64,
}

/// Struct holding a data to send with the signature and piggy-backed public keys.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedBlock<Signature: Serialize, PublicKey: Serialize> {
    pub data: Vec<u8>,
    pub signature: Signature,
    pub pub_keys: Vec<PublicKey>,
}

#[derive(Serialize, Deserialize)]
struct KeyLayers<const T: usize, const N: usize> {
    data: Vec<Vec<KeyCont<T, N>>>,
}

impl<const T: usize, const N: usize> KeyLayers<T, N> {
    pub fn new(depth: usize) -> Self {
        KeyLayers {
            data: vec![vec![]; depth],
        }
    }

    fn insert(&mut self, level: usize, keypair: HorstKeypair<T, N>) {
        let key_cont = KeyCont {
            key: keypair,
            last_cerified: 0,
            signs: 0,
            lifetime: 20,
        };

        self.data[level].push(key_cont);
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockSigner<
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
    #[allow(dead_code)]
    rng: CsPrng,
    layers: KeyLayers<T, TREE_HASH_SIZE>,
    pks: Vec<<Self as BlockSignerTrait>::PublicKey>,
    // ---
    // To determine the type variance: https://stackoverflow.com/a/65960918
    _p: PhantomData<(MsgHashFn, TreeHashFn)>,
}

impl<
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
    BlockSigner<K, TAU, TAUPLUS, T, MSG_HASH_SIZE, TREE_HASH_SIZE, CsPrng, MsgHashFn, TreeHashFn>
{
    fn next_key(
        &mut self,
    ) -> (
        &SecretKey<T, TREE_HASH_SIZE>,
        Vec<PublicKey<TREE_HASH_SIZE>>,
    ) {
        // TODO: Implement
        let pks = vec![
            self.layers.data[0][0].key.public.clone(),
            PublicKey::new(&[0_u8; TREE_HASH_SIZE]),
        ];

        // TODO: Implement
        (&self.layers.data[0][0].key.secret, pks)
    }
}

impl<
        const K: usize,
        const TAU: usize,
        const TAUPLUS: usize,
        const T: usize,
        const MSG_HASH_SIZE: usize,
        const TREE_HASH_SIZE: usize,
        CsPrng: CryptoRng + SeedableRng + RngCore,
        MsgHashFn: Digest,
        TreeHash: Digest,
    > BlockSignerTrait
    for BlockSigner<K, TAU, TAUPLUS, T, MSG_HASH_SIZE, TREE_HASH_SIZE, CsPrng, MsgHashFn, TreeHash>
{
    type Error = Error;
    type Signer = HorstSigScheme<
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

    type SecretKey = <Self::Signer as SignatureSchemeTrait>::SecretKey;
    type PublicKey = <Self::Signer as SignatureSchemeTrait>::PublicKey;
    type Signature = <Self::Signer as SignatureSchemeTrait>::Signature;
    type SignedBlock = SignedBlock<Self::Signature, Self::PublicKey>;
    type BlockSignerParams = BlockSignerParams;

    /// Constructs and initializes a block signer with the given parameters.
    fn new(params: BlockSignerParams) -> Self {
        let mut rng = CsPrng::seed_from_u64(params.seed);
        let mut layers = KeyLayers::new(1);

        let keypair = Self::Signer::gen_key_pair(&mut rng);

        layers.insert(0, keypair);

        BlockSigner {
            rng,
            layers,
            pks: vec![],
            _p: PhantomData,
        }
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::SignedBlock, Error> {
        let (sk, pub_keys) = self.next_key();

        let signature = Self::Signer::sign(data, sk);

        // --- sanity check ---
        assert!(Self::Signer::verify(
            data,
            &signature,
            &self.layers.data[0][0].key.public
        ));
        // --- sanity check ---

        Ok(SignedBlock {
            data: data.to_vec(),
            signature,
            pub_keys,
        })
    }
}

impl<
        const K: usize,
        const TAU: usize,
        const TAUPLUS: usize,
        const T: usize,
        const MSG_HASH_SIZE: usize,
        const TREE_HASH_SIZE: usize,
        CsPrng: CryptoRng + SeedableRng + RngCore,
        MsgHashFn: Digest,
        TreeHash: Digest,
    > BlockVerifierTrait
    for BlockSigner<K, TAU, TAUPLUS, T, MSG_HASH_SIZE, TREE_HASH_SIZE, CsPrng, MsgHashFn, TreeHash>
{
    type Error = Error;
    type Signer = HorstSigScheme<
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

    type SecretKey = <Self::Signer as SignatureSchemeTrait>::SecretKey;
    type PublicKey = <Self::Signer as SignatureSchemeTrait>::PublicKey;
    type Signature = <Self::Signer as SignatureSchemeTrait>::Signature;
    type SignedBlock = SignedBlock<Self::Signature, Self::PublicKey>;
    type BlockVerifierParams = BlockSignerParams;

    /// Constructs and initializes a block signer with the given parameters.
    fn new(params: BlockSignerParams) -> Self {
        let mut rng = CsPrng::seed_from_u64(params.seed);
        let mut layers = KeyLayers::new(1);

        let keypair = Self::Signer::gen_key_pair(&mut rng);

        layers.insert(0, keypair);

        BlockSigner {
            rng,
            layers,
            pks: vec![],
            _p: PhantomData,
        }
    }

    fn verify(&mut self, data: Vec<u8>) -> Result<(Vec<u8>, u64, u64), Error> {
        let block: Self::SignedBlock =
            bincode::deserialize(&data).expect("Should be deserializable!");

        let mut tmp2 = 0;
        for x in &block.signature.data {
            for y in x {
                let h = xxh3_64(&y);
                tmp2 = tmp2 ^ h;
            }
        }

        let mut tmp = 0;
        for pk in block.pub_keys.iter() {
            tmp = tmp ^ xxh3_64(pk.data.as_ref());
        }
        let hash_pks = tmp;
        let hash_sign = tmp2;

        match Self::Signer::verify(&block.data, &block.signature, &block.pub_keys[0]) {
            true => Ok((block.data, hash_sign, hash_pks)),
            false => Err(Error::new("Unable to verify the signature!")),
        }
    }
}
