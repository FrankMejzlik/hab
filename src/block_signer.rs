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
use crate::common::Error;
pub use crate::horst::{
    HorstKeypair, HorstPublicKey as PublicKey, HorstSecretKey as SecretKey, HorstSigScheme,
    HorstSignature as Signature,
};
use crate::traits::{BlockSignerTrait, SignatureSchemeTrait};
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
    rng: CsPrng,
    layers: KeyLayers<T, TREE_HASH_SIZE>,
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
        let pks = vec![PublicKey::new(&[0_u8; TREE_HASH_SIZE])];

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
            _p: PhantomData,
        }
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::SignedBlock, Error> {
        let (sk, pub_keys) = self.next_key();

        let signature = Self::Signer::sign(data, sk);

        // --- sanity check ---
        assert_eq!(
            Self::Signer::verify(data, &signature, &self.layers.data[0][0].key.public),
            true
        );
        info!("Signature check OK.");
        // --- sanity check ---

        Ok(SignedBlock {
            data: data.to_vec(),
            signature,
            pub_keys,
        })
    }
}
