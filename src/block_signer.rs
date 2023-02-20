//!
//! Module for broadcasting the signed data packets.
//!

use std::hash::Hash;
use std::marker::PhantomData;
// ---
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use core::fmt::Debug;
use std::collections::HashSet;

use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::de::Deserializer;
use serde::ser::{SerializeStruct, Serializer};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::Digest;
use slice_of_array::SliceFlatExt;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use xxhash_rust::xxh3::xxh3_64;
// ---
use crate::common::Error;
use crate::config;
use crate::horst::HorstPublicKey;
pub use crate::horst::{
    HorstKeypair, HorstPublicKey as PublicKey, HorstSecretKey as SecretKey, HorstSigScheme,
    HorstSignature as Signature,
};
use crate::traits::{BlockSignerTrait, BlockVerifierTrait, SignatureSchemeTrait};
use crate::utils;
use crate::utils::UnixTimestamp;
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};
use std::{fmt, num};

///
/// Wrapper for one key.
///
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct KeyCont<const T: usize, const N: usize> {
    key: HorstKeypair<T, N>,
    #[allow(dead_code)]
    last_cerified: UnixTimestamp,
    #[allow(dead_code)]
    signs: usize,
    #[allow(dead_code)]
    lifetime: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyWrapper<Key> {
    pub key: Key,
    pub layer: u8,
}
impl<Key> KeyWrapper<Key> {
    pub fn new(key: Key, layer: u8) -> Self {
        KeyWrapper { key, layer }
    }
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
    pub pub_keys: Vec<KeyWrapper<PublicKey>>,
}

#[derive(Serialize, Debug, Deserialize, PartialEq)]
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

#[derive(Debug)]
pub struct BlockSigner<
    const K: usize,
    const TAU: usize,
    const TAUPLUS: usize,
    const T: usize,
    const MSG_HASH_SIZE: usize,
    const TREE_HASH_SIZE: usize,
    CsPrng: CryptoRng + SeedableRng + RngCore + Serialize + DeserializeOwned + PartialEq + Debug,
    MsgHashFn: Digest + Debug,
    TreeHashFn: Digest + Debug,
> {
    rng: CsPrng,
    layers: KeyLayers<T, TREE_HASH_SIZE>,
    pks: HashSet<(UnixTimestamp, u8, <Self as BlockSignerTrait>::PublicKey)>,
    _x: PhantomData<(MsgHashFn, TreeHashFn)>,
}

impl<
        const K: usize,
        const TAU: usize,
        const TAUPLUS: usize,
        const T: usize,
        const MSG_HASH_SIZE: usize,
        const TREE_HASH_SIZE: usize,
        CsPrng: CryptoRng + SeedableRng + RngCore + Serialize + DeserializeOwned + PartialEq + Debug,
        MsgHashFn: Digest + Debug,
        TreeHashFn: Digest + Debug,
    >
    BlockSigner<K, TAU, TAUPLUS, T, MSG_HASH_SIZE, TREE_HASH_SIZE, CsPrng, MsgHashFn, TreeHashFn>
{
    fn dump_pks(&self) -> String {
        let mut res = String::new();
        res.push_str("=== RECEIVER: Public keys ===\n");
        for (_, _, pk) in self.pks.iter() {
            res.push_str(&format!("\t{}", pk));
        }
        res
    }

    fn store_state(&mut self) {
        create_dir_all(config::ID_DIR).expect("!");
        let filepath = format!("{}/{}", config::ID_DIR, config::ID_FILENAME);
        let filepath_string = format!("{}/{}", config::ID_DIR, config::ID_CHECK_FILENAME);
        {
            let mut file = File::create(filepath).expect("The file should be writable!");

            let rng_bytes = bincode::serialize(&self.rng).expect("!");
            let layers_bytes = bincode::serialize(&self.layers).expect("!");
            let pks_bytes = bincode::serialize(&self.pks).expect("!");

            file.write_u64::<LittleEndian>(rng_bytes.len() as u64)
                .expect("!");
            file.write_u64::<LittleEndian>(layers_bytes.len() as u64)
                .expect("!");
            file.write_u64::<LittleEndian>(pks_bytes.len() as u64)
                .expect("!");
            file.write_all(&rng_bytes)
                .expect("Failed to write state to file");
            file.write_all(&layers_bytes)
                .expect("Failed to write state to file");
            file.write_all(&pks_bytes)
                .expect("Failed to write state to file");

            let mut file2 = File::create(filepath_string).expect("!");
            file2
                .write_all(&format!("{:?}", self).into_bytes())
                .expect("!");
        }

        // Check
        {
            let filepath = format!("{}/{}", config::ID_DIR, config::ID_FILENAME);
            let mut file = File::open(filepath).expect("!");

            let rng_len = file.read_u64::<LittleEndian>().expect("!") as usize;
            let layers_len = file.read_u64::<LittleEndian>().expect("!") as usize;
            let pks_len = file.read_u64::<LittleEndian>().expect("!") as usize;

            let mut rng_bytes = vec![0u8; rng_len];
            file.read_exact(&mut rng_bytes)
                .expect("Failed to read state from file");

            let mut layers_bytes = vec![0u8; layers_len];
            file.read_exact(&mut layers_bytes)
                .expect("Failed to read state from file");

            let mut pks_bytes = vec![0u8; pks_len];
            file.read_exact(&mut pks_bytes)
                .expect("Failed to read state from file");

            let rng: CsPrng = bincode::deserialize(&rng_bytes).expect("!");

            let layers =
                bincode::deserialize::<KeyLayers<T, TREE_HASH_SIZE>>(&layers_bytes).expect("!");
            let pks = bincode::deserialize::<
                HashSet<(UnixTimestamp, u8, <Self as BlockSignerTrait>::PublicKey)>,
            >(&pks_bytes)
            .expect("!");

            assert_eq!(self.rng, rng);
            assert_eq!(self.layers, layers);
            assert_eq!(self.pks, pks);
        }
    }

    fn load_state(&mut self) -> bool {
        let filepath = format!("{}/{}", config::ID_DIR, config::ID_FILENAME);
        debug!("Trying to load the state from '{filepath}'...");
        let mut file = match File::open(&filepath) {
            Ok(x) => x,
            Err(_) => {
                return false;
            }
        };

        let rng_len = file.read_u64::<LittleEndian>().expect("!") as usize;
        let layers_len = file.read_u64::<LittleEndian>().expect("!") as usize;
        let pks_len = file.read_u64::<LittleEndian>().expect("!") as usize;

        let mut rng_bytes = vec![0u8; rng_len];
        file.read_exact(&mut rng_bytes)
            .expect("Failed to read state from file");

        let mut layers_bytes = vec![0u8; layers_len];
        file.read_exact(&mut layers_bytes)
            .expect("Failed to read state from file");

        let mut pks_bytes = vec![0u8; pks_len];
        file.read_exact(&mut pks_bytes)
            .expect("Failed to read state from file");

        let rng: CsPrng = bincode::deserialize(&rng_bytes).expect("!");
        let layers =
            bincode::deserialize::<KeyLayers<T, TREE_HASH_SIZE>>(&layers_bytes).expect("!");
        let pks = bincode::deserialize::<
            HashSet<(UnixTimestamp, u8, <Self as BlockSignerTrait>::PublicKey)>,
        >(&pks_bytes)
        .expect("!");

        self.rng = rng;
        self.layers = layers;
        self.pks = pks;
        info!("An existing ID loaded from '{}'.", filepath);
        true
    }

    fn next_key(
        &mut self,
    ) -> (
        &SecretKey<T, TREE_HASH_SIZE>,
        Vec<KeyWrapper<PublicKey<TREE_HASH_SIZE>>>,
    ) {
        // TODO: Implement
        let pks = vec![
            KeyWrapper::new(self.layers.data[0][0].key.public.clone(), 0),
            KeyWrapper::new(PublicKey::new(&[0_u8; TREE_HASH_SIZE]), 1),
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
        CsPrng: CryptoRng + SeedableRng + RngCore + Serialize + DeserializeOwned + PartialEq + Debug,
        MsgHashFn: Digest + Debug,
        TreeHashFn: Digest + Debug,
    > BlockSignerTrait
    for BlockSigner<
        K,
        TAU,
        TAUPLUS,
        T,
        MSG_HASH_SIZE,
        TREE_HASH_SIZE,
        CsPrng,
        MsgHashFn,
        TreeHashFn,
    >
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
        TreeHashFn,
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

        let mut new_inst = BlockSigner {
            rng,
            layers,
            pks: HashSet::new(),
            _x: PhantomData,
        };

        match Self::load_state(&mut new_inst) {
            true => info!("The existing ID was loaded."),
            false => info!("No existing ID found, creating a new one."),
        };
        new_inst
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

        self.store_state();

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
        CsPrng: CryptoRng + SeedableRng + RngCore + Serialize + DeserializeOwned + PartialEq + Debug,
        MsgHashFn: Digest + Debug,
        TreeHashFn: Digest + Debug,
    > BlockVerifierTrait
    for BlockSigner<
        K,
        TAU,
        TAUPLUS,
        T,
        MSG_HASH_SIZE,
        TREE_HASH_SIZE,
        CsPrng,
        MsgHashFn,
        TreeHashFn,
    >
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
        TreeHashFn,
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

        let mut new_inst = BlockSigner {
            rng,
            layers,
            pks: HashSet::new(),
            _x: PhantomData,
        };
        match Self::load_state(&mut new_inst) {
            true => info!("The existing ID was loaded."),
            false => info!("No existing ID found, creating a new one."),
        };

        debug!(tag: "block_verifier", "{}", new_inst.dump_pks());
        new_inst
    }

    fn verify(&mut self, data: Vec<u8>) -> Result<(Vec<u8>, bool, u64, u64), Error> {
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
            tmp = tmp ^ xxh3_64(pk.key.data.as_ref());
        }
        let hash_pks = tmp;
        let hash_sign = tmp2;

        let valid = Self::Signer::verify(
            &block.data,
            &block.signature,
            &block.pub_keys[config::DUMMY_KEY_IDX].key,
        );

        let k = block.pub_keys.first().expect("!");
        self.pks.insert((utils::unix_ts(), k.layer, k.key.clone()));

        self.store_state();

        debug!(tag: "block_verifier", "{}", self.dump_pks());

        Ok((block.data, valid, hash_sign, hash_pks))
    }
}
