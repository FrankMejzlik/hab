//!
//! Module for broadcasting the signed data packets.
//!

use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::marker::PhantomData;
// ---
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use core::fmt::Debug;
use rand::prelude::Distribution;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::Digest;
use xxhash_rust::xxh3::xxh3_64;
// ---
use crate::common::DiscreteDistribution;
use crate::common::Error;
use crate::config;
pub use crate::horst::{
    HorstKeypair, HorstPublicKey as PublicKey, HorstSecretKey as SecretKey, HorstSigScheme,
    HorstSignature as Signature,
};
use crate::traits::{BlockSignerTrait, BlockVerifierTrait, SignatureSchemeTrait};
use crate::utils;
use crate::utils::UnixTimestamp;
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

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

impl<const T: usize, const N: usize> Display for KeyCont<T, N> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} -> | {} | {} |",
            utils::shorten(&utils::to_hex(&self.key.public.data), 10),
            utils::unix_ts_to_string(self.last_cerified),
            self.lifetime - self.signs,
        )
    }
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
    pub layers: usize,
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

impl<const T: usize, const N: usize> Display for KeyLayers<T, N> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mut res = String::new();

        for (l_idx, layer) in self.data.iter().enumerate() {
            for kc in layer.iter() {
                res.push_str(&format!("\t[{}]\t{}\n", l_idx, kc))
            }
        }

        write!(f, "{}", res)
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
    pks: HashMap<<Self as BlockSignerTrait>::PublicKey, (UnixTimestamp, u8)>,
    distr: DiscreteDistribution,
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
        for (pk, (ts, level)) in self.pks.iter() {
            res.push_str(&format!(
                "\t[{level}]\t{pk} -> | {} |\n",
                utils::unix_ts_to_string(*ts)
            ));
        }
        res
    }

    fn dump_layers(&self) -> String {
        let mut res = String::new();
        res.push_str("=== SENDER: Secret & public keys ===\n");
        res.push_str(&format!("{}", self.layers));
        res
    }

    fn store_state(&mut self) {
        create_dir_all(config::ID_DIR).expect("!");
        let filepath = format!("{}/{}", config::ID_DIR, config::ID_FILENAME);
        {
            let mut file = File::create(filepath).expect("The file should be writable!");

            let rng_bytes = bincode::serialize(&self.rng).expect("!");
            let layers_bytes = bincode::serialize(&self.layers).expect("!");
            let pks_bytes = bincode::serialize(&self.pks).expect("!");
            let distr_bytes = bincode::serialize(&self.distr).expect("!");

            file.write_u64::<LittleEndian>(rng_bytes.len() as u64)
                .expect("!");
            file.write_u64::<LittleEndian>(layers_bytes.len() as u64)
                .expect("!");
            file.write_u64::<LittleEndian>(pks_bytes.len() as u64)
                .expect("!");
            file.write_u64::<LittleEndian>(distr_bytes.len() as u64)
                .expect("!");
            file.write_all(&rng_bytes)
                .expect("Failed to write state to file");
            file.write_all(&layers_bytes)
                .expect("Failed to write state to file");
            file.write_all(&pks_bytes)
                .expect("Failed to write state to file");
            file.write_all(&distr_bytes)
                .expect("Failed to write state to file");
        }

        // Check
        {
            let filepath = format!("{}/{}", config::ID_DIR, config::ID_FILENAME);
            let mut file = File::open(filepath).expect("!");

            let rng_len = file.read_u64::<LittleEndian>().expect("!") as usize;
            let layers_len = file.read_u64::<LittleEndian>().expect("!") as usize;
            let pks_len = file.read_u64::<LittleEndian>().expect("!") as usize;
            let distr_len = file.read_u64::<LittleEndian>().expect("!") as usize;

            let mut rng_bytes = vec![0u8; rng_len];
            file.read_exact(&mut rng_bytes)
                .expect("Failed to read state from file");

            let mut layers_bytes = vec![0u8; layers_len];
            file.read_exact(&mut layers_bytes)
                .expect("Failed to read state from file");

            let mut pks_bytes = vec![0u8; pks_len];
            file.read_exact(&mut pks_bytes)
                .expect("Failed to read state from file");

            let mut distr_bytes = vec![0u8; distr_len];
            file.read_exact(&mut distr_bytes)
                .expect("Failed to read state from file");

            let rng: CsPrng = bincode::deserialize(&rng_bytes).expect("!");

            let layers =
                bincode::deserialize::<KeyLayers<T, TREE_HASH_SIZE>>(&layers_bytes).expect("!");
            let pks = bincode::deserialize::<
                HashMap<<Self as BlockSignerTrait>::PublicKey, (UnixTimestamp, u8)>,
            >(&pks_bytes)
            .expect("!");
            let distr: DiscreteDistribution = bincode::deserialize(&distr_bytes).expect("!");

            assert_eq!(self.rng, rng);
            assert_eq!(self.layers, layers);
            assert_eq!(self.pks, pks);
            assert_eq!(self.distr, distr);
        }
    }

    fn load_state() -> Option<Self> {
        let filepath = format!("{}/{}", config::ID_DIR, config::ID_FILENAME);
        debug!("Trying to load the state from '{filepath}'...");
        let mut file = match File::open(&filepath) {
            Ok(x) => x,
            Err(_) => {
                return None;
            }
        };

        let rng_len = file.read_u64::<LittleEndian>().expect("!") as usize;
        let layers_len = file.read_u64::<LittleEndian>().expect("!") as usize;
        let pks_len = file.read_u64::<LittleEndian>().expect("!") as usize;
        let distr_len = file.read_u64::<LittleEndian>().expect("!") as usize;

        let mut rng_bytes = vec![0u8; rng_len];
        file.read_exact(&mut rng_bytes)
            .expect("Failed to read state from file");

        let mut layers_bytes = vec![0u8; layers_len];
        file.read_exact(&mut layers_bytes)
            .expect("Failed to read state from file");

        let mut pks_bytes = vec![0u8; pks_len];
        file.read_exact(&mut pks_bytes)
            .expect("Failed to read state from file");

        let mut distr_bytes = vec![0u8; distr_len];
        file.read_exact(&mut distr_bytes)
            .expect("Failed to read state from file");

        let rng: CsPrng = bincode::deserialize(&rng_bytes).expect("!");
        let layers =
            bincode::deserialize::<KeyLayers<T, TREE_HASH_SIZE>>(&layers_bytes).expect("!");
        let pks = bincode::deserialize::<
            HashMap<<Self as BlockSignerTrait>::PublicKey, (UnixTimestamp, u8)>,
        >(&pks_bytes)
        .expect("!");
        let distr: DiscreteDistribution = bincode::deserialize(&distr_bytes).expect("!");

        info!("An existing ID loaded from '{}'.", filepath);
        Some(Self {
            rng,
            layers,
            pks,
            distr,
            _x: PhantomData,
        })
    }

    fn next_key(
        &mut self,
    ) -> (
        &SecretKey<T, TREE_HASH_SIZE>,
        Vec<KeyWrapper<PublicKey<TREE_HASH_SIZE>>>,
    ) {
		// TODO: Detect the first sign to use only level 0
		// TODO: Restrict level 0 to be used at maximum rate

        // Send all public keys
        let mut pks = vec![];
        for (l_idx, layer) in self.layers.data.iter().enumerate() {
            for k in layer.iter() {
                pks.push(KeyWrapper::new(k.key.public.clone(), l_idx as u8));
            }
        }

        let sign_layer = self.distr.sample(&mut self.rng);
        debug!(tag:"sender", "Signing with key from the layer {sign_layer}...");
        let signing_key = self.layers.data[sign_layer]
            .first_mut()
            .expect("At least one key per layer must be there!");
        signing_key.signs += 1;
        signing_key.last_cerified = utils::unix_ts();

		// TODO: Remove & replace keys

        (&signing_key.key.secret, pks)
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
        // Try to load the identity from the disk
        match Self::load_state() {
            Some(x) => {
                info!(tag: "sender", "The existing ID was loaded.");
                debug!(tag: "block_signer", "{}", x.dump_layers());
                return x;
            }
            None => info!(tag: "sender", "No existing ID found, creating a new one."),
        };
        info!(tag: "sender",
            "Creating new `BlockSigner` with seed {} and {} layers of keys.",
            params.seed, params.layers
        );

        // Instantiate the probability distribution
        let weights = (0..params.layers)
            .map(|x| 2_f64.powf(x as f64))
            .collect::<Vec<f64>>();
        let distr = DiscreteDistribution::new(weights);

        // Initially populate the layers with keys
        let mut rng = CsPrng::seed_from_u64(params.seed);
        let mut layers = KeyLayers::new(params.layers);
        for l_idx in 0..params.layers {
            // Two key at all times on all layers
            layers.insert(l_idx, Self::Signer::gen_key_pair(&mut rng));
            layers.insert(l_idx, Self::Signer::gen_key_pair(&mut rng));
        }

        let new_inst = BlockSigner {
            rng,
            layers,
            pks: HashMap::new(),
            distr,
            _x: PhantomData,
        };

        debug!(tag: "block_signer", "{}", new_inst.dump_layers());
        new_inst
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::SignedBlock, Error> {
        let (sk, pub_keys) = self.next_key();
        let signature = Self::Signer::sign(data, sk);
        debug!(tag: "block_signer", "{}", self.dump_layers());

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
    fn new(_params: BlockSignerParams) -> Self {
        // Try to load the identity from the disk
        match Self::load_state() {
            Some(x) => {
                info!(tag: "receiver", "The existing ID was loaded.");
                debug!(tag: "block_verifier", "{}", x.dump_layers());
                return x;
            }
            None => info!(tag: "receiver", "No existing ID found, creating a new one."),
        };
        info!(tag: "receiver", "Creating new `BlockVerifier`.");

        let new_inst = BlockSigner {
            rng: CsPrng::seed_from_u64(0), //< Not used
            layers: KeyLayers::new(0),     //< Not used
            pks: HashMap::new(),
            distr: DiscreteDistribution::new(vec![]), //< Not used
            _x: PhantomData,
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
                let h = xxh3_64(y);
                tmp2 ^= h;
            }
        }

        let mut tmp = 0;
        for pk in block.pub_keys.iter() {
            tmp ^= xxh3_64(pk.key.data.as_ref());
        }
        let hash_pks = tmp;
        let hash_sign = tmp2;

        // Try to verify with at least one already certified key
        let mut valid = false;
        for (pk, _) in self.pks.iter() {
            let ok = Self::Signer::verify(&block.data, &block.signature, pk);
            if ok {
                valid = true;
                break;
            }
        }

        // If the signature is valid (or the very first block received), we certify the PKs received
        if valid || self.pks.is_empty() {
            if self.pks.is_empty() {
                info!(tag: "receiver", "(!) Accepting the first received block! (!)");
            }
            // Store all the certified public keys
            for kw in block.pub_keys.iter() {
                // If the key is not yet cached
                if !self.pks.contains_key(&kw.key) {
                    // Store it
                    self.pks
                        .insert(kw.key.clone(), (utils::unix_ts(), kw.layer));
                }
            }
        }

        self.store_state();
        debug!(tag: "block_verifier", "{}", self.dump_pks());

        Ok((block.data, valid, hash_sign, hash_pks))
    }
}
