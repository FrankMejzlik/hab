//!
//! Module for broadcasting the signed data packets.
//!

use std::collections::BTreeSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::mem::swap;
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
use crate::common::SenderIdentity;
use crate::horst::HorstPublicKey;
pub use crate::horst::{
    HorstKeypair, HorstPublicKey as PublicKey, HorstSecretKey as SecretKey, HorstSigScheme,
    HorstSignature as Signature,
};
use crate::pub_key_store::PubKeyStore;
use crate::pub_key_store::StoredPubKey;
use crate::traits::BlockSignerParams;
use crate::traits::BlockVerifierParams;
use crate::traits::Config;
use crate::traits::SignedBlockTrait;
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
            "{} -> | {} | {:02} |",
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

/// Struct holding a data to send with the signature and piggy-backed public keys.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedBlock<Signature: Serialize, PublicKey: Serialize> {
    pub data: Vec<u8>,
    pub signature: Signature,
    pub pub_keys: Vec<KeyWrapper<PublicKey>>,
}

impl<Signature: Serialize, PublicKey: Serialize> SignedBlockTrait
    for SignedBlock<Signature, PublicKey>
{
    fn hash(&self) -> u64 {
        let hash_data = xxh3_64(&self.data);
        let hash_signature =
            xxh3_64(&bincode::serialize(&self.signature).expect("Should be serializable!"));
        let hash_pubkeys =
            xxh3_64(&bincode::serialize(&self.pub_keys).expect("Should be serializable!"));
        hash_data ^ hash_signature ^ hash_pubkeys
    }
}

#[derive(Serialize, Debug, Deserialize, PartialEq)]
struct KeyLayers<const T: usize, const N: usize> {
    /// The key containers in their layers (indices).
    data: Vec<Vec<KeyCont<T, N>>>,
    /// True if the first sign is to come.
    first_sign: bool,
    /// The number of signs before the layer 0 can be used again
    until_top: usize,
    /// A sequence number of the next block to sign.
    next_seq: u64,
}

impl<const T: usize, const N: usize> KeyLayers<T, N> {
    pub fn new(depth: usize) -> Self {
        KeyLayers {
            data: vec![vec![]; depth],
            first_sign: true,
            until_top: 0,
            next_seq: 0,
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

    /// Takes the key from the provided layer, updates it and
    /// returns it (also bool indicating that the new key is needed).
    fn poll(&mut self, layer: usize) -> (KeyCont<T, N>, bool) {
        let resulting_key;
        {
            let signing_key = self.data[layer]
                .first_mut()
                .expect("At least one key per layer must be there!");
            signing_key.signs += 1;
            signing_key.last_cerified = utils::unix_ts();
            resulting_key = signing_key.clone();
        }

        // If this key just died
        let died = if (resulting_key.lifetime - resulting_key.signs) == 0 {
            // Remove it
            self.data[layer].remove(0);
            // And indicate that we need a new one
            true
        } else {
            false
        };

        self.first_sign = false;
        (resulting_key, died)
    }
}

impl<const T: usize, const N: usize> Display for KeyLayers<T, N> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mut res = String::new();

        for (l_idx, layer) in self.data.iter().enumerate() {
            for (i, kc) in layer.iter().enumerate() {
                res.push_str(&format!("[{}] {} ", l_idx, kc));
                if i % 2 == 1 {
                    res.push('\n')
                } else {
                    res.push_str("++ ");
                }
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
    pks: PubKeyStore<<Self as BlockSignerTrait>::PublicKey>,
    distr: DiscreteDistribution,
    config: Config,
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
    fn new_id(&mut self) -> SenderIdentity {
        let id = SenderIdentity { id: self.pks.next_id };
        self.pks.next_id +=1;
        id
    }

    ///
    /// Pretty-prints the structure holding public keys.
    ///
    fn dump_pks(&self) -> String {
        let mut res = String::new();
        res.push_str("=== RECEIVER: Public keys ===\n");
        for (id, key_set) in self.pks.keys.iter() {
            res.push_str(&format!("--- IDENTITY: {id:?} ---"));
            for pk in key_set.iter() {
                res.push_str(&format!(
                    "\t[{}]\t{} -> | {} |\n",
                    pk.layer,
                    pk.key,
                    utils::unix_ts_to_string(pk.received)
                ));
            }
        }
        res
    }

    ///
    /// Pretty-prints the structure holding private keys for signing.
    ///
    fn dump_layers(&self) -> String {
        let mut res = String::new();
        res.push_str("=== SENDER: Secret & public keys ===\n");
        res.push_str(&format!("{}", self.layers));
        res
    }

    ///
    /// Searches the provided layer if there is more than provided keys and deletes the ones
    /// with the earliest timestamp.
    ///
    fn prune_pks(&mut self, _max_per_layer: usize) {


		
        // // Copy all key-timestamp pairs from the given layer
        // let mut from_layer = vec![];
        // for (k, (ts, level)) in self.pks.iter() {
        //     let missing = std::cmp::max(0, (*level as i64 + 1) - from_layer.len() as i64);
        //     for _ in 0..missing {
        //         from_layer.push(vec![]);
        //     }

        //     from_layer[*level as usize].push((k.clone(), *ts));
        // }

        // for layer_items in from_layer.iter_mut() {
        //     // Sort them by timestamp
        //     layer_items.sort_by_key(|x| x.1);

        //     // Remove the excessive keys
        //     for item in layer_items
        //         .iter()
        //         .take(std::cmp::max(0, layer_items.len() as i32 - max_per_layer as i32) as usize)
        //     {
        //         self.pks.remove(&item.0);
        //     }
        // }
    }

    fn store_state(&mut self) {
        create_dir_all(&self.config.id_dir).expect("!");
        let filepath = format!("{}/{}", self.config.id_dir, self.config.id_filename);
        {
            let mut file = File::create(filepath).expect("The file should be writable!");

            let rng_bytes = bincode::serialize(&self.rng).expect("!");
            let layers_bytes = bincode::serialize(&self.layers).expect("!");
            let pks_bytes = bincode::serialize(&self.pks).expect("!");
            let distr_bytes = bincode::serialize(&self.distr).expect("!");
            let config_bytes = bincode::serialize(&self.config).expect("!");

            file.write_u64::<LittleEndian>(rng_bytes.len() as u64)
                .expect("!");
            file.write_u64::<LittleEndian>(layers_bytes.len() as u64)
                .expect("!");
            file.write_u64::<LittleEndian>(pks_bytes.len() as u64)
                .expect("!");
            file.write_u64::<LittleEndian>(distr_bytes.len() as u64)
                .expect("!");
            file.write_u64::<LittleEndian>(config_bytes.len() as u64)
                .expect("!");
            file.write_all(&rng_bytes)
                .expect("Failed to write state to file");
            file.write_all(&layers_bytes)
                .expect("Failed to write state to file");
            file.write_all(&pks_bytes)
                .expect("Failed to write state to file");
            file.write_all(&distr_bytes)
                .expect("Failed to write state to file");
            file.write_all(&config_bytes)
                .expect("Failed to write state to file");
        }

        // Check
        {
            let filepath = format!("{}/{}", self.config.id_dir, self.config.id_filename);
            let mut file = File::open(filepath).expect("!");

            let rng_len = file.read_u64::<LittleEndian>().expect("!") as usize;
            let layers_len = file.read_u64::<LittleEndian>().expect("!") as usize;
            let pks_len = file.read_u64::<LittleEndian>().expect("!") as usize;
            let distr_len = file.read_u64::<LittleEndian>().expect("!") as usize;
            let config_len = file.read_u64::<LittleEndian>().expect("!") as usize;

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

            let mut config_bytes = vec![0u8; config_len];
            file.read_exact(&mut config_bytes)
                .expect("Failed to read state from file");

            let rng: CsPrng = bincode::deserialize(&rng_bytes).expect("!");

            let layers =
                bincode::deserialize::<KeyLayers<T, TREE_HASH_SIZE>>(&layers_bytes).expect("!");
            let pks =
                bincode::deserialize::<PubKeyStore<HorstPublicKey<TREE_HASH_SIZE>>>(&pks_bytes)
                    .expect("!");
            let distr: DiscreteDistribution = bincode::deserialize(&distr_bytes).expect("!");
            let config: Config = bincode::deserialize(&config_bytes).expect("!");

            assert_eq!(self.rng, rng);
            assert_eq!(self.layers, layers);
            assert_eq!(self.pks, pks);
            assert_eq!(self.distr, distr);
            assert_eq!(self.config, config);
        }
    }

    fn load_state(filepath: &str) -> Option<Self> {
        debug!("Trying to load the state from '{filepath}'...");
        let mut file = match File::open(filepath) {
            Ok(x) => x,
            Err(_) => return None,
        };

        let rng_len = file.read_u64::<LittleEndian>().expect("!") as usize;
        let layers_len = file.read_u64::<LittleEndian>().expect("!") as usize;
        let pks_len = file.read_u64::<LittleEndian>().expect("!") as usize;
        let distr_len = file.read_u64::<LittleEndian>().expect("!") as usize;
        let config_len = file.read_u64::<LittleEndian>().expect("!") as usize;

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

        let mut config_bytes = vec![0u8; config_len];
        file.read_exact(&mut config_bytes)
            .expect("Failed to read state from file");

        let rng: CsPrng = bincode::deserialize(&rng_bytes).expect("!");
        let layers =
            bincode::deserialize::<KeyLayers<T, TREE_HASH_SIZE>>(&layers_bytes).expect("!");
        let pks = bincode::deserialize::<PubKeyStore<HorstPublicKey<TREE_HASH_SIZE>>>(&pks_bytes)
            .expect("!");
        let distr: DiscreteDistribution = bincode::deserialize(&distr_bytes).expect("!");
        let config: Config = bincode::deserialize(&config_bytes).expect("!");

        info!("An existing ID loaded from '{}'.", filepath);
        Some(Self {
            rng,
            layers,
            pks,
            distr,
            config,
            _x: PhantomData,
        })
    }

    fn next_key(
        &mut self,
    ) -> (
        SecretKey<T, TREE_HASH_SIZE>,
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

        // Sample what layer to use
        let sign_layer = if self.layers.first_sign {
            debug!(tag:"sender", "The first ever sign is using layer 0");
            0
        } else {
            self.distr.sample(&mut self.rng)
        };
        debug!(tag:"sender", "Signing with key from the layer {sign_layer}...");

        // Poll the key
        let (signing_key, died) = self.layers.poll(sign_layer);

        // If needed generate a new key for the given layer
        if died {
            self.layers.insert(
                sign_layer,
                <Self as BlockSignerTrait>::Signer::gen_key_pair(&mut self.rng),
            );
        }

        (signing_key.key.secret, pks)
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

    /// Constructs and initializes a block signer with the given parameters.
    fn new(params: BlockSignerParams, config: Config) -> Self {
        // Try to load the identity from the disk
        match Self::load_state(&format!("{}/{}", config.id_dir, config.id_filename)) {
            Some(x) => {
                info!(tag: "sender", "The existing ID was loaded.");
                debug!(tag: "block_signer", "{}", x.dump_layers());
                return x;
            }
            None => {
                info!(tag: "sender", "No existing ID found, creating a new one.");
            }
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
            pks: PubKeyStore::new(),
            distr,
            config,
            _x: PhantomData,
        };

        debug!(tag: "block_signer", "{}", new_inst.dump_layers());
        new_inst
    }

    fn sign(&mut self, data: Vec<u8>) -> Result<Self::SignedBlock, Error> {
        let (sk, pub_keys) = self.next_key();

        // Append the piggy-backed pubkeys to the payload
        let mut data_to_sign = data.clone();
        data_to_sign.append(&mut bincode::serialize(&pub_keys).expect("Should be serializable!"));

        let signature = Self::Signer::sign(&data_to_sign, &sk);
        debug!(tag: "block_signer", "{}", self.dump_layers());

        self.store_state();

        Ok(SignedBlock {
            data,
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

    /// Constructs and initializes a block signer with the given parameters.
    fn new(_params: BlockVerifierParams, config: Config) -> Self {
        // Try to load the identity from the disk
        match Self::load_state(&format!("{}/{}", config.id_dir, config.id_filename)) {
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
            pks: PubKeyStore::new(),
            distr: DiscreteDistribution::new(vec![]), //< Not used
            config,
            _x: PhantomData,
        };

        debug!(tag: "block_verifier", "{}", new_inst.dump_pks());
        new_inst
    }

    fn verify(&mut self, data: Vec<u8>) -> Result<(Vec<u8>, SenderIdentity, u64, u64), Error> {
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

        let mut to_verify = block.data.clone();
        to_verify
            .append(&mut bincode::serialize(&block.pub_keys).expect("Should be serializable!"));

        // Try to verify with at least one already certified key
        let mut sender_id = None;
		let mut decrypt_pk = None;
        for (id, keys) in self.pks.keys.iter() {
            for stored_key in keys {
                let pk = &stored_key.key;
                let ok = Self::Signer::verify(&to_verify, &block.signature, pk);
                if ok {
					decrypt_pk = Some(pk.clone());
                    sender_id = Some(id.clone());
                    break;
                }
            }
        }

        // If no known identity
        let sender_id = match sender_id {
            Some(x) => x,
            None => {
                let new_id = self.new_id();
                info!(tag: "receiver", "(!) New identity detected: {new_id:#?} (!)");
                self.pks.keys.insert(new_id.clone(), BTreeSet::new());
                new_id
            }
        };

        // Store all the certified public keys
		let mut to_merge = BTreeSet::new();
        for kw in block.pub_keys.iter() {
            // If the key is not yet cached
            let wrapped_key = StoredPubKey {
                key: kw.key.clone(),
                received: utils::unix_ts(),
                layer: kw.layer,
            };

			



            let existing_keys = self.pks.keys.get_mut(&sender_id).expect("Should exist!");
            // Store it
            existing_keys.insert(wrapped_key);
        }

		// -----------------------------------

		// -----------------------------------
		if let Some(x) = decrypt_pk {
			let wrapped_key = StoredPubKey {
				key: x,
				received: utils::unix_ts(),
				layer: 0,
			};

			for (id, key_set) in self.pks.keys.iter_mut() {
				if key_set.contains(&wrapped_key) {
					to_merge.insert(id.clone());
				}
			}
		}
		
		if to_merge.len() > 1 {
			let mut it = to_merge.into_iter();
			let mut fst = it.next().expect("Should be present!");
			let mut snd = it.next().expect("Should be present!");

			// Make sure that we're merging to the lower ID
			if fst.id > snd.id {
				swap(&mut fst, &mut snd)
			}

			info!(tag: "receiver", "(!) Merging identity {} and {} (!)",fst.id, snd.id );

			// To be copied
			let mut existing_keys_snd = self.pks.keys.remove(&snd).expect("Should be there!");
			// Where to be copied
			let existing_keys_fst = self.pks.keys.get_mut(&fst).expect("Should exist!");

			existing_keys_fst.append(&mut existing_keys_snd);
		}
		// ------------------------------------


        // TODO: Delete the oldest PKs if you have at least four of the same level
        self.prune_pks(self.config.max_pks);

        self.store_state();
        debug!(tag: "block_verifier", "{}", self.dump_pks());

        Ok((block.data, sender_id, hash_sign, hash_pks))
    }
}
