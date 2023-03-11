//!
//! Module for broadcasting the signed data packets.
//!

use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::marker::PhantomData;
// ---
use crate::common::BlockSignerParams;
use crate::common::MsgMetadata;
use crate::common::MsgVerification;
use crate::common::VerifyResult;
use crate::constants;
use crate::log_graph;
use bincode::{deserialize, serialize};
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use core::fmt::Debug;
use petgraph::dot::Config;
use petgraph::dot::Dot;
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
use crate::traits::{BlockSignerTrait, BlockVerifierTrait, SignatureSchemeTrait, SignedBlockTrait};
use crate::utils;
use crate::utils::UnixTimestamp;
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

///
/// A wrapper for one key that the sender manages in it's store.
///
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct KeyPairStoreCont<const T: usize, const N: usize> {
    key: HorstKeypair<T, N>,
    #[allow(dead_code)]
    last_cerified: UnixTimestamp,
    #[allow(dead_code)]
    signs: usize,
    #[allow(dead_code)]
    lifetime: usize,
}

impl<const T: usize, const N: usize> Display for KeyPairStoreCont<T, N> {
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

///
/// A wrapper for one key that is used for the transporation over a network.
///
#[derive(Debug, Serialize, Deserialize)]
pub struct PubKeyTransportCont<Key> {
    pub key: Key,
    pub layer: u8,
}
impl<Key> PubKeyTransportCont<Key> {
    pub fn new(key: Key, layer: u8) -> Self {
        PubKeyTransportCont { key, layer }
    }
}

/// Struct holding a data to send with the signature and piggy-backed public keys.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedBlock<Signature: Serialize, PublicKey: Serialize> {
    pub data: Vec<u8>,
    pub signature: Signature,
    pub pub_keys: Vec<PubKeyTransportCont<PublicKey>>,
}

impl<Signature: Serialize, PublicKey: Serialize> SignedBlockTrait
    for SignedBlock<Signature, PublicKey>
{
    fn hash(&self) -> u64 {
        let hash_data = xxh3_64(&self.data);
        let hash_signature = xxh3_64(&serialize(&self.signature).expect(constants::EX_SER));
        let hash_pubkeys = xxh3_64(&serialize(&self.pub_keys).expect(constants::EX_SER));
        hash_data ^ hash_signature ^ hash_pubkeys
    }
}

#[derive(Serialize, Debug, Deserialize, PartialEq)]
pub struct KeyLayers<const T: usize, const N: usize> {
    /// The key containers in their layers (indices).
    data: Vec<Vec<KeyPairStoreCont<T, N>>>,
    /// True if the first sign is to come.
    first_sign: bool,
    /// The number of signs before the layer 0 can be used again
    until_top: usize,
    /// A sequence number of the next block to sign.
    next_seq: u64,
    /// A number of signatures that one keypair can generate.
    key_lifetime: usize,
}

impl<const T: usize, const N: usize> KeyLayers<T, N> {
    pub fn new(depth: usize, key_lifetime: usize) -> Self {
        KeyLayers {
            data: vec![vec![]; depth],
            first_sign: true,
            until_top: 0,
            next_seq: 0,
            key_lifetime,
        }
    }

    fn insert(&mut self, level: usize, keypair: HorstKeypair<T, N>) {
        let key_cont = KeyPairStoreCont {
            key: keypair,
            last_cerified: 0,
            signs: 0,
            lifetime: self.key_lifetime,
        };

        self.data[level].push(key_cont);
    }

    /// Takes the key from the provided layer, updates it and
    /// returns it (also bool indicating that the new key is needed).
    fn poll(&mut self, layer: usize) -> (KeyPairStoreCont<T, N>, bool) {
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
    params: BlockSignerParams,
    rng: CsPrng,
    layers: KeyLayers<T, TREE_HASH_SIZE>,
    pks: PubKeyStore<<Self as BlockSignerTrait>::PublicKey>,
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
    ///
    /// Reads the additional data in the message and returns it along with the clean message.
    ///
    fn read_metadata(mut msg: Vec<u8>) -> (MsgMetadata, Vec<u8>) {
        let len = msg.len() - std::mem::size_of::<usize>();

        let seq = usize::from_le_bytes(
            msg[len..]
                .try_into()
                .expect("Should have a correct length!"),
        );
        debug!("seq: {seq}");
        msg.drain(len..);
        (MsgMetadata { seq }, msg)
    }

    fn new_id(&mut self, petname: Option<String>) -> SenderIdentity {
        let id = SenderIdentity::new(self.pks.next_id, petname);
        self.pks.next_id += 1;
        id
    }

    ///
    /// Pretty-prints the structure holding public keys.
    ///
    fn dump_pks(&self) -> String {
        format!(
            "{:?}",
            Dot::with_config(&self.pks.graph, &[Config::EdgeNoLabel])
        )

        // let mut res = String::new();
        // res.push_str("=== RECEIVER: Public keys ===\n");
        // for (id, key_set) in self.pks.keys.iter() {
        //     res.push_str(&format!("--- IDENTITY: {id:?} ---"));
        //     for pk in key_set.iter() {
        //         res.push_str(&format!(
        //             "\t[{}]\t{} -> | {} |\n",
        //             pk.layer,
        //             pk.key,
        //             utils::unix_ts_to_string(pk.received)
        //         ));
        //     }
        // }
        // res
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

    fn store_state(&mut self) {
        create_dir_all(&self.params.id_dir).expect("!");
        let filepath = format!("{}/{}", self.params.id_dir, self.params.id_filename);
        {
            let mut file = File::create(filepath).expect("The file should be writable!");

            let rng_bytes = serialize(&self.rng).expect("!");
            let layers_bytes = serialize(&self.layers).expect("!");
            let pks_bytes = serialize(&self.pks).expect("!");
            let distr_bytes = serialize(&self.distr).expect("!");
            let config_bytes = serialize(&self.params).expect("!");

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
            let filepath = format!("{}/{}", self.params.id_dir, self.params.id_filename);
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

            let rng: CsPrng = deserialize(&rng_bytes).expect("!");

            let layers = deserialize::<KeyLayers<T, TREE_HASH_SIZE>>(&layers_bytes).expect("!");
            let _pks =
                deserialize::<PubKeyStore<HorstPublicKey<TREE_HASH_SIZE>>>(&pks_bytes).expect("!");
            let distr: DiscreteDistribution = deserialize(&distr_bytes).expect("!");
            let config: BlockSignerParams = deserialize(&config_bytes).expect("!");

            assert_eq!(self.rng, rng);
            assert_eq!(self.layers, layers);
            //assert_eq!(self.pks, pks);
            assert_eq!(self.distr, distr);
            assert_eq!(self.params, config);
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

        let rng: CsPrng = deserialize(&rng_bytes).expect("!");
        let layers = deserialize::<KeyLayers<T, TREE_HASH_SIZE>>(&layers_bytes).expect("!");
        let pks =
            deserialize::<PubKeyStore<HorstPublicKey<TREE_HASH_SIZE>>>(&pks_bytes).expect("!");
        let distr: DiscreteDistribution = deserialize(&distr_bytes).expect("!");
        let params: BlockSignerParams = deserialize(&config_bytes).expect("!");

        info!("An existing ID loaded from '{}'.", filepath);
        Some(Self {
            params,
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
        SecretKey<T, TREE_HASH_SIZE>,
        Vec<PubKeyTransportCont<PublicKey<TREE_HASH_SIZE>>>,
    ) {
        // TODO: Detect the first sign to use only level 0
        // TODO: Restrict level 0 to be used at maximum rate

        // Send all public keys
        let mut pks = vec![];
        for (l_idx, layer) in self.layers.data.iter().enumerate() {
            for k in layer.iter() {
                pks.push(PubKeyTransportCont::new(k.key.public.clone(), l_idx as u8));
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
    fn new(params: BlockSignerParams) -> Self {
        // Try to load the identity from the disk
        match Self::load_state(&format!("{}/{}", params.id_dir, params.id_filename)) {
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
        let mut layers = KeyLayers::new(params.layers, params.key_lifetime);
        for l_idx in 0..params.layers {
            // Two key at all times on all layers
            layers.insert(l_idx, Self::Signer::gen_key_pair(&mut rng));
            layers.insert(l_idx, Self::Signer::gen_key_pair(&mut rng));
        }

        let new_inst = BlockSigner {
            params,
            rng,
            layers,
            pks: PubKeyStore::new(),
            distr,
            _x: PhantomData,
        };

        debug!(tag: "block_signer", "{}", new_inst.dump_layers());
        new_inst
    }

    fn sign(&mut self, data: Vec<u8>) -> Result<Self::SignedBlock, Error> {
        let (sk, pub_keys) = self.next_key();

        // Append the piggy-backed pubkeys to the payload
        let mut data_to_sign = data.clone();
        data_to_sign.append(&mut serialize(&pub_keys).expect(constants::EX_SER));

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
    fn new(params: BlockSignerParams) -> Self {
        // Try to load the identity from the disk
        match Self::load_state(&format!("{}/{}", params.id_dir, params.id_filename)) {
            Some(mut x) => {
                info!(tag: "receiver", "The existing ID was loaded.");
                debug!(tag: "block_verifier", "{}", x.dump_layers());
                // (!)
                x.params.target_petname = params.target_petname;
                // (!)
                return x;
            }
            None => info!(tag: "receiver", "No existing ID found, creating a new one."),
        };
        info!(tag: "receiver", "Creating new `BlockVerifier`.");

        let new_inst = BlockSigner {
            params,
            rng: CsPrng::seed_from_u64(0), //< Not used
            layers: KeyLayers::new(0, 0),  //< Not used
            pks: PubKeyStore::new(),
            distr: DiscreteDistribution::new(vec![]), //< Not used
            _x: PhantomData,
        };

        let dump = new_inst.dump_pks();
        debug!(tag: "block_verifier", "{}", dump);
        log_graph!(dump);
        new_inst
    }

    fn verify(&mut self, data: Vec<u8>) -> Result<VerifyResult, Error> {
        let signed_block: Self::SignedBlock = deserialize(&data).expect(constants::EX_DESER);
        let hash = signed_block.hash();

        // Signature MUST be verified also with public keys attached
        let mut to_verify = signed_block.data.clone();
        to_verify.append(&mut serialize(&signed_block.pub_keys).expect(constants::EX_SER));

        // Is this the first message from the target sender (we'll put the pubkeys directly to it's identity)?
        let all_to_identity = if let Some(old_id) = self.pks.get_id_cc(&self.params.target_petname)
        {
            info!(tag: "receiver", "(!) Using the existing ID: {:?} (!)", old_id.0.petname);
            self.pks.set_target_id(old_id.0.clone());
            false
        } else {
            // Generate the petnamed identity for the target sender
            let new_id = self.new_id(Some(self.params.target_petname.clone()));
            info!(tag: "receiver", "(!) Generating a new trusted identity with keys from the first message: {new_id:#?} (!)");
            self.pks.set_target_id(new_id);
            true
        };

        let sender_id = self
            .pks
            .get_target_id()
            .expect("The target sender should be already set!");

        let mut verification = if all_to_identity {
            MsgVerification::Verified(sender_id.clone())
        } else {
            MsgVerification::Unverified //< By default it's unverified
        };

        let mut certificating_key_idx = None;
        // Iterate over all keys that have been certified by the target sender
        for (v_idx, key_cont) in self.pks.target_keys_iter() {
            // Verify with this pubkey
            if Self::Signer::verify(&to_verify, &signed_block.signature, &key_cont.key) {
                assert!(
                    key_cont.certified_by.contains(&sender_id),
                    "The target sender should have already certified this key."
                );
                trace!(tag: "receiver", "Verified with key: {key_cont:?}");

                verification = MsgVerification::Certified(sender_id.clone());
                certificating_key_idx = Some(v_idx);

                // Is this the matching identity node?
                if let Some(x) = key_cont.id.clone() {
                    if x == sender_id {
                        verification = MsgVerification::Verified(sender_id.clone());
                    }
                }
                break;
            }
        }
        assert!(!(certificating_key_idx.is_some() && all_to_identity), "Cannot be first message from the target identity and verified message at the same time!");

        // If the message was verified with at least certified key
        if certificating_key_idx.is_some() {
            // Store all the certified public keys under the target identity
            for kw in signed_block.pub_keys.iter() {
                // Get a key to store
                let key_to_store = StoredPubKey::new_with_certified(kw, sender_id.clone());

                // Insert the key to the graph
                self.pks.insert_key(
                    certificating_key_idx.expect("Should be some."),
                    key_to_store,
                );
            }
        }
        // If the first message we put all the keys into the identity
        else if all_to_identity {
            let mut id_keys = vec![];
            for kw in signed_block.pub_keys {
                id_keys.push(StoredPubKey::new_with_identity(&kw, sender_id.clone()));
            }
            self.pks.insert_identity_keys(id_keys);
        }

        self.store_state();
        let dump = self.dump_pks();
        debug!(tag: "block_verifier", "{}", dump);
        log_graph!(dump);

        // Read the metadata from the message
        let (metadata, msg) = Self::read_metadata(signed_block.data);

        Ok(VerifyResult {
            msg,
            metadata,
            verification,
            hash,
        })
    }
}
