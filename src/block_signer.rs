//!
//! Module for broadcasting the signed data packets.
//!

use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::{create_dir_all, File};
use std::io::Cursor;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::mem::size_of;
use std::time::Duration;
// ---
use crate::common::BlockSignerParams;
use crate::common::MsgVerification;
use crate::common::SeqNum;
use crate::common::VerifyResult;
use crate::constants;
use crate::log_graph;
use crate::traits::IntoFromBytes;
use bincode::{deserialize, serialize};
use byteorder::BigEndian;
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
    last_cerified: UnixTimestamp,
    lifetime: usize,
    cert_count: usize,
}

impl<const T: usize, const N: usize> Display for KeyPairStoreCont<T, N> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} -> {:02} ({:03})",
            utils::shorten(&utils::to_hex(&self.key.public.data), 6),
            //utils::unix_ts_to_string(self.last_cerified),
            self.lifetime,
            self.cert_count
        )
    }
}

///
/// A wrapper for one key that is used for the transporation over a network.
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PubKeyTransportCont<Key: IntoFromBytes> {
    pub key: Key,
    pub layer: u8,
}
impl<Key: IntoFromBytes> PubKeyTransportCont<Key> {
    pub fn new(key: Key, layer: u8) -> Self {
        PubKeyTransportCont { key, layer }
    }
}
impl<Key: IntoFromBytes> IntoFromBytes for PubKeyTransportCont<Key> {
    fn size() -> usize {
        Key::size() + size_of::<u8>()
    }

    fn into_network_bytes(self) -> Vec<u8> {
        let mut bytes_cursor = std::io::Cursor::new(vec![]);

        bytes_cursor.write_u8(self.layer).unwrap();
        bytes_cursor
            .write_all(&self.key.into_network_bytes())
            .unwrap();

        bytes_cursor.into_inner()
    }
    fn from_network_bytes(bytes: Vec<u8>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut reader = std::io::Cursor::new(bytes);

        // Read the layer
        let layer = reader.read_u8().unwrap();

        // Read the rest of bytes as key
        let mut key_bytes = vec![0; Key::size()];
        reader.read_exact(&mut key_bytes).unwrap();
        let key = Key::from_network_bytes(key_bytes).unwrap();

        Ok(PubKeyTransportCont { key, layer })
    }
}

/// Struct holding a data to send with the signature and piggy-backed public keys.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SignedBlock<Signature: Serialize, PublicKey: Serialize + IntoFromBytes> {
    pub data: Vec<u8>,
    pub signature: Signature,
    pub pub_keys: Vec<PubKeyTransportCont<PublicKey>>,
    pub seq: SeqNum,
}

impl<Signature: Serialize, PublicKey: Serialize + IntoFromBytes> SignedBlockTrait
    for SignedBlock<Signature, PublicKey>
{
    fn hash(&self) -> u64 {
        let hash_data = xxh3_64(&self.data);
        let hash_signature = xxh3_64(&serialize(&self.signature).expect(constants::EX_SER));
        let hash_pubkeys = xxh3_64(&serialize(&self.pub_keys).expect(constants::EX_SER));
        hash_data ^ hash_signature ^ hash_pubkeys
    }
}
impl<Signature: Serialize + IntoFromBytes, PublicKey: Serialize + IntoFromBytes> IntoFromBytes
    for SignedBlock<Signature, PublicKey>
{
    fn size() -> usize {
        // We don't know the number of PKs :(
        2 * 8 + 2 * 4 + Signature::size() + PublicKey::size()
    }

    fn into_network_bytes(self) -> Vec<u8> {
        let mut bytes_cursor = std::io::Cursor::new(vec![]);

        // Write the scheme ID
        bytes_cursor.write_u64::<BigEndian>(1 /*TODO*/).unwrap();

        // Write the signature
        bytes_cursor
            .write_all(&self.signature.into_network_bytes())
            .unwrap();

        // Write the sequence number
        bytes_cursor.write_u64::<BigEndian>(self.seq).unwrap();

        // Write the number of public keys
        bytes_cursor
            .write_u32::<BigEndian>(self.pub_keys.len() as u32)
            .unwrap();

        // Write the data size
        bytes_cursor
            .write_u32::<BigEndian>(self.data.len() as u32)
            .unwrap();

        // Write the public keys
        for pk in self.pub_keys {
            bytes_cursor.write_all(&pk.into_network_bytes()).unwrap();
        }

        // Write the data
        bytes_cursor.write_all(&self.data).unwrap();

        bytes_cursor.into_inner()
    }
    fn from_network_bytes(bytes: Vec<u8>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let sig_size = Signature::size();
        let pk_size = PubKeyTransportCont::<PublicKey>::size();
        let bytes_size = bytes.len();

        let mut reader = std::io::Cursor::new(bytes);

        // Read the scheme ID
        let _scheme_id = reader.read_u64::<BigEndian>().unwrap();

        // Read the signature
        let mut sig_bytes = vec![0; sig_size];
        reader.read_exact(&mut sig_bytes).unwrap();
        let signature = Signature::from_network_bytes(sig_bytes).unwrap();

        // Read the sequence number
        let seq = reader.read_u64::<BigEndian>().unwrap();

        // Read the nubmer of public keys
        let pub_key_count = reader.read_u32::<BigEndian>().unwrap();

        // Read the payload size
        let payload_size = reader.read_u32::<BigEndian>().unwrap();

        // Read all the PKs
        let mut pub_keys = vec![];
        for _ in 0..pub_key_count {
            let mut pk_bytes = vec![0; pk_size];
            reader.read_exact(&mut pk_bytes).unwrap();
            let pk = PubKeyTransportCont::from_network_bytes(pk_bytes).unwrap();
            pub_keys.push(pk);
        }

        // Read the rest as the payload
        let mut data = vec![0; payload_size as usize];
        reader.read_exact(&mut data).unwrap();

        assert_eq!(
            reader.position() as usize,
            bytes_size,
            "There must not be any bytes left!"
        );

        Ok(SignedBlock {
            data,
            signature,
            pub_keys,
            seq,
        })
    }
}

#[derive(Serialize, Debug, Deserialize, PartialEq)]
pub struct KeyLayers<const T: usize, const N: usize> {
    /// The key containers in their layers (indices).
    data: Vec<Vec<KeyPairStoreCont<T, N>>>,
    /// List of seq number when the key layer can be used once again (default 0)
    ready_at: Vec<f64>,
    /// The average rate at which this layer signs.
    avg_sign_rate: Vec<f64>,
    /// True if the first sign is to come.
    first_sign: bool,
    /// The number of signs before the layer 0 can be used again
    until_top: usize,
    /// A sequence number of the next block to sign.
    next_seq: SeqNum,
    /// A number of signatures that one keypair can generate.
    key_lifetime: usize,
    /// A number of certificates to keep per layer.
    cert_window: usize,
}

impl<const T: usize, const N: usize> KeyLayers<T, N> {
    pub fn new(
        depth: usize,
        key_lifetime: usize,
        cert_interval: usize,
        avg_sign_rate: Vec<f64>,
    ) -> Self {
        KeyLayers {
            data: vec![vec![]; depth],
            ready_at: vec![0.0; depth],
            avg_sign_rate,
            first_sign: true,
            until_top: 0,
            next_seq: 0,
            key_lifetime,
            cert_window: utils::calc_cert_window(cert_interval),
        }
    }

    /// Returns true if the key on the given layer can be scheduled already.
    fn is_ready(&self, level: usize) -> bool {
        info!(tag: "sender", "{:#?} < {:#?}", self.ready_at[level], self.next_seq);
        self.ready_at[level] < self.next_seq as f64
    }

    fn insert(&mut self, level: usize, keypair: HorstKeypair<T, N>) {
        let key_cont = KeyPairStoreCont {
            key: keypair,
            last_cerified: 0,
            lifetime: self.key_lifetime,
            cert_count: 0,
        };

        self.data[level].push(key_cont);
    }

    ///
    /// Takes the key from the provided layer, updates it and
    /// returns it (also bool indicating that the new key is needed).
    ///
    fn poll(
        &mut self,
        layer: usize,
    ) -> (
        KeyPairStoreCont<T, N>,
        bool,
        Vec<PubKeyTransportCont<PublicKey<N>>>,
    ) {
		let signing_idx = self.cert_window / 2;
        let resulting_key;
        {
			let signing_key = &mut self.data[layer][signing_idx];
            signing_key.lifetime -= 1;
            signing_key.last_cerified = utils::unix_ts();
			let start = utils::start();
            resulting_key = signing_key.clone();
			utils::stop("\t\t\tpoll(): copy key", start);
        }

        let rate = self.avg_sign_rate[layer];
        if rate > 0.0 {
            self.ready_at[layer] += rate;
        }


        //
        // Determine what keys to certify with this key
        //

        let mut pks = vec![];
        // The first keys is the one to use for verification
        pks.push(PubKeyTransportCont::new(
            resulting_key.key.public.clone(),
            layer as u8,
        ));

        // Fill in the rest of pubkeys
        for (l_idx, layer) in self.data.iter_mut().enumerate() {
            for k in layer.iter_mut() {
                // Skip the signing key
                if k.key.public == resulting_key.key.public {
                    continue;
                }
                pks.push(PubKeyTransportCont::new(k.key.public.clone(), l_idx as u8));
                k.cert_count += 1;
            }
        }

        // If this key just died
        let died = if (resulting_key.lifetime) == 0 {
            // Remove it
			let start = utils::start();
            self.data[layer].remove(0);
			utils::stop("\t\t\tpoll(): copy key", start);
            // And indicate that we need a new one
            true
        } else {
            false
        };

        self.first_sign = false;
        (resulting_key, died, pks)
    }
}

impl<const T: usize, const N: usize> Display for KeyLayers<T, N> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mut res = String::new();

        for (l_idx, layer) in self.data.iter().enumerate() {
            res.push_str(&format!("|{:.1}|", self.ready_at[l_idx]));
            for (i, kc) in layer.iter().enumerate() {
                res.push_str(&format!("[{}] {} ", l_idx, kc));
                if i % self.cert_window == (self.cert_window - 1) {
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
    fn new_id(&mut self, petname: String) -> SenderIdentity {
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
        // TODO: Use key pauses

		let start = utils::start();
        // Sample what layer to use
        let mut sign_layer;
        loop {
            sign_layer = if self.layers.first_sign {
                debug!(tag:"sender", "The first ever sign is using layer 0");
                0
            } else {
                self.distr.sample(&mut self.rng)
            };

            if self.layers.is_ready(sign_layer) {
                break;
            }
        }
        debug!(tag:"sender", "Signing with key from the layer {sign_layer}...");
		utils::stop("\t\t\tnext_key(): sampling", start);

		let start = utils::start();
        // Poll the key
        let (signing_key, died, pks) = self.layers.poll(sign_layer);
		utils::stop("\t\t\tnext_key(): poll", start);

		let start = utils::start();
		let new_key = <Self as BlockSignerTrait>::Signer::gen_key_pair(&mut self.rng);
		utils::stop("\t\t\tnext_key(): gen", start);
		let start = utils::start();
        // If needed generate a new key for the given layer
        if died {
            self.layers.insert(
                sign_layer,
                new_key,
            );
        }
		utils::stop("\t\t\tnext_key(): insert", start);

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
        let num_layers = params.key_dist.len();
        info!(tag: "sender",
            "Creating new `BlockSigner` with seed {} and {} layers of keys.",
            params.seed, num_layers
        );

        let (distr, avg_sign_rate) = utils::lifetimes_to_distr(&params.key_dist);

        // Initially populate the layers with keys
        let mut rng = CsPrng::seed_from_u64(params.seed);

        // We generate `cert_interval` keys backward and `cert_interval` keys forward
        let cw_size = utils::calc_cert_window(params.cert_interval);

        let mut layers = KeyLayers::new(
            num_layers,
            params.key_lifetime,
            params.cert_interval,
            avg_sign_rate,
        );
        for l_idx in 0..num_layers {
            // Generate the desired number of keys per layer to forward & backward certify them
            for _ in 0..cw_size {
                layers.insert(l_idx, Self::Signer::gen_key_pair(&mut rng));
            }
        }

        let new_inst = BlockSigner {
            params,
            rng,
            layers,
            pks: PubKeyStore::new(0),
            distr,
            _x: PhantomData,
        };

        debug!(tag: "block_signer", "{}", new_inst.dump_layers());
        new_inst
    }

    fn sign(&mut self, data: Vec<u8>, seq: SeqNum) -> Result<Self::SignedBlock, Error> {
        let start = utils::start();
        let (sk, pub_keys) = self.next_key();
        utils::stop("\t\tBlockSigner::next_key()", start);

		let start = utils::start();
        // Prepare the data to sign in the correct order
        let mut data_to_sign = Cursor::new(vec![]);
        // Write `seq` as a big-endian u64
        data_to_sign.write_u64::<BigEndian>(seq).unwrap();
        data_to_sign
            .write_u32::<BigEndian>(pub_keys.len() as u32)
            .unwrap();
        data_to_sign
            .write_u32::<BigEndian>(data.len() as u32)
            .unwrap();
        // Pubkeys
        for pk in pub_keys.iter() {
            data_to_sign
                .write_all(&pk.clone().into_network_bytes())
                .unwrap();
        }
        // Write the data
        data_to_sign.write_all(&data).unwrap();
        let data_to_sign = data_to_sign.into_inner();

		utils::stop("\t\tBlockSigner::prep to_sign", start);
		let start = utils::start();

        let signature = Self::Signer::sign(&data_to_sign, &sk);
        debug!(tag: "block_signer", "{}", self.dump_layers());
		utils::stop("\t\tBlockSigner::sign()", start);

        #[cfg(feature = "store_state")]
        self.store_state();

        Ok(SignedBlock {
            data,
            signature,
            pub_keys,
            seq,
        })
    }
    fn next_seq(&mut self) -> SeqNum {
        self.layers.next_seq += 1;
        self.layers.next_seq
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
        let cert_int = params.cert_interval;
        let new_inst = BlockSigner {
            params,
            rng: CsPrng::seed_from_u64(0),                  //< Not used
            layers: KeyLayers::new(0, 0, cert_int, vec![]), //< Not used
            pks: PubKeyStore::new(cert_int),
            distr: DiscreteDistribution::new(vec![]), //< Not used
            _x: PhantomData,
        };

        let dump = new_inst.dump_pks();
        debug!(tag: "block_verifier", "{}", dump);
        log_graph!(dump);
        new_inst
    }

    fn verify(&mut self, data: Vec<u8>) -> Result<VerifyResult, Error> {
        let signed_block = match Self::SignedBlock::from_network_bytes(data) {
            Ok(x) => x,
            Err(_) => return Err(Error::new(constants::DESER_FAILED)),
        };
        let hash = signed_block.hash();

        // Prepare binary buffer to verify signature on
        let mut data_to_sign = Cursor::new(vec![]);
        // Write `seq` as a big-endian u64
        data_to_sign
            .write_u64::<BigEndian>(signed_block.seq)
            .unwrap();
        data_to_sign
            .write_u32::<BigEndian>(signed_block.pub_keys.len() as u32)
            .unwrap();
        data_to_sign
            .write_u32::<BigEndian>(signed_block.data.len() as u32)
            .unwrap();
        // Pubkeys
        for pk in signed_block.pub_keys.iter() {
            data_to_sign
                .write_all(&pk.clone().into_network_bytes())
                .unwrap();
        }
        // Write the data
        data_to_sign.write_all(&signed_block.data).unwrap();
        let to_verify = data_to_sign.into_inner();

        // Read the metadata from the message
        let msg = signed_block.data;

        let mut verification = MsgVerification::Unverified; //< By default it's unverified

        // Get the pubkey FROM THE MESSAGE thath this packet SHOULD be signed with
        let verify_hint_key = signed_block.pub_keys.first().expect("Should be there!");

        // Is this the first message from the target sender (we'll put the pubkeys directly to it's identity)?
        let (sender_id, verify_ours) = if let Some((existing_id, _)) =
            self.pks.get_id_cc(&self.params.target_petname)
        {
            trace!(tag: "receiver", "(!) Using the existing ID: {:?} (!)", existing_id.petnames);
            (
                existing_id.clone(),
                self.pks.get_key(&verify_hint_key.key, existing_id),
            )
        } else {
            // Generate the petnamed identity for the target sender
            let new_id = self.new_id(self.params.target_petname.clone());
            info!(tag: "receiver", "(!) Generating a new trusted identity with keys from the first message: {new_id:#?} (!)");

            let new_key =
                StoredPubKey::new_with_identity(verify_hint_key, new_id.clone(), signed_block.seq);

            let x = self.pks.insert_identity_key(new_key, &new_id);

            log_graph!(self.dump_pks());

            // Insert the initial identity node that is the sig
            (new_id.clone(), Some(x))
        };

        // Verify with this pubkey
        if let Some(verify_idx) = verify_ours {
            let key_cont = self
                .pks
                .get_node(verify_idx)
                .expect("Should be set!")
                .clone();

            if Self::Signer::verify(&to_verify, &signed_block.signature, &key_cont.key) {
                trace!(tag: "receiver", "Verified with key: {key_cont:?}");

                verification = MsgVerification::Certified(sender_id.clone());

                // Store all the certified PKs into the graph
                self.pks.store_pks_for_identity(
                    verify_idx,
                    signed_block.pub_keys,
                    &sender_id,
                    signed_block.seq,
                );

                // Handle SCCs & identities
                self.pks.proces_nodes();

                // Check if the key has become the part of the identity
                let key_cont = self
                    .pks
                    .get_node(verify_idx)
                    .expect("Should be set!")
                    .clone();
                if let Some(key_id) = &key_cont.id {
                    if key_id == &sender_id {
                        verification = MsgVerification::Verified(sender_id.clone());
                    }
                }

                // Remove obsoltete keys
                self.pks.prune_graph(&sender_id);
            }
        }

        // Store the state to the disk
        self.store_state();
        log_graph!(self.dump_pks());

        debug!(tag: "receiver", "Processed the message {}.", signed_block.seq);

        Ok(VerifyResult {
            msg,
            seq: signed_block.seq,
            verification,
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    // ---
    use rand_chacha::ChaCha20Rng;
    // ---
    use super::*;
    use crate::horst::HorstSignature;

    const SEED: u64 = 42;

    /// Size of the hashes in a Merkle tree
    const N: usize = 512 / 8;
    /// Number of SK segments in signature
    const K: usize = 32;
    /// Depth of the Merkle tree (without the root layer)
    const TAU: usize = 16;
    type CsPrng = ChaCha20Rng;
    const TAUPLUS: usize = TAU + 1;

    type Signature = HorstSignature<N, K, TAUPLUS>;
    type SigBlock = SignedBlock<Signature, HorstPublicKey<N>>;

    #[test]
    fn test_signed_block_info_from_bytes() {
        // Generate nested random bytes to call Signature::new
        let mut rng = CsPrng::seed_from_u64(SEED);
        let mut data_0 = [0_u8; N];
        rng.fill_bytes(&mut data_0);
        let mut data_1 = data_0.clone();
        data_1.reverse();

        let key_0 = PubKeyTransportCont::new(HorstPublicKey::new(&data_0), 2);
        let key_1 = PubKeyTransportCont::new(HorstPublicKey::new(&data_1), 62);

        let exp_key_0 = key_0.clone();
        let exp_key_1 = key_1.clone();

        // Serialize into network bytes
        let bytes = key_0.into_network_bytes();
        let act_key_0 = PubKeyTransportCont::from_network_bytes(bytes).unwrap();
        let bytes = key_1.into_network_bytes();
        let act_key_1 = PubKeyTransportCont::from_network_bytes(bytes).unwrap();

        assert_eq!(
            act_key_0, exp_key_0,
            "PubKeyTransportCont deserialization failed!"
        );
        assert_eq!(
            act_key_1, exp_key_1,
            "PubKeyTransportCont deserialization failed!"
        );
    }

    #[test]
    fn test_pub_key_transport_cont_info_from_bytes() {
        let mut rng = CsPrng::seed_from_u64(SEED);
        let mut data = [[[0_u8; N]; TAUPLUS]; K];

        for i in 0..K {
            for j in 0..TAUPLUS {
                rng.fill_bytes(&mut data[i][j]);
            }
        }

        let sig = Signature::new(data);

        let mut payload = [0; 10];
        rng.fill_bytes(&mut payload);

        let mut data_0 = [0_u8; N];
        rng.fill_bytes(&mut data_0);
        let key_0 = PubKeyTransportCont::new(HorstPublicKey::new(&data_0), 2);

        let sb = SigBlock {
            data: payload.to_vec(),
            signature: sig,
            pub_keys: vec![key_0],
            seq: 33,
        };
        let exp_sb = sb.clone();

        // Serialize into network bytes
        let bytes = sb.into_network_bytes();
        let act_sb = SigBlock::from_network_bytes(bytes).unwrap();

        assert_eq!(act_sb, exp_sb, "SignedBlock deserialization failed!");
    }
}
