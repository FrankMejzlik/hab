use std::boxed::Box;
use std::fmt::{Display, Formatter, Result};
// ---
use hex::encode;
use log::debug;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha3::{Digest, Keccak256, Keccak512};
// ---
use crate::box_array;
use crate::merkle_tree::MerkleTree;
use crate::signature_scheme::{KeyPair, SignatureScheme};
use crate::utils;

///
/// HORS with trees
///
/// # Parameters
/// `N` - The output size of a Merkle tree hash function.
/// `T` - Number of SK numbers / number of leaf nodes in Merkle tree
/// `K` - Number of segments in each signature
///
/// ## Hash functions
/// ### `ImplMessageHashFn`
/// * F: {0, 1}* -> {0, 1}^{K * log_2(T)}
/// A hash function for hasing a message of arbitrary length.
///
/// ### `ImplSecretKeyHashFn`
/// * G: {0, 1}^N -> {0, 1}^N
/// A hash function for hasing a secret key numbers to their public counterparts.
///
/// ### `ImplMerkleHashFn`
/// * H: {0, 1}^{2 * N} -> {0, 1}^N
/// A hash function for hasing a concatenation of two child hashes into the parent one
/// in the Merkle tree.
///
/// ## Random generators
/// ### `ImplCsPrng`
/// Cryptographically safe pseudorandom number generator.
///

/// ***************************************
///             PARAMETERS
/// ***************************************
/// Security parameter
const N: usize = 256 / 8;
const TAU: usize = 16;
/// # of SK segments revealed in a signature
const K: usize = 32;

// --- Hash functions ---
type ImplMessageHashFn = Keccak512;
type ImplSecretKeyHashFn = Keccak256;
type ImplMerkleHashFn = Keccak256;

// --- Random generators ---
/// A seedable CSPRNG used for number generation
type ImplCsPrng = ChaCha20Rng;

/// ***************************************
///           INFERED PARAMETERS
/// ***************************************
type ImplSecretKey = HorstSecretKey;
type ImplPublicKey = HorstPublicKey;

/// # of SK numbers / leaf nodes in Merkle tree
const T: usize = 2_usize.pow(TAU as u32);

const MSG_HASH_SIZE: usize = (K * TAU) / 8;
const SK_HASH_SIZE: usize = N;
const TREE_HASH_SIZE: usize = N;

type MsgHashBlock = [u8; MSG_HASH_SIZE];
type SkHashBlock = [u8; SK_HASH_SIZE];
type TreeHashBlock = [u8; TREE_HASH_SIZE];

impl Display for KeyPair<ImplSecretKey, ImplPublicKey> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        writeln!(
            f,
            "\n--- SECRET ---\n{}\n--- PUBLIC ---\n{}",
            self.secret, self.public
        )
    }
}

#[derive(Debug, Clone)]
pub struct HorstSecretKey {
    data: Box<[SkHashBlock; T]>,
}
impl HorstSecretKey {
    fn new(rng: &mut ImplCsPrng) -> Self {
        // Allocate the memory
        let mut data = box_array![[0u8; SK_HASH_SIZE]; T];

        // Generate the key
        for block in data.iter_mut() {
            rng.fill_bytes(block);
        }

        HorstSecretKey { data }
    }

    fn get(&self, idx: usize) -> SkHashBlock {
        self.data[idx]
    }
}

impl Display for HorstSecretKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
        writeln!(f, "<<< HorstSecretKey >>>")?;
        writeln!(f, "\t[{:0>5}]: {}", 0, encode(&self.data[0]))?;
        writeln!(f, "\t[{:0>5}]: {}", 1, encode(&self.data[1]))?;
        writeln!(f, "\t...")?;
        writeln!(f, "\t[{:0>5}]: {}", T - 2, utils::to_hex(&self.data[T - 2]))?;
        writeln!(f, "\t[{:0>5}]: {}", T - 1, utils::to_hex(&self.data[T - 1]))?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct HorstPublicKey {
    data: Box<TreeHashBlock>,
}
impl HorstPublicKey {
    fn new(root_hash: &[u8; TREE_HASH_SIZE]) -> Self {
        let mut data = Box::new([0u8; TREE_HASH_SIZE]);
        data.copy_from_slice(root_hash);

        HorstPublicKey { data }
    }
}
impl Display for HorstPublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
        writeln!(
            f,
            "<<< HorstPublicKey >>>\n\t[00000]: {}",
            utils::to_hex(&*self.data)
        )
    }
}

#[derive(Debug, Clone)]
pub struct HorstSignature {
    data: [[TreeHashBlock; TAU + 1]; K],
}
impl HorstSignature {
    fn new(data: [[TreeHashBlock; TAU + 1]; K]) -> Self {
        HorstSignature { data }
    }
}

impl IntoIterator for HorstSignature {
    type Item = [[u8; TREE_HASH_SIZE]; TAU + 1];
    type IntoIter = HorstSignatureIntoIterator;

    fn into_iter(self) -> Self::IntoIter {
        HorstSignatureIntoIterator {
            cont: self,
            index: 0,
        }
    }
}

pub struct HorstSignatureIntoIterator {
    cont: HorstSignature,
    index: usize,
}

impl Iterator for HorstSignatureIntoIterator {
    type Item = [TreeHashBlock; TAU + 1];
    fn next(&mut self) -> Option<Self::Item> {
        let result = self.cont.data[self.index];
        self.index += 1;
        Some(result)
    }
}

impl Display for HorstSignature {
    fn fmt(&self, f: &mut Formatter) -> Result {
        writeln!(f, "<<< HorstSignature >>>")?;

        for (i, segment) in self.data.into_iter().enumerate() {
            for (j, s) in segment.into_iter().enumerate() {
                if j == 0 {
                    writeln!(f, "[SK_{}] => \t {}", i, utils::to_hex(&s))?;
                } else {
                    writeln!(f, "\t[{:0>5}] => \t {}", j - 1, utils::to_hex(&s))?;
                }
            }
        }

        Ok(())
    }
}

pub struct HorstSigScheme {
    rng: <HorstSigScheme as SignatureScheme>::CsRng,
    secret: Option<HorstSecretKey>,
    tree: Option<MerkleTree<TREE_HASH_SIZE>>,
    public: Option<HorstPublicKey>,
}

impl HorstSigScheme {}

impl SignatureScheme for HorstSigScheme {
    type CsRng = ImplCsPrng;
    type MsgHashFn = ImplMessageHashFn;
    type KeyHashFn = ImplSecretKeyHashFn;
    type TreeHash = ImplMerkleHashFn;
    type SecretKey = ImplSecretKey;
    type PublicKey = ImplPublicKey;
    type Signature = HorstSignature;

    fn new(seed: u64) -> Self {
        // TODO: Check the matching sizes of hashes and parameters
        assert!(TAU < 64, "TAU must be less than 64 bits.");

        assert!(
            (MSG_HASH_SIZE * 8) % TAU == 0,
            "The output size of a message hash function must be multiple of TAU"
        );

        let rng = Self::CsRng::seed_from_u64(seed);
        HorstSigScheme {
            rng,
            secret: None,
            tree: None,
            public: None,
        }
    }

    fn sign(&mut self, msg: &[u8]) -> HorstSignature {
        let mut msg_hash = [0; MSG_HASH_SIZE];
        msg_hash.copy_from_slice(&Self::MsgHashFn::digest(msg)[..MSG_HASH_SIZE]);

        let tree = self.tree.as_ref().unwrap();
        let sk = self.secret.as_ref().unwrap();

        let mut signature = [[[0_u8; TREE_HASH_SIZE]; TAU + 1]; K];

        // Get segment indices
        let indices = utils::get_segment_indices::<K, MSG_HASH_SIZE, TAU>(&msg_hash);
        debug!("indices: {:?}", indices);

        for (i, c_i) in indices.into_iter().enumerate() {
            let mut element = [[0_u8; TREE_HASH_SIZE]; TAU + 1];
            let sk_c_i = sk.get(c_i);
            let auth = tree.get_auth_path(c_i);
            assert_eq!(auth.len(), TAU, "Wrong size of auth path!");

            element[0] = sk_c_i;
            (&mut element[1..]).copy_from_slice(&auth[..TAU]);

            signature[i] = element;
        }
        assert_eq!(
            signature.len(),
            K,
            "Signature has a wrong number of elements!"
        );

        HorstSignature::new(signature)
    }

    fn verify(msg: &[u8], signature: &HorstSignature, pk: &HorstPublicKey) -> bool {
        // Hash the message
        let mut msg_hash: MsgHashBlock = [0; MSG_HASH_SIZE];
        msg_hash.copy_from_slice(&Self::MsgHashFn::digest(msg)[..MSG_HASH_SIZE]);

        // Get segment indices
        let indices = utils::get_segment_indices::<K, MSG_HASH_SIZE, TAU>(&msg_hash);
        debug!("indices: {:?}", indices);

        for (i, segment) in signature.data.into_iter().enumerate() {
            let mut idx = indices[i];

            // TODO: How to initialize
            let mut parent_hash = Self::TreeHash::digest(b"");
            for (j, s) in segment.into_iter().enumerate() {
                // SK
                if j == 0 {
                    // Hash the secret segment
                    parent_hash = Self::KeyHashFn::digest(s);
                }
                // Auth path
                else {
                    let auth_is_left = (idx % 2) == 1;
                    let mut hasher = Self::TreeHash::new();

                    if auth_is_left {
                        hasher.update(s);
                        hasher.update(parent_hash);
                    } else {
                        hasher.update(parent_hash);
                        hasher.update(s);
                    }
                    parent_hash = hasher.finalize();
                    idx /= 2;
                }
            }

            // Check the equality with the PK
            let act_root = &parent_hash.as_slice()[..TREE_HASH_SIZE];
            if act_root != *pk.data {
                debug!(
                    "{}\n\tvs\n {}",
                    utils::to_hex(act_root),
                    utils::to_hex(&*pk.data)
                );
                return false;
            }
        }

        true
    }

    // ---

    fn gen_key_pair(&mut self) -> KeyPair<HorstSecretKey, HorstPublicKey> {
        let sk = HorstSecretKey::new(&mut self.rng);
        let tree = MerkleTree::new::<Self::TreeHash>(sk.data.to_vec());
        let pk = HorstPublicKey::new(tree.root());

        // Update the Merkle tree for this SK
        self.tree = Some(tree);
        self.secret = Some(sk.clone());
        self.public = Some(pk.clone());

        KeyPair {
            secret: sk,
            public: pk,
        }
    }

    // ---

    fn secret_key(&self) -> Option<&HorstSecretKey> {
        self.secret.as_ref()
    }
    fn public_key(&self) -> Option<&HorstPublicKey> {
        self.public.as_ref()
    }
}
