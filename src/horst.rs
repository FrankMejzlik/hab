use std::boxed::Box;
use std::fmt::{Display, Formatter, Result};
// ---
use hex::encode;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha3::{Keccak256, Keccak512};
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
/// * H: {0, 1}* -> {0, 1}^{K * log_2(T)}
/// A hash function for hasing a message of arbitrary length.
///
/// ### `ImplSecretKeyHashFn`
/// * F: {0, 1}^N -> {0, 1}^N
/// A hash function for hasing a secret key numbers to their public counterparts.
///
/// ### `ImplMerkleHashFn`
/// * F: {0, 1}^{2 * N} -> {0, 1}^N
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
/// # of SK numbers / leaf nodes in Merkle tree
const T: usize = 2_usize.pow(TAU as u32);
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

const MSG_HASH_SIZE: usize = K * TAU;
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
    fn new() -> Self {
        let data = [[[0_u8; TREE_HASH_SIZE]; TAU + 1]; K];
        HorstSignature { data }
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
        let rng = Self::CsRng::seed_from_u64(seed);
        HorstSigScheme {
            rng,
            secret: None,
            tree: None,
            public: None,
        }
    }

    fn sign(&mut self, _msg: &[u8]) -> HorstSignature {
        HorstSignature::new()
    }

    fn verify(_signature: &Self::Signature, _pk: &HorstPublicKey) -> bool {
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
