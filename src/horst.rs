//!
//! HORS signature scheme with trees (HORST) as proposed in the [SPHINCS scheme](https://sphincs.cr.yp.to/sphincs-20150202.pdf).
//!
//!
//! # Remarks
//! For now, we don't use the masked Merkle tree construction (called SPR-Merkle tree) as used in
//! the [reference implementation](https://link.springer.com/chapter/10.1007/978-3-540-88403-3_8).
//! We use the standard hash tree.
//!
//! # Parameters
//! * `N` - Size of the hashes inside the Merkle tree (and therefore in the signatures and keys).
//! * `K` - Number of secret key segments in each signature (i.e. we're choosing K-sized subsets from a 2^TAU-sized set).
//! * `TAU` - Depth of the Merkle tree / number of bits in the indexing segment in message hash.
//!         The number of leaves in the tree (i.e. number of items in the set we're choosing from) is 2^TAU.
//!
//! ## Hash functions
//! * `MsgHashFn` - `F: {0, 1}* -> {0, 1}^{K * log_2(T)}`
//! A hash function for hasing a message of arbitrary length & hashing the N-bit secrets into N-bit output.
//!     
//!
//! * `TreeHashFn` - `H: {0, 1}^{2 * N} -> {0, 1}^N` AND `G: {0, 1}^N -> {0, 1}^N`
//! A hash function for hasing a concatenation of two child hashes into the parent one in the Merkle tree.
//! -- AND --
//! A hash function for hasing a secret key elements into the Merkle tree leaves.
//!
//! ## Random generators
//! * `ImplCsPrng` - Cryptographically safe pseudo-random number generator.
//!
use std::boxed::Box;
use std::fmt::{Display, Formatter};
// ---
use ::slice_of_array::prelude::*;
use hex::encode;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use sha3::Digest;

// ---
use crate::box_array;
use crate::merkle_tree::MerkleTree;
use crate::signature_scheme::{KeyPair, SignatureScheme};
use crate::utils;

pub type HorstKeypair<const T: usize, const N: usize> =
    KeyPair<HorstSecretKey<T, N>, HorstPublicKey<N>>;

impl<const T: usize, const N: usize> Display for KeyPair<HorstSecretKey<T, N>, HorstPublicKey<N>> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "\n--- SECRET ---\n{}\n--- PUBLIC ---\n{}",
            self.secret, self.public
        )
    }
}

#[derive(Debug, Clone)]
pub struct HorstSecretKey<const T: usize, const TREE_HASH_SIZE: usize> {
    data: Box<[[u8; TREE_HASH_SIZE]; T]>,
}
impl<const T: usize, const TREE_HASH_SIZE: usize> HorstSecretKey<T, TREE_HASH_SIZE> {
    fn new(rng: &mut impl RngCore) -> Self {
        // Allocate the memory
        let mut data = box_array![[0u8; TREE_HASH_SIZE]; T];

        // Generate the key
        for block in data.iter_mut() {
            rng.fill_bytes(block);
            // debug!("{}", utils::to_hex(block));
        }

        HorstSecretKey { data }
    }

    fn get(&self, idx: usize) -> [u8; TREE_HASH_SIZE] {
        self.data[idx]
    }
}

impl<const T: usize, const N: usize> Display for HorstSecretKey<T, N> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
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
pub struct HorstPublicKey<const N: usize> {
    data: Box<[u8; N]>,
}
impl<const N: usize> HorstPublicKey<N> {
    pub fn new(root_hash: &[u8; N]) -> Self {
        let mut data = Box::new([0u8; N]);
        data.copy_from_slice(root_hash);

        HorstPublicKey { data }
    }
}
impl<const N: usize> Display for HorstPublicKey<N> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "<<< HorstPublicKey >>>\n\t[00000]: {}",
            utils::to_hex(&*self.data)
        )
    }
}
impl<const N: usize> Serialize for HorstPublicKey<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("HorstPublicKey", 1)?;
        state.serialize_field("data", self.data.as_slice())?;
        state.end()
    }
}

#[derive(Debug, Clone)]
pub struct HorstSignature<const N: usize, const K: usize, const TAUPLUS: usize> {
    data: [[[u8; N]; TAUPLUS]; K],
}
impl<const N: usize, const K: usize, const TAUPLUS: usize> HorstSignature<N, K, TAUPLUS> {
    pub fn new(data: [[[u8; N]; TAUPLUS]; K]) -> Self {
        HorstSignature { data }
    }
}
impl<const N: usize, const K: usize, const TAUPLUS: usize> Serialize
    for HorstSignature<N, K, TAUPLUS>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("HorstPublicKey", 1)?;
        state.serialize_field("data", self.data.flat().flat())?;
        state.end()
    }
}

impl<const N: usize, const K: usize, const TAUPLUS: usize> Display
    for HorstSignature<N, K, TAUPLUS>
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
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

pub struct HorstSigScheme<
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
> {
    rng: <Self as SignatureScheme<N, K, TAU, CsPrng, MsgHashFn, TreeHash>>::CsPrng,
    secret: Option<HorstSecretKey<T, TREE_HASH_SIZE>>,
    tree: Option<MerkleTree<TREE_HASH_SIZE>>,
    public: Option<HorstPublicKey<TREE_HASH_SIZE>>,
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
    HorstSigScheme<
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
    > SignatureScheme<N, K, TAU, CsPrng, MsgHashFn, TreeHash>
    for HorstSigScheme<
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
    type CsPrng = CsPrng;
    type MsgHashFn = MsgHashFn;
    type TreeHash = TreeHash;
    type SecretKey = HorstSecretKey<T, TREE_HASH_SIZE>;
    type PublicKey = HorstPublicKey<TREE_HASH_SIZE>;
    type Signature = HorstSignature<TREE_HASH_SIZE, K, TAUPLUS>;

    type MsgHashBlock = [u8; MSG_HASH_SIZE];
    type TreeHashBlock = [u8; TREE_HASH_SIZE];

    fn new(seed: u64) -> Self {
        // TODO: Check the matching sizes of hashes and parameters
        assert_eq!(
            MSG_HASH_SIZE,
            <MsgHashFn as Digest>::output_size(),
            "The parameters do not match the size of a message hash function output!"
        );
        assert_eq!(
            TREE_HASH_SIZE,
            <TreeHash as Digest>::output_size(),
            "The parameter do not match the size of the a tree hash function output!"
        );

        assert!(TAU < 64, "TAU must be less than 64 bits.");

        assert!(
            (MSG_HASH_SIZE * 8) % TAU == 0,
            "The output size of a message hash function must be multiple of TAU"
        );

        let rng = Self::CsPrng::seed_from_u64(seed);
        HorstSigScheme {
            rng,
            secret: None,
            tree: None,
            public: None,
        }
    }

    fn sign(&mut self, msg: &[u8]) -> Self::Signature {
        let mut msg_hash = [0; MSG_HASH_SIZE];
        msg_hash.copy_from_slice(&Self::MsgHashFn::digest(msg)[..MSG_HASH_SIZE]);

        let tree = self.tree.as_ref().unwrap();
        let sk = self.secret.as_ref().unwrap();

        let mut signature = [[[0_u8; TREE_HASH_SIZE]; TAUPLUS]; K];

        // Get segment indices
        let indices = utils::get_segment_indices::<K, MSG_HASH_SIZE, TAU>(&msg_hash);
        // debug!("indices: {:?}", indices);

        for (i, c_i) in indices.into_iter().enumerate() {
            let mut element = [[0_u8; TREE_HASH_SIZE]; TAUPLUS];
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

    fn verify(msg: &[u8], signature: &Self::Signature, pk: &Self::PublicKey) -> bool {
        // Hash the message
        let mut msg_hash = [0; MSG_HASH_SIZE];
        msg_hash.copy_from_slice(&Self::MsgHashFn::digest(msg)[..MSG_HASH_SIZE]);

        // Get segment indices
        let indices = utils::get_segment_indices::<K, MSG_HASH_SIZE, TAU>(&msg_hash);
        // debug!("indices: {:?}", indices);

        for (i, segment) in signature.data.into_iter().enumerate() {
            let mut idx = indices[i];

            // TODO: How to initialize
            let mut parent_hash = Self::TreeHash::digest(b"");
            for (j, s) in segment.into_iter().enumerate() {
                // SK
                if j == 0 {
                    // Hash the secret segment
                    parent_hash = Self::TreeHash::digest(s);
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
                return false;
            }
        }

        true
    }

    // ---

    fn gen_key_pair(&mut self) -> KeyPair<Self::SecretKey, Self::PublicKey> {
        let sk = Self::SecretKey::new(&mut self.rng);
        let tree = MerkleTree::new::<Self::TreeHash>(sk.data.to_vec());
        let pk = Self::PublicKey::new(tree.root());

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

    fn secret_key(&self) -> Option<&Self::SecretKey> {
        self.secret.as_ref()
    }
    fn public_key(&self) -> Option<&Self::PublicKey> {
        self.public.as_ref()
    }
}
#[cfg(test)]
mod tests {
    // ---
    use sha3::Digest;
    use std::println as debug;

    // ---
    use super::*;

    // #[test]
    // fn test_horst_sign_verify() {
    //     let msg = b"Hello, world!";

    //     let mut alice_signer = Signer::new(args.seed);
    //     let mut eve_signer = Signer::new(args.seed + 1);

    //     //
    //     // Alice signs
    //     //
    //     let alice_key_pair = alice_signer.gen_key_pair();
    //     debug!("{}", alice_key_pair);
    //     let alice_sign = alice_signer.sign(msg);
    //     //debug!("{}", alice_sign);

    //     //
    //     // Eve attacker signs
    //     //
    //     let _eve_key_pair = eve_signer.gen_key_pair();
    //     //debug!("{}", eve_key_pair);
    //     let eve_sign = eve_signer.sign(msg);
    //     //debug!("{}", eve_sign);

    //     //
    //     // Bob verifies
    //     //
    //     let bob_from_alice_valid = Signer::verify(msg, &alice_sign, &alice_key_pair.public);
    //     assert!(bob_from_alice_valid, "The valid signature was rejected!");

    //     let bob_from_eve_valid = Signer::verify(msg, &eve_sign, &alice_key_pair.public);
    //     assert!(!bob_from_eve_valid, "The invalid signature was accepted!");
    // }
}
