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
//! * `TreeHashFn` - `F: {0, 1}* -> {0, 1}^{K * log_2(T)}`
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
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
// ---
use crate::common::Error;
use hex::encode;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha3::Digest;
// ---
use crate::merkle_tree::MerkleTree;
use crate::traits::{FtsSchemeTrait, IntoFromBytes, Key, KeyPair, PublicKeyBounds};
use crate::utils;

impl<const T: usize, const N: usize> Display for KeyPair<HorstSecretKey<T, N>, HorstPublicKey<N>> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "\n--- SECRET ---\n{}\n--- PUBLIC ---\n{}",
            self.secret, self.public
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HorstSecretKey<const T: usize, const N: usize> {
    data: Vec<Vec<u8>>,
    tree: Box<MerkleTree<N>>,
}
impl<const T: usize, const N: usize> HorstSecretKey<T, N> {
    fn new<TreeHash: Digest, CsPrng: CryptoRng + SeedableRng + RngCore>(rng: &mut CsPrng) -> Self {
        let start = utils::start();

        // Allocate the memory
        let mut data = vec![
            unsafe {
                let mut v = Vec::with_capacity(N);
                v.set_len(N);
                v
            };
            T
        ];

        utils::stop("\t\t\t\tSK(): alloc", start);
        let start = utils::start();
        // Generate the key
        for block in data.iter_mut() {
            rng.fill_bytes(block);
        }
        utils::stop("\t\t\t\tnext_key(): gen", start);

        // Pregenerate the tree
        let start = utils::start();
        let tree = Box::new(MerkleTree::new::<TreeHash>(&data));
        utils::stop("\t\t\t\tSK(): tree", start);

        HorstSecretKey { data, tree }
    }

    fn get(&self, idx: usize) -> [u8; N] {
        self.data[idx]
            .as_slice()
            .try_into()
            .expect("The size should be `N`!")
    }
}

impl<const T: usize, const N: usize> Display for HorstSecretKey<T, N> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "<<< HorstSecretKey >>>")?;
        writeln!(f, "\t[{:0>5}]: {}", 0, encode(self.data[0].clone()))?;
        writeln!(f, "\t[{:0>5}]: {}", 1, encode(self.data[1].clone()))?;
        writeln!(f, "\t...")?;
        writeln!(f, "\t[{:0>5}]: {}", T - 2, utils::to_hex(&self.data[T - 2]))?;
        writeln!(f, "\t[{:0>5}]: {}", T - 1, utils::to_hex(&self.data[T - 1]))?;

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct HorstPublicKey<const N: usize> {
    pub data: Vec<u8>,
}

impl<const N: usize> IntoFromBytes for HorstPublicKey<N> {
    fn size() -> usize {
        N
    }

    fn into_network_bytes(self) -> Vec<u8> {
        self.data.clone()
    }

    fn from_network_bytes(bytes: Vec<u8>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if bytes.len() != N {
            return Err(Error::new("Invalid public key size!"));
        }
        Ok(HorstPublicKey { data: bytes })
    }
}

impl<const N: usize> Key for HorstPublicKey<N> {
    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> PublicKeyBounds for HorstPublicKey<N> {}
impl<const N: usize> HorstPublicKey<N> {
    pub fn new(root_hash: &[u8; N]) -> Self {
        let mut data = vec![0u8; N];
        data.copy_from_slice(root_hash);

        HorstPublicKey { data }
    }
}
impl<const N: usize> Display for HorstPublicKey<N> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", utils::shorten(&utils::to_hex(&self.data), 10))
    }
}

impl<const N: usize> fmt::Debug for HorstPublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", utils::shorten(&utils::to_hex(&self.data), 4))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HorstSignature<const N: usize, const K: usize, const TAUPLUS: usize> {
    pub data: Vec<Vec<Vec<u8>>>,
}

impl<const N: usize, const K: usize, const TAUPLUS: usize> IntoFromBytes
    for HorstSignature<N, K, TAUPLUS>
{
    fn size() -> usize {
        K * TAUPLUS * N
    }

    fn into_network_bytes(self) -> Vec<u8> {
        // For self.data write to a buffer
        let mut buffer = vec![];
        for i in 0..K {
            for j in 0..TAUPLUS {
                buffer.extend_from_slice(&self.data[i][j]);
            }
        }
        buffer
    }
    fn from_network_bytes(bytes: Vec<u8>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        // From `bytes` parse into multidimensional vectors as in `self.data`
        if bytes.len() != K * TAUPLUS * N {
            return Err(Error::new("Invalid signature size!"));
        }
        let mut data = vec![];
        data.reserve(K);
        for i in 0..K {
            let mut data_i = vec![];
            data_i.reserve(TAUPLUS);
            for j in 0..TAUPLUS {
                let mut data_ij = vec![];
                data_ij.reserve(N);
                for k in 0..N {
                    data_ij.push(bytes[i * (TAUPLUS * N) + j * N + k]);
                }
                data_i.push(data_ij);
            }
            data.push(data_i);
        }

        Ok(HorstSignature { data })
    }
}

impl<const N: usize, const K: usize, const TAUPLUS: usize> HorstSignature<N, K, TAUPLUS> {
    pub fn new(data: [[[u8; N]; TAUPLUS]; K]) -> Self {
        // TODO: Reimplement using e.g. `ndarray` crate
        let mut vec = vec![];
        vec.reserve(K);

        for x in data {
            let mut vx = vec![];
            vx.reserve(TAUPLUS);
            for y in x {
                vx.push(y.to_vec());
            }
            vec.push(vx);
        }
        HorstSignature { data: vec }
    }
}

impl<const N: usize, const K: usize, const TAUPLUS: usize> Display
    for HorstSignature<N, K, TAUPLUS>
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "<<< HorstSignature >>>")?;

        for (i, segment) in self.data.iter().enumerate() {
            for (j, s) in segment.iter().enumerate() {
                if j == 0 {
                    writeln!(f, "[SK_{}] => \t {}", i, utils::to_hex(s))?;
                } else {
                    writeln!(f, "\t[{:0>5}] => \t {}", j - 1, utils::to_hex(s))?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct HorstSigScheme<
    const N: usize,
    const K: usize,
    const TAU: usize,
    const TAUPLUS: usize,
    const T: usize,
    const KEY_CHARGES: usize,
    CsPrng: CryptoRng + SeedableRng + RngCore + Serialize + DeserializeOwned,
    TreeHashFn: Digest,
> {
    // To determine the type variance: https://stackoverflow.com/a/71276732
    _p: PhantomData<(CsPrng, TreeHashFn)>,
}

impl<
        const N: usize,
        const K: usize,
        const TAU: usize,
        const TAUPLUS: usize,
        const T: usize,
        const KEY_CHARGES: usize,
        CsPrng: CryptoRng + SeedableRng + RngCore + Serialize + DeserializeOwned,
        TreeHashFn: Digest,
    > HorstSigScheme<N, K, TAU, TAUPLUS, T, KEY_CHARGES, CsPrng, TreeHashFn>
{
}

impl<
        const N: usize,
        const K: usize,
        const TAU: usize,
        const TAUPLUS: usize,
        const T: usize,
        const KEY_CHARGES: usize,
        CsPrng: CryptoRng + SeedableRng + RngCore + Serialize + DeserializeOwned,
        TreeHashFn: Digest,
    > FtsSchemeTrait for HorstSigScheme<N, K, TAU, TAUPLUS, T, KEY_CHARGES, CsPrng, TreeHashFn>
{
    type Error = Error;
    type CsPrng = CsPrng;
    type TreeHashFn = TreeHashFn;
    type SecretKey = HorstSecretKey<T, N>;
    type PublicKey = HorstPublicKey<N>;
    type Signature = HorstSignature<N, K, TAUPLUS>;

    fn check_params() -> bool {
        println!("{N}, {}", <TreeHashFn as Digest>::output_size());
        if N != <TreeHashFn as Digest>::output_size() {
            error!("The parameters do not match the size of a message hash function output!");
            return false;
        }

        if N != <TreeHashFn as Digest>::output_size() {
            error!("The parameter do not match the size of the a tree hash function output!");
            return false;
        }

        if TAU > 64 {
            error!("The TAU parameter must be at most 64. Because we want to use at most 64-bit indices to the segments.");
            return false;
        }

        if (N * 8) % TAU != 0 {
            error!("The bit output size of the message hash function must be multiple of TAU because we will divide it into segments of TAU-bit length.");
            return false;
        };

        true
    }

    fn sign(msg: &[u8], secret_key: &Self::SecretKey) -> Self::Signature {
        let mut msg_hash = [0; N];
        msg_hash.copy_from_slice(&Self::TreeHashFn::digest(msg)[..N]);

        let tree = secret_key.tree.as_ref();

        let mut signature = [[[0_u8; N]; TAUPLUS]; K];

        // Get segment indices
        let indices = utils::get_segment_indices::<K, N, TAU>(&msg_hash);
        // debug!("indices: {:?}", indices);

        for (i, c_i) in indices.into_iter().enumerate() {
            let mut element = [[0_u8; N]; TAUPLUS];
            let sk_c_i = secret_key.get(c_i);
            let auth = tree.get_auth_path(c_i);
            assert_eq!(auth.len(), TAU, "Wrong size of auth path!");

            element[0] = sk_c_i;
            element[1..].copy_from_slice(&auth[..TAU]);

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
        let mut msg_hash = [0; N];
        msg_hash.copy_from_slice(&Self::TreeHashFn::digest(msg)[..N]);

        // Get segment indices
        let indices = utils::get_segment_indices::<K, N, TAU>(&msg_hash);
        // debug!("indices: {:?}", indices);

        for (i, segment) in signature.data.iter().enumerate() {
            let mut idx = indices[i];

            // TODO: How to initialize
            let mut parent_hash = Self::TreeHashFn::digest(b"");
            for (j, s) in segment.iter().enumerate() {
                // SK
                if j == 0 {
                    // Hash the secret segment
                    parent_hash = Self::TreeHashFn::digest(s);
                }
                // Auth path
                else {
                    let auth_is_left = (idx % 2) == 1;
                    let mut hasher = Self::TreeHashFn::new();

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
            let act_root = &parent_hash.as_slice()[..N];
            if act_root != pk.data {
                return false;
            }
        }

        true
    }

    // ---

    fn gen_key_pair(rng: &mut Self::CsPrng) -> KeyPair<Self::SecretKey, Self::PublicKey> {
        let sk = Self::SecretKey::new::<Self::TreeHashFn, Self::CsPrng>(rng);
        let pk = Self::PublicKey::new(sk.tree.root());

        KeyPair::new(sk, pk)
    }

    fn key_charges() -> usize {
        KEY_CHARGES
    }
}
#[cfg(test)]
mod tests {

    use std::println as debug;
    // ---
    use rand_chacha::ChaCha20Rng;
    use sha3::Sha3_512;
    // ---
    use super::*;

    const SEED: u64 = 42;

    /// Size of the hashes in a Merkle tree
    //const N: usize = 512 / 8;
    /// Number of SK segments in signature
    const K: usize = 32;
    /// Depth of the Merkle tree (without the root layer)
    const TAU: usize = 16;

    // --- Random generators ---
    /// A seedable CSPRNG used for number generation
    type CsPrng = ChaCha20Rng;
    const KEY_CHARGES: usize = 10;

    // --- Hash functions ---
    type TreeHashFn = Sha3_512;

    // ---

    const TAUPLUS: usize = TAU + 1;
    const T: usize = 2_usize.pow(TAU as u32);
    const N: usize = (K * TAU) / 8;

    type Signer = HorstSigScheme<N, K, TAU, TAUPLUS, T, KEY_CHARGES, CsPrng, TreeHashFn>;

    type Signature = HorstSignature<N, K, TAUPLUS>;

    #[test]
    fn test_horst_sign_verify() {
        let msg = b"Hello, world!";

        assert!(Signer::check_params(), "Invalid `Signer` parameters!");

        let mut rng = CsPrng::seed_from_u64(SEED);
        //
        // Alice signs
        //
        let alice_key_pair = Signer::gen_key_pair(&mut rng);
        let alice_sign = Signer::sign(msg, &alice_key_pair.secret);

        //
        // Eve attacker signs
        //
        let eve_key_pair = Signer::gen_key_pair(&mut rng);
        let eve_sign = Signer::sign(msg, &eve_key_pair.secret);

        //
        // Bob verifies
        //
        let bob_from_alice_valid = Signer::verify(msg, &alice_sign, &alice_key_pair.public);
        debug!("Valid signature check's result: {}", bob_from_alice_valid);
        assert!(bob_from_alice_valid, "The valid signature was rejected!");

        let bob_from_eve_valid = Signer::verify(msg, &eve_sign, &alice_key_pair.public);
        debug!("Invalid signature check's result: {}", bob_from_eve_valid);
        assert!(!bob_from_eve_valid, "The invalid signature was accepted!");
    }

    #[test]
    fn test_info_from_bytes() {
        // Generate nested random bytes to call Signature::new
        let mut rng = CsPrng::seed_from_u64(SEED);
        let mut data = [[[0_u8; N]; TAUPLUS]; K];

        for i in 0..K {
            for j in 0..TAUPLUS {
                rng.fill_bytes(&mut data[i][j]);
            }
        }

        let sig = Signature::new(data);
        let exp_sig = sig.clone();

        // Serialize into network bytes
        let bytes = sig.into_network_bytes();
        let act_sig = Signature::from_network_bytes(bytes).unwrap();

        assert_eq!(exp_sig, act_sig, "Signature deserialization failed!");
    }
}
