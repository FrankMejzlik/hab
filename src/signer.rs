use std::fmt::Debug;
use std::vec::Vec;
// ---
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha3::Digest;

pub struct SignedBlock {
    pub data: Vec<u8>,
    pub sign: Vec<u8>,
    pub keys: Vec<u8>,
}

impl SignedBlock {
    pub fn new(data: Vec<u8>, sign: Vec<u8>, keys: Vec<u8>) -> Self {
        SignedBlock { data, sign, keys }
    }
}

pub trait Key
where
    Self: Sized,
{
    fn new() -> Self
    where
        Self: Sized;
    fn data(&self) -> &[u8];
}

pub trait PrivateKey
where
    Self: Debug + Key,
{
    fn is_private(&self) -> bool {
        true
    }
    fn is_public(&self) -> bool {
        !self.is_private()
    }
}

pub trait PublicKey
where
    Self: Debug + Key,
{
    fn is_private(&self) -> bool {
        false
    }
    fn is_public(&self) -> bool {
        !self.is_private()
    }
}

pub trait Signer<
    GLargeHash: Digest,
    GSmallHash: Digest,
    GPrivateKey: PrivateKey,
    GPublicKey: PublicKey,
    GCsrng: CryptoRng + SeedableRng + RngCore,
>
{
    fn new(seed: u64) -> Self;
    fn sign(&self, msg: &[u8], priv_key: GPrivateKey) -> SignedBlock;
    fn verify(&self, signature: &[u8], pub_key: GPublicKey) -> bool;
    fn gen_key_pair(&self) -> (GPrivateKey, GPublicKey);
}
