use std::boxed::Box;
use std::fmt::Debug;
use std::vec::Vec;
use std::fmt::{Display};
// ---
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha3::Digest;

pub struct KeyPair<GPrivateKey, GPublicKey> {
    pub private: GPrivateKey,
    pub public: GPublicKey,
}

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
    Self: Sized + Display,
{
    type CsRng: CryptoRng + SeedableRng + RngCore;
	type Hash: Digest;
    // ---
    fn new(rng: &mut Self::CsRng) -> Self
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

pub trait SignatureScheme {
    type CsRng: CryptoRng + SeedableRng + RngCore;
    type LargeHash: Digest;
    type SmallHash: Digest;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

    fn new(seed: u64) -> Self;
    fn sign(&mut self, msg: &[u8], priv_key: &Self::PrivateKey) -> Box<SignedBlock>;
    fn verify(&self, signature: &[u8], pub_key: &Self::PublicKey) -> bool;
    fn gen_key_pair(&mut self) -> Box<KeyPair<Self::PrivateKey, Self::PublicKey>>;
}
