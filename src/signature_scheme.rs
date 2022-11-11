// ---
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha3::Digest;

pub struct KeyPair<GSecretKey, GPublicKey> {
    pub secret: GSecretKey,
    pub public: GPublicKey,
}

pub trait SignatureScheme<
    const N: usize,
    const K: usize,
    const TAU: usize,
    CsPrng: CryptoRng + SeedableRng + RngCore,
    MsgHashFn: Digest,
    TreeHash: Digest,
>
{
    type CsPrng: CryptoRng + SeedableRng + RngCore;
    type MsgHashFn: Digest;
    type TreeHash: Digest;
    type SecretKey;
    type PublicKey;
    type Signature;

    type MsgHashBlock;
    type SkHashBlock;
    type TreeHashBlock;

    fn new(seed: u64) -> Self;
    fn verify(msg: &[u8], signature: &Self::Signature, pub_key: &Self::PublicKey) -> bool;
    // ---
    fn sign(&mut self, msg: &[u8]) -> Self::Signature;
    fn gen_key_pair(&mut self) -> KeyPair<Self::SecretKey, Self::PublicKey>;
    // ---
    fn secret_key(&self) -> Option<&Self::SecretKey>;
    fn public_key(&self) -> Option<&Self::PublicKey>;
}
