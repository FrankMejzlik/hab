use std::vec::Vec;
// ---
use sha3::Digest;
// ---
use crate::signer::{PrivateKey, PublicKey, Signer};

pub struct LamportSigner {}

impl Signer for LamportSigner {
    fn new(_short_hash: impl Digest, _long_hash: impl Digest) -> Self {
        LamportSigner {}
    }

    fn sign(_msg: &[u8], _priv_key: Box<dyn PrivateKey>) -> Vec<u8> {
        vec![]
    }

    fn check(_signature: &[u8], _pub_key: Box<dyn PublicKey>) -> Vec<u8> {
        vec![]
    }
}
