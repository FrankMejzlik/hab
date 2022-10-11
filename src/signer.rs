use std::boxed::Box;
use std::fmt::Debug;
// ---
use sha3::Digest;

pub trait Key {
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

pub trait Signer {
    fn new(short_hash: impl Digest, long_hash: impl Digest) -> Self;
    fn sign(msg: &[u8], priv_key: Box<dyn PrivateKey>) -> Vec<u8>;
    fn check(signature: &[u8], pub_key: Box<dyn PublicKey>) -> Vec<u8>;
}
