//!
//! Module defining the general interfaces.
//!

use std::error::Error as ErrorTrait;
use std::fmt::Debug;
// ---
use crate::block_signer::SignedBlock;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha3::Digest;
// ---
use crate::common::{BlockSignerParams, Error, ReceivedMessage, SeqType, VerifyResult};

///
/// Global trait bound specifications.
///
/// This is a workaround with defining a new trait with supertraits.
/// Once the trait aliases are in stable rust, it can be used instread:
/// https://github.com/rust-lang/rust/issues/41517
///

pub trait Key {
    fn data(&self) -> &[u8];
}

/// The trait bounds we appply on a `PublicKey` generic type.

pub trait PublicKeyBounds:
    Debug + Clone + PartialEq + Eq + PartialOrd + Ord + IntoFromBytes + Key
{
}
// ----------------------------------

///
/// Provides a high-level interface for broadcasting the signed data to the subscribed receivers.
///
/// # See
/// * `trait ReceiverTrait`
///
pub trait SenderTrait {
    fn broadcast(&mut self, data: Vec<u8>) -> Result<(), Error>;
}

///
/// Provides a high-level interface for receiving the signed data from the desired source sender.
///
/// # See
/// * `trait SenderTrait`
///
pub trait ReceiverTrait {
    fn receive(&mut self) -> Result<ReceivedMessage, Error>;
    /// Ignores the next `count` incomming pieces.
    fn ignore_next(&mut self, count: usize);
}

pub trait SignedBlockTrait {
    //fn new(data: Vec<u8>) -> Self;
    fn hash(&self) -> u64;
}
pub trait IntoFromBytes {
    fn size() -> usize;
    fn into_network_bytes(self) -> Vec<u8>;
    fn from_network_bytes(bytes: Vec<u8>) -> Result<Self, Error>
    where
        Self: Sized;
}

///
/// A high-level interface for signing the block of data and receiving the block of data
/// that is safe to be transfered via insecure channel (e.g. Internet).  
/// The authenticity and integrity of the data can be verified using the matching public
/// key (e.g. using a struct implementing `BlockVerifierTrait`).
///
/// Such interface needs some signature scheme to work. Such scheme can be for example `SignatureSchemeTrait`.
///
/// The counterpart inteface to this is a receiver one - `BlockVerifierTrait`.
///
/// # See also
/// `SignatureSchemeTrait`
/// `BlockVerifierTrait`
///
pub trait MessageSignerTrait {
    type Error: ErrorTrait;
    type PublicKey: PublicKeyBounds + Serialize + DeserializeOwned;
    type Signature: Serialize + DeserializeOwned + IntoFromBytes;

    fn new(params: BlockSignerParams) -> Self;
    fn sign(
        &mut self,
        message: Vec<u8>,
        seq: SeqType,
    ) -> Result<SignedBlock<Self::Signature, Self::PublicKey>, Error>;
    fn next_seq(&mut self) -> SeqType;
}

///
/// A high-level interface for verifying the signature on the provided block of data.
///
/// Such interface needs some signature scheme to work. Such scheme can be for example `SignatureSchemeTrait`.
/// The counterpart inteface to this is a sender one - `BlockSignerTrait`.
///
/// # See also
/// `SignatureSchemeTrait`
/// `BlockSignerTrait`
///
pub trait MessageVerifierTrait {
    type Error: ErrorTrait;

    fn new(params: BlockSignerParams) -> Self;
    fn verify(&mut self, piece: Vec<u8>) -> Result<VerifyResult, Self::Error>;
}

///
/// An interface for a hash-based signature scheme that can generate key pairs, sign a block of data
/// and also verify the signature of the provided data.
///
/// This can be used by higher-level interfaces that add some additional functionality above it (e.g. hierarchy
/// of key pairs). One such trait is `BlockSignerTrait`.
///
/// # See also
/// `BlockSignerTrait`
///
pub trait FtsSchemeTrait {
    type Error: ErrorTrait;
    type CsPrng: CryptoRng + SeedableRng + RngCore + Serialize + DeserializeOwned;
    type TreeHashFn: Digest;
    type SecretKey: Serialize + DeserializeOwned;
    type PublicKey: PublicKeyBounds + Serialize + DeserializeOwned;
    type Signature: Serialize + DeserializeOwned + IntoFromBytes;
    //type SignedMessage: SignedBlockTrait + Serialize + DeserializeOwned + IntoFromBytes;

    ///
    /// Checks the configured parameters. It is recommended to do the chceck during the initialization.
    ///
    /// For example that the size of the hash function output matches the declared hash size.
    fn check_params() -> bool;
    fn verify(msg: &[u8], signature: &Self::Signature, pub_key: &Self::PublicKey) -> bool;
    fn sign(msg: &[u8], secret_key: &Self::SecretKey) -> Self::Signature;
    fn gen_key_pair(rng: &mut Self::CsPrng) -> KeyPair<Self::SecretKey, Self::PublicKey>;
}

///
/// Provides an interface for broadcasting the data blocks to the subscribed
/// receivers over the computer network.
///
pub trait NetworkSenderTrait {
    type Error: ErrorTrait;

    ///
    /// Sends the provided data to the currently subscribed receivers.
    ///
    fn broadcast(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}

pub trait NetworkReceiverTrait {
    type Error: ErrorTrait;

    ///
    /// Blocks until some signed blocks are received.
    ///
    fn receive(&mut self) -> Result<Vec<u8>, Self::Error>;
}

///
/// Interface for sending out the diagnostic data via WebSocket API.
///
pub trait DiagServerTrait {
    type Error: ErrorTrait;

    /// Sends the JSON representation of the current state of the application.
    fn send_state(&mut self, data: &str) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyPair<GSecretKey, GPublicKey> {
    pub secret: GSecretKey,
    pub public: GPublicKey,
}

impl<GSecretKey, GPublicKey> KeyPair<GSecretKey, GPublicKey> {
    pub fn new(secret: GSecretKey, public: GPublicKey) -> Self {
        KeyPair { secret, public }
    }
}
