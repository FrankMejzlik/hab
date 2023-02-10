//!
//! Module defining the general interfaces.
//!

use std::error::Error as ErrorTrait;
use std::io::{Read, Write};
// ---
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha3::Digest;

pub trait Error {}

#[derive(Clone)]
pub struct KeyPair<GSecretKey, GPublicKey> {
    pub secret: GSecretKey,
    pub public: GPublicKey,
}

impl<GSecretKey, GPublicKey> KeyPair<GSecretKey, GPublicKey> {
    pub fn new(secret: GSecretKey, public: GPublicKey) -> Self {
        KeyPair { secret, public }
    }
}

pub trait BlockSignerTrait {
    type Error: ErrorTrait;
    type Signer: SignatureSchemeTrait;
    type BlockSignerParams;
    type SecretKey;
    type PublicKey;
    type Signature;
    type SignedBlock;

    fn new(params: Self::BlockSignerParams) -> Self;
    fn sign(&mut self, data: &[u8]) -> Result<Self::SignedBlock, Self::Error>;
}

pub trait SignatureSchemeTrait {
    type CsPrng: CryptoRng + SeedableRng + RngCore;
    type MsgHashFn: Digest;
    type TreeHash: Digest;
    type SecretKey;
    type PublicKey;
    type Signature;

    type MsgHashBlock;
    type TreeHashBlock;

    fn new() -> Self;
    fn verify(msg: &[u8], signature: &Self::Signature, pub_key: &Self::PublicKey) -> bool;
    fn sign(msg: &[u8], secret_key: &Self::SecretKey) -> Self::Signature;
    fn gen_key_pair(rng: &mut Self::CsPrng) -> KeyPair<Self::SecretKey, Self::PublicKey>;
}

///
/// Provides an interface for broadcasting the data blocks to the subscribed
/// receivers over the computer network.
///
pub trait NetworkSender {
    type Error: ErrorTrait;

    ///
    /// Sends the provided data to the currently subscribed receivers.
    ///
    fn broadcast(&self, data: &[u8]) -> Result<(), Self::Error>;
}

///
/// Provides a high-level interface for broadcasting the signed data to the subscribed receivers.
///
/// # See
/// * `trait ReceiverTrait`
///
pub trait SenderTrait {
    fn run(&mut self, input: &dyn Read);
}

///
/// Provides a high-level interface for receiving the signed data from the desired source sender.
///
/// # See
/// * `trait SenderTrait`
///
pub trait ReceiverTrait {
    fn run(&mut self, output: &dyn Write);
}

///
/// Interface for sending out the diagnostic data via WebSocket API.
///
pub trait DiagServerTrait {
    type Error: ErrorTrait;

    /// Sends the JSON representation of the current state of the application.
    fn send_state(&mut self, data: &str) -> Result<(), Self::Error>;
}
