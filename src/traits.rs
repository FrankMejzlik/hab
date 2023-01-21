//!
//! Module defining the general interfaces.
//!

use std::error::Error as ErrorTrait;
use std::io::{Read, Write};
// ---
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha3::Digest;

pub trait Error {}

pub struct KeyPair<GSecretKey, GPublicKey> {
    pub secret: GSecretKey,
    pub public: GPublicKey,
}

impl<GSecretKey, GPublicKey> KeyPair<GSecretKey, GPublicKey> {
    fn new(secret: GSecretKey, public: GPublicKey) -> Self {
        KeyPair { secret, public }
    }
}

pub trait SignatureScheme {
    type CsPrng: CryptoRng + SeedableRng + RngCore;
    type MsgHashFn: Digest;
    type TreeHash: Digest;
    type SecretKey;
    type PublicKey;
    type Signature;

    type MsgHashBlock;
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
