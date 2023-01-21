//!
//! Module for broadcasting the signed data packets.
//!

// ---
use bincode::serialize;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use sha3::Digest;
// ---
use crate::horst::{HorstKeypair, HorstPublicKey, HorstSecretKey, HorstSigScheme, HorstSignature};
use crate::signer_keystore::*;

#[derive(Debug)]
pub enum BlockSignerError {
    FailedToSign(String),
}

/// Struct holding parameters for the sender.
pub struct BlockSignerParams {
    pub seed: u64,
}

/// Struct holding a data to send with the signature and piggy-backed public keys.
#[derive(Debug)]
pub struct SignedBlock<Signature: Serialize, PublicKey: Serialize> {
    pub data: Vec<u8>,
    pub signature: Signature,
    pub pub_keys: Vec<PublicKey>,
}
impl<Signature: Serialize, PublicKey: Serialize> SignedBlock<Signature, PublicKey> {
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(&self).unwrap()
    }
}

impl<Signature: Serialize, PublicKey: Serialize> Serialize for SignedBlock<Signature, PublicKey> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("SignedBlock", 3)?;
        state.serialize_field("data", &self.data)?;
        state.serialize_field("signature", &self.signature)?;
        state.serialize_field("pub_keys", &self.pub_keys)?;
        state.end()
    }
}

pub struct BlockSigner<
    const N: usize,
    const K: usize,
    const TAU: usize,
    const TAUPLUS: usize,
    const T: usize,
    const MSG_HASH_SIZE: usize,
    const TREE_HASH_SIZE: usize,
    CsPrng: CryptoRng + SeedableRng + RngCore,
    MsgHashFn: Digest,
    TreeHashFn: Digest,
> {
    keystore: SignerKeystore<
        N,
        K,
        TAU,
        TAUPLUS,
        T,
        MSG_HASH_SIZE,
        TREE_HASH_SIZE,
        CsPrng,
        MsgHashFn,
        TreeHashFn,
    >,
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
    BlockSigner<N, K, TAU, TAUPLUS, T, MSG_HASH_SIZE, TREE_HASH_SIZE, CsPrng, MsgHashFn, TreeHash>
{
    /// Constructs and initializes a block signer with the given parameters.
    pub fn new(params: BlockSignerParams) -> Self {
        let keystore_params = SignerKeystoreParams { seed: params.seed };
        let keystore = SignerKeystore::new(keystore_params);
        BlockSigner { keystore }
    }

    pub fn sign(
        &mut self,
        data: &[u8],
    ) -> Result<SignedBlock<Signature<N, K, TAUPLUS>, PublicKey<N>>, BlockSignerError> {
        let pub_keys = vec![PublicKey::new(&[0_u8; N])];
        let signature = Signature::new([[[0_u8; N]; TAUPLUS]; K]);

        Ok(SignedBlock {
            data: data.to_vec(),
            signature,
            pub_keys,
        })
    }
}
