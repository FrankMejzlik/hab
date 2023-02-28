//!
//! The main module providing high-level API for the receiver of the data.
//!

use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

// ---
use crate::common::{Error, ReceivedBlock, SenderIdentity};
use crate::net_receiver::{NetReceiver, NetReceiverParams};
use crate::traits::{BlockVerifierParams, BlockVerifierTrait, Config, ReceiverTrait};
use xxhash_rust::xxh3::xxh3_64;
// ---
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct ReceiverParams {
    pub addr: String,
    pub running: Arc<AtomicBool>,
}

pub struct Receiver<BlockVerifier: BlockVerifierTrait> {
    #[allow(dead_code)]
    params: ReceiverParams,
    verifier: BlockVerifier,
    net_receiver: NetReceiver,
}

impl<BlockVerifier: BlockVerifierTrait> Receiver<BlockVerifier> {
    pub fn new(params: ReceiverParams, config: Config) -> Self {
        let block_signer_params = BlockVerifierParams {};
        let verifier = BlockVerifier::new(block_signer_params, config.clone());

        let net_recv_params = NetReceiverParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
        };
        let net_receiver = NetReceiver::new(net_recv_params, config);

        Receiver {
            params,
            verifier,
            net_receiver,
        }
    }
}

impl<BlockVerifier: BlockVerifierTrait> ReceiverTrait for Receiver<BlockVerifier> {
    fn receive(&mut self) -> Result<ReceivedBlock, Error> {
        let signed_block = match self.net_receiver.receive() {
            Ok(x) => x,
            Err(e) => {
                return Err(Error::new(&format!(
                    "Error while receiving the signed data block! ERROR: {e}"
                )));
            }
        };

        let (msg, valid, hash_sign, hash_pks) = match self.verifier.verify(signed_block) {
            Ok(x) => x,
            Err(e) => {
                return Err(Error::new(&format!("Cannot verify! ERROR: {e}")));
            }
        };

        let hash_whole = xxh3_64(&msg) ^ hash_sign ^ hash_pks;
        debug!(tag: "receiver","[{hash_whole}] {}", String::from_utf8_lossy(&msg));

        Ok(ReceivedBlock::new(
            msg,
            SenderIdentity::new(valid.into()),
            HashSet::new(),
        ))
    }
}
