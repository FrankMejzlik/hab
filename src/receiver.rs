//!
//! The main module providing high-level API for the receiver of the data.
//!

use std::collections::HashSet;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ---
use crate::block_signer::BlockSignerParams;
use crate::common::{Error, ReceivedBlock, SenderIdentity};
use crate::config::BlockVerifierInst;
use crate::net_receiver::{NetReceiver, NetReceiverParams};
use crate::traits::{BlockVerifierTrait, ReceiverTrait};
use tokio::sync::broadcast::error::SendError;
use xxhash_rust::xxh3::xxh3_64;
// ---
use crate::log_output;
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct ReceiverParams {
    pub addr: String,
    pub running: Arc<AtomicBool>,
}

pub struct Receiver {
    #[allow(dead_code)]
    params: ReceiverParams,
    verifier: BlockVerifierInst,
    net_receiver: NetReceiver,
}

impl Receiver {
    pub fn new(params: ReceiverParams) -> Self {
        let block_signer_params = BlockSignerParams { seed: 0, layers: 0 };
        let verifier = BlockVerifierInst::new(block_signer_params);

        let net_recv_params = NetReceiverParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
        };
        let net_receiver = NetReceiver::new(net_recv_params);

        Receiver {
            params,
            verifier,
            net_receiver,
        }
    }
}

impl ReceiverTrait for Receiver {
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
