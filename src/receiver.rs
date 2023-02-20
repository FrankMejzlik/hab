//!
//! The main module providing high-level API for the receiver of the data.
//!

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ---
use crate::block_signer::BlockSignerParams;
use crate::config::BlockVerifierInst;
use crate::net_receiver::{NetReceiver, NetReceiverParams};
use crate::traits::{BlockVerifierTrait, ReceiverTrait};
use xxhash_rust::xxh3::xxh3_64;
// ---
use crate::config;
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
    fn run(&mut self, output: &mut dyn Write, mut input: Option<impl Read>) {
        // The main loop as long as the app should run
        while self.params.running.load(Ordering::Acquire) {
            let mut signed_block = vec![];
            // INPUT: file
            if let Some(ref mut x) = input {
                x.read_to_end(&mut signed_block)
                    .expect("Should be readable!");
                // When using file, it is one iteration only
                self.params.running.store(false, Ordering::Release);
            }
            // INPUT: network
            else {
                // Block until we receive some whole signed block
                signed_block = match self.net_receiver.receive() {
                    Ok(x) => x,
                    Err(e) => {
                        warn!("Error while receiving the signed data block! ERROR: {e}");
                        continue;
                    }
                };
            }

            let hash = xxh3_64(&signed_block);
            debug!(tag: "receiver", "Received signed block of {} bytes with hash '{hash}'.", signed_block.len());
            log_output!(hash, &signed_block);

            // Debug log the input signed block
            let (msg, valid, hash_sign, hash_pks) = match self.verifier.verify(signed_block) {
                Ok(x) => x,
                Err(e) => {
                    warn!("Invalid block thrown away! ERROR: {e}");
                    continue;
                }
            };

            let hash_whole = xxh3_64(&msg) ^ hash_sign ^ hash_pks;
            debug!(tag: "receiver","[{hash_whole}] {}", String::from_utf8_lossy(&msg));

            // OUTPUT
            if valid {
                output
                    .write_all(&msg)
                    .expect("The output should be writable!");
                output.flush().expect("Should be flushable!");
            }
            debug!(tag: "received", "[{}] {}",valid, String::from_utf8_lossy(&msg));
        }
    }
}
