//!
//! The main module providing high-level API for the receiver of the data.
//!

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---
use crate::common::{Error, ReceivedBlock};
use crate::log_output;
use crate::net_receiver::{NetReceiver, NetReceiverParams};
use crate::traits::{BlockVerifierParams, BlockVerifierTrait, Config, MsgMetadata, ReceiverTrait};
use xxhash_rust::xxh3::xxh3_64;
// ---
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct ReceiverParams {
    pub addr: String,
    pub running: Arc<AtomicBool>,
}

pub struct Receiver<BlockVerifier: BlockVerifierTrait + std::marker::Send + 'static> {
    params: ReceiverParams,
    #[allow(dead_code)]
    verifier: Arc<Mutex<BlockVerifier>>,
    net_receiver: Arc<Mutex<NetReceiver>>,
}

impl<BlockVerifier: BlockVerifierTrait + std::marker::Send> Receiver<BlockVerifier> {
    pub fn new(params: ReceiverParams, config: Config) -> Self {
        let block_signer_params = BlockVerifierParams {};
        let verifier = Arc::new(Mutex::new(BlockVerifier::new(
            block_signer_params,
            config.clone(),
        )));

        let net_recv_params = NetReceiverParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
        };
        let net_receiver = Arc::new(Mutex::new(NetReceiver::new(net_recv_params, config)));

        let running_clone = params.running.clone();
        let net_receiver_clone = net_receiver.clone();
        let verifier_clone = verifier.clone();

        std::thread::spawn(move || {
            while running_clone.load(Ordering::Acquire) {
                let signed_block;
                {
                    //< LOCK
                    let mut net_receiver_guard =
                        net_receiver_clone.lock().expect("Should be lockable!");
                    signed_block = match net_receiver_guard.receive() {
                        Ok(x) => x,
                        Err(e) => {
                            warn!(tag: "receiver", "Failed to receiver from the socket! ERRROR: {e}");
                            continue;
                        }
                    };
                    //< UNLOCK
                }

                {
                    //< LOCK
                    let mut verifier_guard = verifier_clone.lock().expect("Should be lockable!");

                    let (msg, sender_id, _hash_sign, _hash_pks) = match verifier_guard
                        .verify(signed_block)
                    {
                        Ok(x) => x,
                        Err(e) => {
                            warn!(tag: "receiver", "Failed to verify the signed block! ERRROR: {e}");
                            continue;
                        }
                    };

                    // Read the metadata from the message
                    let (metadata, msg) = Self::read_metadata(msg);

                    let hash = xxh3_64(&msg) ^ _hash_sign ^ _hash_pks;

                    let mut net_receiver_guard =
                        net_receiver_clone.lock().expect("Should be lockable!");

                    net_receiver_guard.enqueue(msg, sender_id, metadata, hash);
                    //< UNLOCK
                }
            }
        });

        Receiver {
            params,
            verifier,
            net_receiver,
        }
    }

    ///
    /// Reads the additional data in the message and returns it along with the clean message.
    ///
    fn read_metadata(mut msg: Vec<u8>) -> (MsgMetadata, Vec<u8>) {
        let len = msg.len() - std::mem::size_of::<usize>();

        let seq = usize::from_le_bytes(
            msg[len..]
                .try_into()
                .expect("Should have a correct length!"),
        );
        debug!("seq: {seq}");
        msg.drain(len..);
        (MsgMetadata { seq }, msg)
    }
}

impl<BlockVerifier: BlockVerifierTrait + std::marker::Send> ReceiverTrait
    for Receiver<BlockVerifier>
{
    fn receive(&mut self) -> Result<ReceivedBlock, Error> {
        // The main loop polling messages from the DeliveryQueues.
        while self.params.running.load(Ordering::Acquire) {
            let received;
            {
                //< LOCK
                let mut net_rec_guard = self.net_receiver.lock().expect("Should be lockable!");
                received = net_rec_guard.dequeue();
                //< UNLOCK
            }

            if let Some((msg, sender_id, _metadata, hash)) = received {
                #[cfg(feature = "log_input_output")]
                {
                    debug!(tag: "receiver","[{}][{hash}] {}", _metadata.seq, String::from_utf8_lossy(&msg));
                    log_output!(_metadata.seq, hash, &msg);
                }
                return Ok(ReceivedBlock::new(msg, sender_id, HashSet::new()));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(Error::new("Application terminating."))
    }
}
