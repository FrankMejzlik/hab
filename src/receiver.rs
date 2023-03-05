//!
//! The main module providing high-level API for the receiver of the data.
//!

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---
use crate::common::{BlockSignerParams, Error, MsgMetadata, ReceivedBlock, SenderIdentity, SeqNum};
use crate::log_output;
use crate::net_receiver::{NetReceiver, NetReceiverParams};
use crate::traits::{BlockVerifierTrait, ReceiverTrait};
use xxhash_rust::xxh3::xxh3_64;
// ---
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct ReceiverParams {
    pub target_addr: String,
    pub target_name: String,
    pub running: Arc<AtomicBool>,
    pub id_dir: String,
    pub id_filename: String,
    pub datagram_size: usize,
    pub net_buffer_size: usize,
    pub pub_key_layer_limit: usize,
}

pub struct Receiver<BlockVerifier: BlockVerifierTrait + std::marker::Send + 'static> {
    params: ReceiverParams,
    #[allow(dead_code)]
    verifier: Arc<Mutex<BlockVerifier>>,
    net_receiver: Arc<Mutex<NetReceiver>>,
    #[allow(dead_code)]
    prev_seqs: HashMap<SenderIdentity, SeqNum>,
}

impl<BlockVerifier: BlockVerifierTrait + std::marker::Send> Receiver<BlockVerifier> {
    pub fn new(params: ReceiverParams) -> Self {
        let block_signer_params = BlockSignerParams {
            seed: 0,
            layers: 0,
            id_dir: params.id_dir.clone(),
            id_filename: params.id_filename.clone(),
            target_petname: params.target_name.clone(),
            pub_key_layer_limit: params.pub_key_layer_limit,
        };
        let verifier = Arc::new(Mutex::new(BlockVerifier::new(block_signer_params)));

        let net_recv_params = NetReceiverParams {
            addr: params.target_addr.clone(),
            running: params.running.clone(),
            datagram_size: params.datagram_size,
            net_buffer_size: params.net_buffer_size,
        };
        let net_receiver = Arc::new(Mutex::new(NetReceiver::new(net_recv_params)));

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
            prev_seqs: HashMap::new(),
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
                // // In-orderity check
                // assert!(
                //     _metadata.seq < *self.prev_seqs.get(&sender_id).expect("Should be there!"),
                //     "The messages are not delivered in-order!"
                // );

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
