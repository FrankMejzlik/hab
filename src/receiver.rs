//!
//! The main module providing high-level API for the receiver of the data.
//!

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
// ---
use xxhash_rust::xxh3::xxh3_64;
// ---
use crate::common::{BlockSignerParams, Error, ReceivedBlock, SenderIdentity, SeqNum};
use crate::delivery_queues::{DeliveryQueues, DeliveryQueuesParams};
use crate::net_receiver::{NetReceiver, NetReceiverParams};
use crate::traits::{BlockVerifierTrait, ReceiverTrait};
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
    pub key_lifetime: usize,
    pub cert_interval: usize,
    pub delivery_deadline: Duration,
}

pub struct Receiver<BlockVerifier: BlockVerifierTrait + std::marker::Send + 'static> {
    params: ReceiverParams,
    #[allow(dead_code)]
    verifier: Arc<Mutex<BlockVerifier>>,
    #[allow(dead_code)]
    prev_seqs: HashMap<SenderIdentity, SeqNum>,
    delivery: Arc<Mutex<DeliveryQueues>>,
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
            key_lifetime: params.key_lifetime,
            cert_interval: params.cert_interval,
            max_piece_size: 0,
            key_dist: vec![], //< Not used
        };
        let verifier = Arc::new(Mutex::new(BlockVerifier::new(block_signer_params)));

        let net_recv_params = NetReceiverParams {
            addr: params.target_addr.clone(),
            running: params.running.clone(),
            datagram_size: params.datagram_size,
            net_buffer_size: params.net_buffer_size,
        };

        let running_clone = params.running.clone();
        let verifier_clone = verifier.clone();

        let delivery = Arc::new(Mutex::new(DeliveryQueues::new(DeliveryQueuesParams {
            deadline: params.delivery_deadline,
        })));
        let delivery_clone = delivery.clone();

        std::thread::spawn(move || {
            let mut net_receiver = NetReceiver::new(net_recv_params);

            while running_clone.load(Ordering::Acquire) {
                let signed_block;
                {
                    //< LOCK
                    signed_block = match net_receiver.receive() {
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

                    let verify_result = match verifier_guard.verify(signed_block) {
                        Ok(x) => x,
                        Err(e) => {
                            warn!(tag: "receiver", "Failed to verify the signed block! ERRROR: {e}");
                            continue;
                        }
                    };

                    let mut delivery_guard = delivery_clone.lock().expect("Should be lockable!");

                    delivery_guard.enqueue(verify_result);
                    //< UNLOCK
                }
            }
        });

        Receiver {
            params,
            verifier,
            prev_seqs: HashMap::new(),
            delivery,
        }
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
                let mut delivery_guard = self.delivery.lock().expect("Should be lockable!");
                received = delivery_guard.dequeue();
                //< UNLOCK
            }

            if let Some(verif_result) = received {
                debug!(tag: "delivery_queues","[{}][{}][{}] {}", verif_result.metadata.seq, verif_result.hash, verif_result.msg.len(), xxh3_64(&verif_result.msg));

                return Ok(ReceivedBlock::new(
                    verif_result.msg,
                    verif_result.verification,
                    verif_result.metadata,
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(Error::new("Application terminating."))
    }
}
