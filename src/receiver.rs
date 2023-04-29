//!
//! The main module providing high-level API for the receiver of the data.
//!

use crate::block_signer::BlockSigner;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
// ---
// ---
use crate::common::{BlockSignerParams, Error, ReceivedMessage};
use crate::delivery_queues::{DeliveryQueues, DeliveryQueuesParams};
use crate::net_receiver::{NetReceiver, NetReceiverParams};
use crate::traits::{MessageVerifierTrait, ReceiverTrait};
use crate::{utils, FtsSchemeTrait};
// ---
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct ReceiverParams {
    /// A filename where the identity will be serialized.
    pub id_filename: String,
    /// Maximum time to delay the delivery of a piece if subsequent pieces are already received.
    pub delivery_delay: Duration,
    /// If this receiver should also re-send the received pieces.
    pub distribute: Option<String>,
    /// The IP address of the target sender.
    pub target_addr: String,
    /// The name of the target sender (the petname).
    pub target_name: String,
    /// A flag that indicates if the application should run or terminate.
    pub running: Arc<AtomicBool>,
    /// An alternative output destination instead of a network (useful for testing).
    pub alt_input: Option<mpsc::Receiver<Vec<u8>>>,
}

pub struct Receiver<Signer: FtsSchemeTrait> {
    params: ReceiverParams,
    delivery: Arc<Mutex<DeliveryQueues>>,
    skip_counter: Arc<AtomicUsize>,
    _x: PhantomData<Signer>,
}

impl<Signer: FtsSchemeTrait> Receiver<Signer> {
    pub fn new(mut params: ReceiverParams) -> Self {
        let block_signer_params = BlockSignerParams {
            seed: 0,
            id_filename: params.id_filename.clone(),
            target_petname: params.target_name.clone(),
            pre_cert: None,
            max_piece_size: 0, //< Not used
            key_lifetime: 0,   //< Not used
            key_dist: vec![],  //< Not used
        };

        let net_recv_params = NetReceiverParams {
            addr: params.target_addr.clone(),
            running: params.running.clone(),
            alt_input: params.alt_input.take(),
        };

        let running_clone = params.running.clone();

        let delivery = Arc::new(Mutex::new(DeliveryQueues::new(DeliveryQueuesParams {
            deadline: params.delivery_delay,
        })));
        let delivery_clone = delivery.clone();

        let skip_counter = Arc::new(AtomicUsize::new(0));
        let skip_counter_clone = skip_counter.clone();

        std::thread::spawn(move || {
            let mut verifier_clone = BlockSigner::<Signer>::new(block_signer_params);
            let mut net_receiver = NetReceiver::new(net_recv_params);

            while running_clone.load(Ordering::Acquire) {
                let signed_block;
                {
                    //< LOCK
                    signed_block = match net_receiver.receive() {
                        Ok(x) => x,
                        Err(e) => {
                            warn!(tag: "receiver", "Failed to receiver from the socket! ERRROR: {e}");
                            return;
                        }
                    };
                    //< UNLOCK
                }

                // If should based on `skip_counter_clone`
                let mut skip = false;
                loop {
                    let skip_val = skip_counter_clone.load(Ordering::Acquire);
                    if skip_val > 0 {
                        if let Ok(_) = skip_counter_clone.compare_exchange(
                            skip_val,
                            skip_val - 1,
                            Ordering::Release,
                            Ordering::Acquire,
                        ) {
                            skip = true;
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if skip {
                    trace!(tag:"receiver", "Skipping a block!");
                    continue;
                }

                {
                    let verify_result = match verifier_clone.verify(signed_block) {
                        Ok(x) => x,
                        Err(e) => {
                            warn!(tag: "receiver", "Failed to verify the signed block! ERROR: {e}");
                            continue;
                        }
                    };

                    //< LOCK
                    let mut delivery_guard = delivery_clone.lock().expect("Should be lockable!");
                    delivery_guard.enqueue(verify_result);
                    //< UNLOCK
                }
            }
        });

        Receiver {
            params,
            delivery,
            skip_counter,
            _x: PhantomData,
        }
    }
}

impl<Signer: FtsSchemeTrait + Send + Sync> ReceiverTrait for Receiver<Signer> {
    fn receive(&mut self) -> Result<ReceivedMessage, Error> {
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
                debug!(tag: "delivery_queues","[{}][{}][{}] {}", verif_result.seq, verif_result.hash, verif_result.msg.len(), utils::sha2_256_str(&verif_result.msg));

                return Ok(ReceivedMessage::new(
                    verif_result.msg,
                    verif_result.verification,
                    verif_result.seq,
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Err(Error::new("Application terminating."))
    }
    fn ignore_next(&mut self, count: usize) {
        self.skip_counter.store(count, Ordering::Release);
    }
}
