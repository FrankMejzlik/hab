//!
//! The main module providing high-level API for the receiver of the data.
//!

use hab::common::MsgVerification;
use hab::{Receiver, ReceiverParams, ReceiverTrait};
use std::io::{stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
// ---
use sha2::{Digest, Sha256};
// ---
#[allow(unused_imports)]
use hab::{debug, error, info, trace, warn};

use crate::config::{self, BlockSignerInst};

#[derive(Debug)]
pub struct AudiBroReceiverParams {
    pub running: Arc<AtomicBool>,
    pub target_addr: String,
    pub target_name: String,
    /// A number of signatures one keypair can generate.
    pub key_lifetime: usize,
    pub cert_interval: usize,
    pub delivery_deadline: Duration,
    pub tui: bool,
    pub alt_input: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
}

pub struct AudiBroReceiver {
    params: AudiBroReceiverParams,
    receiver: Receiver<BlockSignerInst>,
}

impl AudiBroReceiver {
    pub fn new(params: AudiBroReceiverParams) -> Self {
        let receiver = Receiver::new(ReceiverParams {
            running: params.running.clone(),
            target_addr: params.target_addr.clone(),
            target_name: params.target_name.clone(),
            id_dir: config::ID_DIR.into(),
            id_filename: config::ID_FILENAME.into(),
            datagram_size: config::DATAGRAM_SIZE,
            net_buffer_size: config::BUFFER_SIZE,
            key_lifetime: params.key_lifetime,
            cert_interval: params.cert_interval,
            delivery_deadline: params.delivery_deadline,
            alt_input: params.alt_input,
        });

        AudiBroReceiver { params, receiver }
    }

    pub fn run(&mut self) {
        // The main loop as long as the app should run
        while self.params.running.load(Ordering::Acquire) {
            let received_block = match self.receiver.receive() {
                Ok(x) => x,
                Err(e) => {
                    warn!("Unable to receive! ERROR: {e}");
                    continue;
                }
            };

            // OUTPUT

            let mut handle = stdout().lock();

            let mut hasher = Sha256::new();
            hasher.update(&received_block.data);
            let result = hasher.finalize();
            let hash = format!("{:x}", result);

            let size = received_block.data.len();

            match &received_block.sender {
                MsgVerification::Verified(id) => {
                    writeln!(
                        handle,
                        "{};verified;{};{};{}",
                        received_block.metadata.seq,
                        id.petnames.join(","),
                        size,
                        hash
                    )
                    .unwrap();
                }
                MsgVerification::Certified(id) => {
                    writeln!(
                        handle,
                        "{};certified;{};{};{}",
                        received_block.metadata.seq,
                        id.petnames.join(","),
                        size,
                        hash
                    )
                    .unwrap();
                }
                MsgVerification::Unverified => {
                    writeln!(
                        handle,
                        "{};unverified;;{};{}",
                        received_block.metadata.seq, size, hash
                    )
                    .unwrap();
                }
            }

            debug!(tag: "received", "[{}][{:?}] {}", received_block.metadata.seq, received_block.sender, hash);
        }
    }
}
