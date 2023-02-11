//!
//! The main module providing high-level API for the sender of the data.
//!

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{mem::size_of_val, thread};
// ---
use chrono::Local;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
// ---
use crate::block_signer::BlockSignerParams;
use crate::config::BlockSignerInst;
use crate::net_sender::{NetSender, NetSenderParams};
use crate::traits::{BlockSignerTrait, SenderTrait};

pub struct SenderParams {
    pub seed: u64,
    pub port: u32,
}

pub struct Sender {
    #[allow(dead_code)]
    params: SenderParams,
    signer: BlockSignerInst,
    net_sender: NetSender,
}

impl Sender {
    pub fn new(params: SenderParams) -> Self {
        let block_signer_params = BlockSignerParams { seed: params.seed };
        let signer = BlockSignerInst::new(block_signer_params);

        let net_sender_params = NetSenderParams { port: params.port };
        let net_sender = NetSender::new(net_sender_params);

        Sender {
            params,
            signer,
            net_sender,
        }
    }
}

impl SenderTrait for Sender {
    fn run(&mut self, _input: &dyn Read, running: Arc<AtomicBool>) {
        // The main loop as long as the app should run
        while running.load(Ordering::Acquire) {
            let msg = Local::now()
                .format("%d-%m-%Y %H:%M:%S")
                .to_string()
                .into_bytes();
            debug!("Processing message '{}'...", String::from_utf8_lossy(&msg));

            let signed_data = match self.signer.sign(&msg) {
                Ok(x) => x.to_bytes(),
                Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
            };

            debug!("Signed data block size: {}B", size_of_val(&signed_data));

            match self.net_sender.broadcast(&signed_data) {
                Ok(()) => debug!("Signed data block broadcasted."),
                Err(e) => panic!("Failed to broadcast the data block!\nERROR: {:?}", e),
            };

            thread::sleep(Duration::from_secs(3));
        }
    }
}
