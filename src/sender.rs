//!
//! The main module providing high-level API for the sender of the data.
//!

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{mem::size_of_val, thread};
// ---
use crate::block_signer::BlockSignerParams;
use crate::config::BlockSignerInst;
use crate::net_sender::{NetSender, NetSenderParams};
use crate::traits::{BlockSignerTrait, SenderTrait};
#[allow(unused_imports)]
// ---
use crate::{debug, error, info, trace, warn};
use chrono::Local;

#[derive(Debug)]
pub struct SenderParams {
    pub seed: u64,
    pub addr: String,
    pub running: Arc<AtomicBool>,
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

        let net_sender_params = NetSenderParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
        };
        let net_sender = NetSender::new(net_sender_params);

        Sender {
            params,
            signer,
            net_sender,
        }
    }
    // ---
    #[cfg(feature = "simulate_stdin")]
    fn read_input(input: &mut dyn Read) -> Vec<u8> {
        thread::sleep(Duration::from_secs(5));
        let msg = Local::now().format("%d-%m-%Y %H:%M:%S").to_string();
        debug!(tag: "sender", "Processing input '{}'...", &msg);
        msg.into_bytes()
    }
    #[cfg(not(feature = "simulate_stdin"))]
    fn read_input(input: &mut dyn Read) -> Vec<u8> {
        let mut msg = String::default();
        input.read_to_string(&mut msg).expect("Fail");
        debug!(tag: "sender", "Processing input '{}'...", &msg);
        msg.into_bytes()
    }
}

impl SenderTrait for Sender {
    fn run(&mut self, input: &mut dyn Read) {
        // The main loop as long as the app should run
        while self.params.running.load(Ordering::Acquire) {
            let data = Self::read_input(input);

            let signed_data = match self.signer.sign(&data) {
                Ok(x) => x.to_bytes(),
                Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
            };

            if let Err(e) = self.net_sender.broadcast(&signed_data) {
                panic!("Failed to broadcast the data block!\nERROR: {:?}", e);
            };
        }
    }
}
