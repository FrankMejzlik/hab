//!
//! The main module providing high-level API for the sender of the data.
//!

use slice_of_array::SliceFlatExt;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{mem::size_of_val, thread};
// ---
use crate::block_signer::BlockSignerParams;
use chrono::Local;
use xxhash_rust::xxh3::xxh3_64;
// ---
use crate::config::BlockSignerInst;
use crate::net_sender::{NetSender, NetSenderParams};
use crate::traits::{BlockSignerTrait, SenderTrait};
#[allow(unused_imports)]
use crate::{debug, error, info, log_input, trace, warn};

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

    /// Reads the available chunk of data from the provided input.
    fn read_input(_input: &mut dyn Read) -> Vec<u8> {
        let mut msg = String::default();

        #[cfg(feature = "simulate_stdin")]
        {
            // We simulate periodic data coming via input
            thread::sleep(Duration::from_secs(5));
            msg = Local::now().format("%d-%m-%Y %H:%M:%S").to_string();
        }

        #[cfg(not(feature = "simulate_stdin"))]
        _input.read_to_string(&mut msg).expect("Fail");

        debug!(tag: "sender", "Processing input '{}'...", &msg);

        msg.into_bytes()
    }
}

impl SenderTrait for Sender {
    fn run(&mut self, input: &mut dyn Read) {
        // The main loop as long as the app should run
        while self.params.running.load(Ordering::Acquire) {
            let data = Self::read_input(input);

            let hash_sign;
            let hash_pks;
            let signed_data = match self.signer.sign(&data) {
                Ok(x) => {
                    let mut tmp2 = 0;
                    for x in &x.signature.data {
                        for y in x {
                            let h = xxh3_64(&y);
                            tmp2 = tmp2 ^ h;
                        }
                    }

                    let mut tmp = 0;
                    for pk in x.pub_keys.iter() {
                        tmp = tmp ^ xxh3_64(pk.data.as_ref());
                    }
                    hash_pks = tmp;
                    hash_sign = tmp2;
                    bincode::serialize(&x).expect("Should be seriallizable.")
                }
                Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
            };

            // Debug log the input signed block
            let hash = xxh3_64(&signed_data);
            log_input!(hash, &signed_data);
            debug!(tag: "sender", "\tBroadcasting {} bytes with hash '{hash}'...", signed_data.len());

            // STDOUT
            println!(
                "msg: {}\n\thash: {hash}\n\tsignature: {hash_sign}\n\thash_pks: {hash_pks}",
                String::from_utf8_lossy(&data)
            );

            if let Err(e) = self.net_sender.broadcast(&signed_data) {
                panic!("Failed to broadcast the data block!\nERROR: {:?}", e);
            };
        }
    }
}
