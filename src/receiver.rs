//!
//! The main module providing high-level API for the receiver of the data.
//!

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
// ---
use crate::block_signer::BlockSignerParams;
use crate::config::BlockSignerInst;
use crate::net_receiver::{NetReceiver, NetReceiverParams};
use crate::traits::{BlockSignerTrait, ReceiverTrait};
#[allow(unused_imports)]
// ---
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct ReceiverParams {
    pub addr: String,
    pub running: Arc<AtomicBool>,
}

pub struct Receiver {
    #[allow(dead_code)]
    params: ReceiverParams,
    signer: BlockSignerInst,
    net_receiver: NetReceiver,
}

impl Receiver {
    pub fn new(params: ReceiverParams) -> Self {
        let block_signer_params = BlockSignerParams { seed: 0 };
        let signer = BlockSignerInst::new(block_signer_params);

        let net_recv_params = NetReceiverParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
        };
        let net_receiver = NetReceiver::new(net_recv_params);

        Receiver {
            params,
            signer,
            net_receiver,
        }
    }
}

impl ReceiverTrait for Receiver {
    fn run(&mut self, _output: &mut dyn Write) {
        // The main loop as long as the app should run
        while self.params.running.load(Ordering::Acquire) {
            debug!("Receiver running...");
            thread::sleep(Duration::from_secs(1));
        }
    }
}
