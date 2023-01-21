//!
//! The main module providing high-level API for the sender of the data.
//!

use std::io::Read;
use std::{mem::size_of_val, thread};
// ---
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
// ---
use crate::block_signer::BlockSignerParams;
use crate::config::BlockSignerInst;
use crate::net_sender::{NetSender, NetSenderParams};
use crate::traits::SenderTrait;

pub struct SenderParams {
    pub seed: u64,
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
        let mut signer = BlockSignerInst::new(block_signer_params);

        let net_sender_params = NetSenderParams {};
        let net_sender = NetSender::new(net_sender_params);

        Sender {
            params,
            signer,
            net_sender,
        }
    }
}

impl SenderTrait for Sender {
    fn run(&mut self, _input: &dyn Read) {
        let msg = b"Hello, world!";

        let packet = match self.signer.sign(msg) {
            Ok(x) => x,
            Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
        };

        debug!("packet: {} B", size_of_val(&packet));

        let packet_bytes = packet.to_bytes();
        match self.net_sender.broadcast(&packet_bytes) {
            Ok(()) => debug!("Packet broadcasted."),
            Err(e) => panic!("Failed to broadcast the data block!\nERROR: {:?}", e),
        };

        loop {
            thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}
