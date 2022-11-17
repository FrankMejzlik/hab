//!
//! The main module providing high-level API for the broadcaster of the data.
//!

use crate::net_sender::{NetSender, NetSenderParams};

pub struct SenderParams {
    pub seed: u64,
}

pub struct Sender {
    // params: SenderParams,
    // signer: BlockSigner,
    // net_sender: NetSender,
}

impl Sender {
    fn new(_params: &SenderParams) -> Self {
        Sender {}
    }
}
