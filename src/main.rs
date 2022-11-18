//!
//! <PROJECT_NAME> is an implementation of the hash-based authentication protocol for streamed data.
//!
mod block_signer;
mod common;
mod config;
#[allow(clippy::assertions_on_constants)]
mod horst;
mod merkle_tree;
mod net_receiver;
mod net_sender;
mod sender;
mod signer_keystore;
mod traits;
mod utils;

use std::mem::size_of_val;
// ---
use clap::Parser;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use simple_logger::SimpleLogger;
// ---
use block_signer::BlockSignerParams;
use common::{Args, ProgramMode};
use config::BlockSignerInst;
use net_sender::{NetSender, NetSenderParams};

fn run_sender(args: Args) {
    info!("Running a sender...");

    let params = BlockSignerParams { seed: args.seed };
    let net_sender_params = NetSenderParams {};

    let msg = b"Hello, world!";

    let mut signer = BlockSignerInst::new(params);

    let packet = match signer.sign(msg) {
        Ok(x) => x,
        Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
    };

    debug!("packet: {} B", size_of_val(&packet));

    let net_sender = NetSender::new(net_sender_params);
    let packet_bytes = packet.to_bytes();
    match net_sender.broadcast(&packet_bytes) {
        Ok(()) => debug!("Packet broadcasted."),
        Err(e) => panic!("Failed to broadcast the data block!\nERROR: {:?}", e),
    };
}

fn run_receiver(_args: Args) {
    info!("Running a receiver...");
}

fn main() {
    SimpleLogger::new().without_timestamps().init().unwrap();
    let args = Args::parse();

    // Sender mode
    match args.mode {
        ProgramMode::Sender => run_sender(args),
        ProgramMode::Receiver => run_receiver(args),
    }
}
