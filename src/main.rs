//!
//! <PROJECT_NAME> is an implementation of the hash-based authentication protocol for streamed data.
//!
mod block_signer;
mod common;
mod config;
mod diag_server;
#[allow(clippy::assertions_on_constants)]
mod horst;
mod merkle_tree;
mod net_receiver;
mod net_sender;
mod sender;
mod traits;
mod utils;

use std::fs::File;
use std::thread;
// ---
use clap::Parser;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
// ---
use crate::traits::{DiagServerTrait, SenderTrait};
use common::{Args, ProgramMode};
use diag_server::DiagServer;
use sender::{Sender, SenderParams};

#[allow(dead_code)]
fn run_diag_server(_args: Args) {
    info!("Running a diag server...");

    let mut diag_server = DiagServer::new("127.0.0.1:9000".parse().unwrap());

    loop {
        let msg = format!("{}", utils::unix_ts());
        diag_server
            .send_state(&msg)
            .expect("Failed to send the message!");
        thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn run_sender(args: Args) {
    info!("Running a sender...");

    let sender_params = SenderParams { seed: args.seed };
    let mut sender = Sender::new(sender_params);

    // Use the desired input (STDIN or the provided file)
    match args.input {
        Some(input_file) => {
            info!("Getting input from the file '{}'...", input_file);
            let file = match File::open(input_file) {
                Ok(file) => file,
                Err(e) => {
                    panic!("Failed to open file: {:?}", e);
                }
            };
            sender.run(&file)
        }
        None => {
            info!("Getting input from STDIN...");
            sender.run(&std::io::stdin())
        }
    }
}

fn run_receiver(_args: Args) {
    info!("Running a receiver...");
    // TODO
}

fn main() {
    if let Err(e) = common::setup_logger() {
        warn!("Unable to initialize the logger!\nERROR: {}", e);
    }

    let args = Args::parse();

    // Sender mode
    match args.mode {
        ProgramMode::Sender => run_sender(args),
        ProgramMode::Receiver => run_receiver(args),
    }
}
