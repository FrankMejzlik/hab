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
mod receiver;
mod sender;
mod traits;
mod utils;

use std::fs::File;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
// ---
use clap::Parser;
use ctrlc;
// ---
use crate::common::{Args, ProgramMode};
use crate::diag_server::DiagServer;
use crate::receiver::{Receiver, ReceiverParams};
use crate::sender::{Sender, SenderParams};
use crate::traits::{DiagServerTrait, ReceiverTrait, SenderTrait};

#[allow(dead_code)]
fn run_diag_server(_args: Args, running: Arc<AtomicBool>) {
    info!("Running a diag server...");

    let mut diag_server = DiagServer::new("127.0.0.1:9000".parse().unwrap());

    while running.load(Ordering::Acquire) {
        let msg = format!("{}", utils::unix_ts());
        diag_server
            .send_state(&msg)
            .expect("Failed to send the message!");
        thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn run_sender(args: Args, running: Arc<AtomicBool>) {
    let sender_params = SenderParams {
        seed: args.seed,
        addr: args.addr,
        running,
    };
    info!("Running a sender with {sender_params:#?}");

    let mut sender = Sender::new(sender_params);

    // Use the desired input (STDIN or the provided file)
    match args.input {
        Some(input_file) => {
            info!("Getting input from the file '{}'...", input_file);
            let mut file = match File::open(input_file) {
                Ok(file) => file,
                Err(e) => {
                    panic!("Failed to open file: {:?}", e);
                }
            };
            sender.run(&mut file)
        }
        None => {
            info!("Getting input from STDIN...");
            sender.run(&mut std::io::stdin())
        }
    }
}

fn run_receiver(args: Args, running: Arc<AtomicBool>) {
    let recv_params = ReceiverParams {
        addr: args.addr,
        running,
    };
    info!("Running a receiver with {recv_params:#?}");

    let mut receiver = Receiver::new(recv_params);

    // Use the desired input (STDOUT or the provided file)
    match args.output {
        Some(output_file) => {
            info!("Putting output to the file '{}'...", output_file);
            let mut file = match File::open(output_file) {
                Ok(file) => file,
                Err(e) => {
                    panic!("Failed to open file: {:?}", e);
                }
            };
            receiver.run(&mut file)
        }
        None => {
            info!("Putting output to STDOUT...");
            receiver.run(&mut std::io::stdout())
        }
    }
}

fn init_application() -> Arc<AtomicBool> {
    // Clear the directories before every launch
    _ = std::fs::remove_dir_all(config::INPUT_DBG_DIR);
    _ = std::fs::remove_dir_all(config::OUTPUT_DBG_DIR);

    // Create the directory for logs
    std::fs::create_dir_all(config::LOGS_DIR).expect("The logs directory should be created.");

    // Create the directories for debugging input/output
    std::fs::create_dir_all(config::INPUT_DBG_DIR).expect("The directory should be created.");
    std::fs::create_dir_all(config::OUTPUT_DBG_DIR).expect("The directory should be created.");

    // Flag that indicates if the app shoul still run
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    ctrlc::set_handler(move || {
        running_clone.store(false, Ordering::Release);
        thread::sleep(std::time::Duration::from_millis(100));
        std::process::exit(0x01);
    })
    .expect("Error setting Ctrl-C handler");

    running
}

fn main() {
    if let Err(e) = common::setup_logger() {
        info!("Unable to initialize the logger!\nERROR: {}", e);
    }
    let args = Args::parse();
    let running = init_application();

    // Sender mode
    match args.mode {
        ProgramMode::Sender => run_sender(args, running),
        ProgramMode::Receiver => run_receiver(args, running),
    }
}
