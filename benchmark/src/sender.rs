//!
//! The main module providing high-level API for the sender of the data.
//!

use rand::RngCore;
use std::io::stdin;
use std::io::BufRead;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver as MpscReceiver};
use std::sync::Arc;

// ---

// ---
#[allow(unused_imports)]
use hab::{debug, error, info, log_input, trace, warn};
use hab::{Sender, SenderParams, SenderTrait};
// ---
use crate::config::{self, BlockSignerInst};
use crate::tui::TerminalUi;

#[derive(Debug)]
pub struct AudiBroSenderParams {
    pub running: Arc<AtomicBool>,
    pub seed: u64,
    pub layers: usize,
    /// An address where the sender will listen for heartbeats.
    pub addr: String,
    /// A number of signatures one keypair can generate.
    pub key_lifetime: usize,
    pub cert_interval: usize,
    pub max_piece_size: usize,
    pub tui: bool,
    pub key_dist: Vec<Vec<usize>>,
	pub alt_output: Option<std::sync::mpsc::Sender<Vec<u8>>> 
}

pub struct AudiBroSender {
    params: AudiBroSenderParams,
    sender: Sender<BlockSignerInst>,
}

impl AudiBroSender {
    pub fn new(params: AudiBroSenderParams) -> Self {
        let sender = Sender::new(SenderParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
            layers: params.layers,
            seed: params.seed,
            id_dir: config::ID_DIR.into(),
            id_filename: config::ID_FILENAME.into(),
            datagram_size: config::DATAGRAM_SIZE,
            net_buffer_size: config::BUFFER_SIZE,
            subscriber_lifetime: config::SUBSCRIBER_LIFETIME,
            key_lifetime: params.key_lifetime,
            cert_interval: params.cert_interval,
            max_piece_size: params.max_piece_size,
            key_dist: params.key_dist.clone(),
			alt_output: params.alt_output.clone()
        });
        AudiBroSender { params, sender }
    }

    pub fn run(&mut self) {
        let (tx, mut rx) = channel();

        if self.params.tui {
            std::thread::spawn(move || {
                let tui = TerminalUi::new(tx);
                tui.run_tui();
            });
        }

        // The main loop as long as the app should run
        while self.params.running.load(Ordering::Acquire) {
            // Get the data to broadcast from TUI mode
            let data = if self.params.tui {
                Self::read_input_tui(&mut rx)
            }
            // Else get data from stream mode
            else {
                Self::read_input()
            };

            if let Err(e) = self.sender.broadcast(data) {
                warn!("Failed to broadcast! ERROR: {e}");
            }
        }
    }
    // ---

    /// Reads the available chunk of data from the provided input.
    fn read_input() -> Vec<u8> {
        let input_bytes;
        #[cfg(feature = "simulate_stdin")]
        {
            use chrono::Local;
            use std::thread;

            let mut rng = rand::thread_rng();
            let mut buffer = vec![0u8; 512 * 1024 * 1024]; // 5 MiB buffer
            rng.fill_bytes(&mut buffer);

            if let Some(x) = config::SIM_INPUT_PERIOD {
                // We simulate periodic data coming via input
                thread::sleep(x);
            } else {
                let mut handle = stdin().lock();
                let mut input = String::new();
                handle.read_line(&mut input).expect("Failed to read line");
            }

            let msg = Local::now().format("%d-%m-%Y %H:%M:%S").to_string();
            input_bytes = msg.into_bytes();
            input_bytes = buffer
        }

        #[cfg(not(feature = "simulate_stdin"))]
        {
            let mut handle = stdin().lock();
            let mut input = String::new();
            handle.read_line(&mut input).expect("Failed to read line");
            input.pop();
            input_bytes = input.into_bytes();
        }

        input_bytes
    }

    ///
    /// Runs the TUI and periodically sends the input data to broadcast.
    ///
    fn read_input_tui(rx: &mut MpscReceiver<Vec<u8>>) -> Vec<u8> {
        // Wait for the data
        let input_bytes = match rx.recv() {
            Ok(x) => x,
            Err(_e) => panic!("The input is dead!"),
        };

        input_bytes
    }
}
