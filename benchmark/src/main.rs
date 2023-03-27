//!
//! <PROJECT_NAME> is an implementation of the hash-based authentication protocol for streamed data.
//!
mod benchmarker;
mod config;
// ---
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
// ---
use clap::Parser;
#[allow(unused_imports)]
use hab::{debug, error, info, log_input, trace, warn};
use serde::{Deserialize, Serialize};
// ---
use crate::{
    benchmarker::{Benchmarker, BenchmarkerParams},
    config::{Args, BenchmarkType},
};

fn run_bench_reauth(_args: Args, _file_config: FileConfig, running: Arc<AtomicBool>) {
	let sender_addr = "0.0.0.0:5555".to_string();
	let seed = 40;
	let target_addr = "127.0.0.1:5555".to_string();
	let target_name = "alice".to_string();
    let key_lifetime = 3;
    let forward_cert = 1;
    let max_delivery_deadline = Duration::from_millis(100);
    let max_piece_size = 1024 * 1024 * 4;
    let key_dist = vec![vec![4, 100], vec![2, 0], vec![1, 0]];
    let id_dir = config::ID_DIR.to_string();
    let id_filename = config::ID_FILENAME.to_string();
    let datagram_size = 2_usize.pow(15);
    let net_buffer_size = 2_usize.pow(16);
    let subscriber_lifetime = Duration::from_secs(5);

    let recv_params = BenchmarkerParams {
        running,
		sender_addr,
		seed,
		target_addr,
		target_name,
        key_lifetime: key_lifetime,
        cert_interval: forward_cert,
        delivery_deadline: max_delivery_deadline,
        max_piece_size,
        key_dist,
        id_dir,
        id_filename,
        datagram_size,
        net_buffer_size,
        subscriber_lifetime,
    };
    info!("Running a benchmark with configuration: {recv_params:#?}");

    let mut bench = Benchmarker::new(recv_params);
    bench.benchmark_reauth();
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

    for t in config::USED_LOG_TAGS {
        info!(tag: t, "+++++++++++++++++++++++++++++++++");
        info!(tag: t, "+++++++++ PROGRAM START +++++++++");
        info!(tag: t, "+++++++++++++++++++++++++++++++++");
    }

    running
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileConfig {
    key_dist: Vec<Vec<usize>>,
}

fn main() {
    if let Err(e) = config::setup_logger() {
        panic!("Unable to initialize the logger!\nERROR: {}", e);
    }

    // Override with cmd args
    let args = Args::parse();
    let running = init_application();

    let config_str = std::fs::read_to_string(&args.config).expect("Failed to read config file");
    let config: FileConfig = toml::from_str(&config_str).expect("Failed to parse config file");

    // Sender mode
    match args.bench_type {
        BenchmarkType::ReAuthenticationTime => run_bench_reauth(args, config, running),
    }
}
