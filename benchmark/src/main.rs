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

fn run_bench_reauth(args: Args, _file_config: FileConfig, running: Arc<AtomicBool>) {
    let mut bench = Benchmarker::new(BenchmarkerParams {
        running: running.clone(),
    });

    let configs = vec![
        (
            "exp",
            vec![
                vec![1024, 0],
                vec![256, 0],
                vec![64, 0],
                vec![16, 0],
                vec![4, 0],
                vec![1, 0],
            ],
        ),
        (
            "lin",
            vec![
                vec![1354, 0],
                vec![1083, 0],
                vec![812, 0],
                vec![542, 0],
                vec![271, 0],
                vec![1, 0],
            ],
        ),
        (
            "log",
            vec![
                vec![1360, 0],
                vec![1357, 0],
                vec![1344, 0],
                vec![1286, 0],
                vec![1040, 0],
                vec![1, 0],
            ],
        ),
    ];
	
    // If real-world parameters should be benchmarked (takes a long time)
    if args.real_params {
        println!("Running with real-world parameters...");
        let reps = 1000;
        let pre_certs = vec![4, 6, 8];
        let key_chargess = vec![10, 20];
        bench.benchmark_reauth(configs, pre_certs, key_chargess, reps);
    }
    // If minimal parameters should be benchmarked
    else {
        println!("Running with minimal parameters...");
        let reps = 1000;
        let pre_certs = vec![1, 2, 4];
        let key_chargess = vec![1, 2, 4];
        bench.benchmark_reauth(configs, pre_certs, key_chargess, reps);
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
	println!("{:?}",args.real_params);
    let running = init_application();

    let config_str = std::fs::read_to_string(&args.config).expect("Failed to read config file");
    let config: FileConfig = toml::from_str(&config_str).expect("Failed to parse config file");

    // Sender mode
    match args.bench_type {
        BenchmarkType::Reauth => run_bench_reauth(args, config, running),
    }
}
