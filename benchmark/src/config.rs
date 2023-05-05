//!
//! General static config file where you can tune the desired protocol paramters.
//!

// ---
use clap::Parser;
// ---
use hab::utils;
// ---
use crate::config;

/// A directory where we store the logs by default (e.g. when you run `cargo run`)
pub const LOGS_DIR: &str = "logs/";
/// A directory for output of signed blocks that the SENDER boradcasts.
pub const INPUT_DBG_DIR: &str = "logs/input/";
/// A directory for output of signed blocks that the RECEIVER receives.
pub const OUTPUT_DBG_DIR: &str = "logs/output/";

/// List of logging tags that we use throuought the program.
pub const USED_LOG_TAGS: &[&str] = &[
    "output",
    "sender",
    "registrator_task",
    "subscribers",
    "broadcasted",
    "block_signer",
    "receiver",
    "heartbeat_task",
    "received",
    "fragmented_blocks",
    "block_verifier",
    "delivery_queues",
];
/// A period in which the simulated STDIN input will be procuded.
#[cfg(feature = "simulate_stdin")]
//pub const SIM_INPUT_PERIOD: Option<Duration> = Some(Duration::from_millis(10));
pub const SIM_INPUT_PERIOD: Option<Duration> = None;

// ***
// The clap config for command line arguments.
// ***

/// Types of benchmarks that can be run.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum BenchmarkType {
    /// Time to re-authenticate.
    Reauth,
}

/// Define the CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    // --- required ---
    /// What benchmark to run.
    #[clap(value_enum)]
    pub bench_type: BenchmarkType,

    // --- optional ---
    #[clap(short, long, default_value = "config.toml")]
    pub config: String,
}

///
/// Setups the logger so it ignores the debug & trace logs in the third-party libs.
///
pub fn setup_logger() -> Result<(), fern::InitError> {
    std::fs::create_dir_all(config::LOGS_DIR).expect("The logs directory should be created.");

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}] {}",
                //chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                chrono::Local::now().format("%H:%M:%S"),
                record.level(),
                message
            ))
        })
        // Disable all by default
        .level(log::LevelFilter::Info) // TODO: This does now work properly
        // Allow for this module
        .level_for(utils::binary_name(), log::LevelFilter::Trace)
        //.chain(std::io::stdout())
        .chain(fern::log_file(format!("{}/output.log", config::LOGS_DIR))?)
        .apply()?;
    Ok(())
}
