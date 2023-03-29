//!
//! General static config file where you can tune the desired protocol paramters.
//!

// ---
use cfg_if::cfg_if;
use clap::Parser;
use rand_chacha::ChaCha20Rng;
use sha3::Sha3_512;
// ---
use hab::utils;
use hab::BlockSigner;
// ---
use crate::config;

/// A directory where the identity files lie (e.g. `BlockSigner` with secret & public keys).
pub const ID_DIR: &str = ".identity/";

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

// ***************************************
//             PARAMETERS
// ***************************************
cfg_if! {
    // *** PRODUCTION ***
    if #[cfg(not(feature = "debug"))] {
        /// Size of the hashes in a Merkle tree
        const N: usize = 512 / 8;
        /// Number of SK segments in signature
        const K: usize = 32;
        /// Depth of the Merkle tree (without the root layer)
        const TAU: usize = 16;

        // --- Random generators ---
        /// A seedable CSPRNG used for number generation
        type CsPrng = ChaCha20Rng;

        // --- Hash functions ---
        // Hash fn for message hashing. msg: * -> N
        type MsgHashFn = Sha3_512;
        // Hash fn for tree & secret hashing. sk: 2N -> N & tree: N -> N
        type TreeHashFn = Sha3_512;
    }
    // *** DEBUG ***
    else {
        use sha3::{Sha3_256};

        /// Size of the hashes in a Merkle tree
        const N: usize = 256 / 8;
        /// Number of SK segments in signature
        const K: usize = 64;
        /// Depth of the Merkle tree (without the root layer)
        const TAU: usize = 4;

        // --- Random generators ---
        /// A seedable CSPRNG used for number generation
        type CsPrng = ChaCha20Rng;

        // --- Hash functions ---
        // Hash fn for message hashing. msg: * -> N
        type MsgHashFn = Sha3_256;
        // Hash fn for tree & secret hashing. sk: 2N -> N & tree: N -> N
        type TreeHashFn = Sha3_256;
    }
}

// ---
const T: usize = 2_usize.pow(TAU as u32);
const MSG_HASH_SIZE: usize = (K * TAU) / 8;
const TREE_HASH_SIZE: usize = N;

// Alias for the specific signer/verifier we'll be using.
pub type BlockSignerInst = BlockSigner<
    K,
    TAU,
    { TAU + 1 },
    T,
    MSG_HASH_SIZE,
    TREE_HASH_SIZE,
    CsPrng,
    MsgHashFn,
    TreeHashFn,
>;

// ***
// The clap config for command line arguments.
// ***

/// Types of benchmarks that can be run.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum BenchmarkType {
    /// Time to re-authenticate.
    ReAuthenticationTime,
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
