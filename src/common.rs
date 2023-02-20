//!
//! Code shared throught the project.
//!

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::mem::size_of;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
// ---
use clap::Parser;
use rand::{distributions::Distribution, Rng};
// ---
use crate::config;
use crate::utils;

//
// Usefull type aliases
//
pub type UnixTimestamp = u128;
pub type SubscribersMapArc = Arc<Mutex<BTreeMap<SocketAddr, UnixTimestamp>>>;
pub type PortNumber = u16;
pub type DgramHash = u64;
pub type DgramIdx = u32;

pub fn get_datagram_sizes() -> (usize, usize, usize) {
    let header_size = size_of::<DgramHash>() + 2 * size_of::<DgramIdx>();
    let payload_size = config::DATAGRAM_SIZE - header_size;

    (config::DATAGRAM_SIZE, header_size, payload_size)
}

///
/// A weighed discrete distribution.
///
/// The provided weights of the distribution do NOT need to sum up to 1.
/// Only the proportion of the total sum matters.
///
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscreteDistribution {
    /// Weights of the discrete events (no need to sum up to 1).
    weights: Vec<f64>,
}

impl DiscreteDistribution {
    ///
    /// Constructs the discrete distribution with the probabilities proportional to the provided weights.
    ///
    /// # Arguments
    /// * `weights` - Weights to determine the probability of the given event (index) to occur.
    ///
    pub fn new(weights: Vec<f64>) -> DiscreteDistribution {
        DiscreteDistribution { weights }
    }
}

impl Distribution<usize> for DiscreteDistribution {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> usize {
        let total_weight: f64 = self.weights.iter().sum();
        let threshold = total_weight * rng.gen::<f64>();

        let mut cumulative_weight = 0.0;
        for (value, weight) in (0..self.weights.len()).zip(self.weights.iter()) {
            cumulative_weight += weight;
            if cumulative_weight >= threshold {
                return value;
            }
        }
        unreachable!()
    }
}

// ***
// The general error type we're using throught this program.
// ***

/// General error type used in this binary.
#[derive(Debug)]
pub struct Error {
    msg: String,
}
impl Error {
    pub fn new(msg: &str) -> Self {
        Error {
            msg: msg.to_string(),
        }
    }
}

/// The error must be printable.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

/// Implement the std::error::Error interface.
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
    fn description(&self) -> &str {
        &self.msg
    }
    fn cause(&self) -> Option<&dyn StdError> {
        None
    }
}

// ***
// The clap config for command line arguments.
// ***

/// Modes in which the progarm can operate.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ProgramMode {
    /// The broadcaster of the data.
    Sender,
    /// The subscriber to the broadcasters.
    Receiver,
}

/// Define the CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    // --- required ---
    /// What mode to launch the program in.
    #[clap(value_enum)]
    pub mode: ProgramMode,
    /// The address of the sender.
    #[clap()]
    pub addr: String,

    // --- optional ---
    /// Seed used for the CSPRNG.
    #[clap(short, long, default_value_t = 42)]
    pub seed: u64,
    /// The input source file (if none, STDIN for sender, network for receiver)
    #[clap(short, long)]
    pub input: Option<String>,
    /// The output source file (if none, STDOUT for receiver, network for sender)
    #[clap(short, long)]
    pub output: Option<String>,
    /// A desired number of key layers to use (for sender only)
    #[clap(long, default_value_t = 8)]
    pub layers: usize,
}

///
/// Setups the logger so it ignores the debug & trace logs in the third-party libs.
///
pub fn setup_logger() -> Result<(), fern::InitError> {
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
        .level(log::LevelFilter::Warn)
        // Allow for this module
        .level_for(utils::binary_name(), log::LevelFilter::Trace)
        //.chain(std::io::stdout())
        .chain(fern::log_file(format!("{}/output.log", config::LOGS_DIR))?)
        .apply()?;
    Ok(())
}

///
/// Wrapper around the standard logging macros to accept also tag and log the messages
/// also to separate files per tag.
///

#[macro_export]
macro_rules! trace {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Trace {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),

                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            //log::trace!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::trace!($($arg)+);
    }};
}

#[macro_export]
macro_rules! debug {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Debug {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),
                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            //log::debug!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::debug!($($arg)+);
    }};
}

#[macro_export]
macro_rules! info {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Info {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),
                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            //log::info!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::info!($($arg)+);
    }};

}

#[macro_export]
macro_rules! warn {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Info {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),
                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            //log::warn!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::warn!($($arg)+);
    }};

}

#[macro_export]
macro_rules! error {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Info {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),
                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            //log::error!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::error!($($arg)+);
    }};

}

/// A global counter for the number of processed input data blocks.
pub static LOG_INPUT_COUNTER: AtomicUsize = AtomicUsize::new(0);
/// A global counter for the number of processed output data blocks.
pub static LOG_OUTPUT_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[macro_export]
macro_rules! log_input {
    ($hash:expr, $data:expr) => {{
        use crate::common::LOG_INPUT_COUNTER;
        use crate::config::INPUT_DBG_DIR;
        use std::io::Write;
        use std::sync::atomic::Ordering;

        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!(
                "{}/{:06}_{:020}.in",
                INPUT_DBG_DIR,
                LOG_INPUT_COUNTER.load(Ordering::Acquire),
                $hash
            ))
            .unwrap();

        log_file.write_all($data).unwrap();
        LOG_INPUT_COUNTER.fetch_add(1, Ordering::Release);
    }};
}

#[macro_export]
macro_rules! log_output {
    ($hash:expr, $data:expr) => {{
        use crate::common::LOG_OUTPUT_COUNTER;
        use crate::config::OUTPUT_DBG_DIR;
        use std::io::Write;
        use std::sync::atomic::Ordering;

        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!(
                "{}/{:06}_{:020}.out",
                OUTPUT_DBG_DIR,
                LOG_OUTPUT_COUNTER.load(Ordering::Acquire),
                $hash
            ))
            .unwrap();

        log_file.write_all($data).unwrap();
        LOG_OUTPUT_COUNTER.fetch_add(1, Ordering::Release);
    }};
}

#[cfg(test)]
mod tests {

    // ---
    use rand::rngs::OsRng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    // ---
    use super::*;

    // --- Random generators ---
    /// A seedable CSPRNG used for number generation
    type CsPrng = ChaCha20Rng;

    #[test]
    fn test_discrete_distribution() {
        const NUM_ITERS: usize = 1000;
        const DELTA: f32 = 0.75;

        let mut seed_rng = OsRng;
        let random_seed = seed_rng.gen::<u64>();
        let mut rng = CsPrng::seed_from_u64(random_seed);

        let weights = vec![1.0, 2.0, 4.0, 8.0];
        let dist = DiscreteDistribution::new(weights);

        let mut hist = vec![0, 0, 0, 0];
        for _ in 0..NUM_ITERS {
            let idx = dist.sample(&mut rng);
            hist[idx] += 1;
        }
        println!("hist: {hist:?}");

        for (i, x) in hist.iter().enumerate() {
            if i == 0 {
                continue;
            }
            let prev = hist[i - 1];
            assert!(
                (prev as f32) < ((*x as f32) * DELTA),
                "The variance in the samples is too large!"
            );
        }
    }
}
