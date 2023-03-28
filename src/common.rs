//!
//! Code shared throught the project.
//!

use serde::{Deserialize, Serialize};
use std::fmt;
use std::mem::size_of;
use std::time::Duration;
use std::{cmp::Ordering, error::Error as StdError};
// ---
use rand::{distributions::Distribution, Rng};

// ---
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

//
// Usefull type aliases
//
pub type UnixTimestamp = u128;
pub type PortNumber = u16;
pub type DgramHash = u64;
pub type MsgSignPubkeysChecksum = u64;
pub type DgramIdx = u32;
pub type SeqNum = u64;
pub type SenderId = u64;

pub const LOGS_DIR: &str = "logs/";

pub fn get_datagram_sizes(dgram_size: usize) -> (usize, usize, usize) {
    let header_size = size_of::<DgramHash>() + 2 * size_of::<DgramIdx>();
    let payload_size = dgram_size - header_size;

    (dgram_size, header_size, payload_size)
}

///
/// Enum describing the states of message verification that can happen.
///
#[derive(Debug)]
pub enum MsgVerification {
    /// Not send by the target identity nor someone certified by it.
    Unverified,
    /// Send by someone who has been certified by the target identity (not proved to be the identity itself).
    Certified(SenderIdentity),
    /// Proved that the target identity signed the message.
    Verified(SenderIdentity),
}

/// The error must be printable.
impl fmt::Display for MsgVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsgVerification::Verified(x) => write!(f, "Verified({:#?})", x.petnames),
            MsgVerification::Certified(x) => write!(f, "Certified({:#?})", x.petnames),
            MsgVerification::Unverified => write!(f, "Unverified"),
        }
    }
}

#[derive(Debug)]
pub struct VerifyResult {
    pub msg: Vec<u8>,
    pub metadata: MsgMetadata,
    pub verification: MsgVerification,
    /// A hash computed as a combination of three parts (msg, signature, pubkeys).
    pub hash: MsgSignPubkeysChecksum,
}

impl Ord for VerifyResult {
    fn cmp(&self, other: &Self) -> Ordering {
        self.metadata.seq.cmp(&other.metadata.seq).reverse()
    }
}

impl PartialOrd for VerifyResult {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.metadata.seq.cmp(&other.metadata.seq).reverse())
    }
}

impl Eq for VerifyResult {}

impl PartialEq for VerifyResult {
    fn eq(&self, other: &Self) -> bool {
        self.metadata.seq == other.metadata.seq
    }
}

///
/// General config of the library.
///
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    pub id_dir: String,
    pub id_filename: String,
    pub logs_dir: String,
    pub subscriber_lifetime: Duration,
    pub net_buffer_size: usize,
    pub datagram_size: usize,
}

///
/// A structure holding additional data about the message that the protocol is transmitting.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgMetadata {
    /// The sequence number of this message.
    pub seq: SeqNum,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
/// Struct holding parameters for the sender.
pub struct BlockSignerParams {
    pub seed: u64,
    /// A directory name where the identity stores will be stored.
    pub id_dir: String,
    /// A filename where the identity sotres will be serialized.
    pub id_filename: String,
    /// User-defined name of the target identity.
    pub target_petname: String,
    /// A number of signatures that one keypair can generate.
    pub key_lifetime: usize,
    /// A number of keys to certify forward (and backward).
    pub cert_interval: usize,
    /// A maximum byte size of payload in one piece.
    pub max_piece_size: usize,
    pub key_dist: Vec<Vec<usize>>,
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Clone)]
pub struct SenderIdentity {
    pub ids: Vec<u64>,
    pub petnames: Vec<String>,
    // If true, the identity still has some nodes in the identity graph and has chance to be re-authenticated.
    pub alive: bool,
}

impl SenderIdentity {
    pub fn new(id: SenderId, petname: String) -> Self {
        SenderIdentity {
            ids: vec![id],
            petnames: vec![petname],
            alive: false,
        }
    }
    pub fn merge(&mut self, mut other: SenderIdentity) {
        self.ids.append(&mut other.ids);
        self.petnames.append(&mut other.petnames);
        info!(tag: "receiver", "(!) Merged IDs to {:#?}. (!)", self);
    }
}

pub struct ReceivedBlock {
    pub data: Vec<u8>,
    pub sender: MsgVerification,
    pub metadata: MsgMetadata,
}

impl ReceivedBlock {
    pub fn new(data: Vec<u8>, sender: MsgVerification, metadata: MsgMetadata) -> Self {
        ReceivedBlock {
            data,
            sender,
            metadata,
        }
    }
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

///
/// Wrapper around the standard logging macros to accept also tag and log the messages
/// also to separate files per tag.
///

#[macro_export]
macro_rules! trace {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use $crate::common::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Trace && log::STATIC_MAX_LEVEL >= log::Level::Trace {
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
        use $crate::common::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Debug && log::STATIC_MAX_LEVEL >= log::Level::Debug {
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
        use $crate::common::LOGS_DIR;
        use std::io::Write;
        if log::max_level() >= log::Level::Info && log::STATIC_MAX_LEVEL >= log::Level::Info {
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
        use $crate::common::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Warn && log::STATIC_MAX_LEVEL >= log::Level::Warn {
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
        use $crate::common::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Error && log::STATIC_MAX_LEVEL >= log::Level::Error {
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

#[macro_export]
macro_rules! log_input {
    ($seq:expr, $hash:expr, $data:expr) => {{
        use std::io::Write;
        use $crate::common::LOGS_DIR;

        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{}/input/{:06}_{:020}.in", LOGS_DIR, $seq, $hash))
            .unwrap();

        log_file.write_all($data).unwrap();
    }};
}

#[macro_export]
macro_rules! log_output {
    ($seq:expr, $hash:expr, $data:expr) => {{
        use std::io::Write;
        use $crate::common::LOGS_DIR;

        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{}/output/{:06}_{:020}.out", LOGS_DIR, $seq, $hash))
            .unwrap();

        log_file.write_all($data).unwrap();
    }};
}

#[macro_export]
macro_rules! log_graph {
    ($graph:expr) => {{
        use std::fs::File;
        use std::process::Command;
        use std::process::Stdio;

        if log::max_level() >= log::Level::Info && log::STATIC_MAX_LEVEL >= log::Level::Info {
            let file = File::create("output.svg").unwrap();
            let outputfile = Stdio::from(file);

            let mut output = Command::new("echo")
                .arg(&format!("{}", $graph))
                .stdout(Stdio::piped())
                .spawn()
                .expect("failed to execute process");

            let pipe = output.stdout.take().unwrap();

            let grep = Command::new("dot")
                .arg("-T")
                .arg("svg")
                .stdin(pipe)
                .stdout(outputfile)
                .spawn()
                .expect("failed to execute process");

            grep.wait_with_output().expect("failed to wait on child");
        }
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
