//!
//! General static config file where you can tune the desired protocol paramters.
//!

/// A directory where the identity files lie (e.g. `BlockSigner` with secret & public keys).
pub const ID_DIR: &str = ".identity/";
/// A name of the file where the state of `BlockSigner` is serialized.
pub const ID_FILENAME: &str = "id.bin";

/// A directory where we store the logs by default (e.g. when you run `cargo run`)
pub const LOGS_DIR: &str = "logs/";
/// A directory for output of signed blocks that the SENDER boradcasts.
#[allow(dead_code)]
pub const INPUT_DBG_DIR: &str = "logs/input/";
/// A directory for output of signed blocks that the RECEIVER receives.
#[allow(dead_code)]
pub const OUTPUT_DBG_DIR: &str = "logs/output/";

/// How long we will keep the subscriber alive without receiving another heartbeat.
pub const SUBSCRIBER_LIFETIME: u128 = 10_000;
/// Size of the buffer used to receive UDP datagrams.
pub const BUFFER_SIZE: usize = 1024;
/// Size of the datagram we send over the UDP prorocol.
pub const DATAGRAM_SIZE: usize = 512;
/// A maximum number of keys per layer stored at the receiver.
pub const MAX_PKS: usize = 3;
