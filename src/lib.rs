//!
//! <PROJECT_NAME> is an implementation of the hash-based authentication protocol for streamed data.
//!
mod block_signer;
mod common;
mod config;
mod diag_server;
mod horst;
mod merkle_tree;
mod net_receiver;
mod net_sender;
mod sender;
mod receiver;
mod traits;
// ---
pub mod utils;
// ---
pub use block_signer::BlockSigner;
pub use sender::{Sender, SenderParams};
pub use receiver::{Receiver, ReceiverParams};
pub use traits::{SenderTrait, ReceiverTrait};
