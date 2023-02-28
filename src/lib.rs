//!
//! <PROJECT_NAME> is an implementation of the hash-based authentication protocol for streamed data.
//!
mod block_signer;
mod diag_server;
mod horst;
mod merkle_tree;
mod net_receiver;
mod net_sender;
mod receiver;
mod sender;
mod traits;
// ---
pub mod common;
pub mod utils;
// ---
pub use block_signer::BlockSigner;
pub use traits::{Config, ReceiverTrait, SenderTrait};

pub use receiver::{Receiver, ReceiverParams};
pub use sender::{Sender, SenderParams};
