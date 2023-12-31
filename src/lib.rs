//!
//! <PROJECT_NAME> is an implementation of the hash-based authentication protocol for streamed data.
//!
mod block_signer;
mod buffer_tracker;
mod constants;
mod delivery_queues;
mod diag_server;
mod horst;
mod merkle_tree;
mod net_receiver;
mod net_sender;
mod pub_key_store;
mod receiver;
mod receiver_sim;
mod sender;
mod sender_sim;
mod traits;
// ---
pub mod common;
pub mod utils;
// ---
pub use common::Config;
pub use horst::HorstSigScheme;
pub use receiver::{Receiver, ReceiverParams};
pub use receiver_sim::ReceiverSim;
pub use sender::{Sender, SenderParams};
pub use sender_sim::SenderSim;
pub use traits::{FtsSchemeTrait, ReceiverTrait, SenderTrait};
