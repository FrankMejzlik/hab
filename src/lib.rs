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

#[cfg(test)]
mod tests {

    use std::sync::{atomic::AtomicBool, Arc};

    use std::time::Duration;

    use crate::{ReceiverParams, ReceiverSim, SenderParams, SenderSim};

    #[test]
    fn test_simulator() {
        let sender_params = SenderParams {
            id_filename: "id_filename".to_string(),
            seed: 42,
            key_dist: vec![vec![4, 100], vec![2, 0], vec![1, 0]],
            pre_cert: 2,
            max_piece_size: 0,
            datagram_size: 0,
            receiver_lifetime: Duration::from_secs(0),
            sender_addr: "".to_string(),
            key_charges: Some(1),
            dgram_delay: Duration::from_secs(0),
            running: Arc::new(AtomicBool::new(true)),
            alt_output: None,
        };

        let receiver_params = ReceiverParams {
            running: Arc::new(AtomicBool::new(true)),
            target_addr: "".to_string(),
            target_name: "".to_string(),
            id_filename: "".to_string(),
            distribute: None,
            heartbeat_period: Duration::from_secs(0),
            delivery_delay: Duration::from_secs(0),
            frag_timeout: Duration::from_secs(0),
            dgram_delay: Duration::from_secs(0),
            receiver_lifetime: Duration::from_secs(0),
            deliver: false,
            alt_input: None,
        };

        let mut sender = SenderSim::new(sender_params);
        let mut receiver = ReceiverSim::new(receiver_params);

        let signed_message = sender.broadcast(0);
        let verify_result = receiver.receive(signed_message);
        println!("verify_result: {:#?}", verify_result);

        println!("Finished.");
    }
}
