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

    use crate::common::MessageAuthentication;
    use crate::{ReceiverParams, ReceiverSim, SenderParams, SenderSim, utils};

	const REPS : usize = 100;

    #[test]
    fn test_simulator() {

		let key_dist = vec![
            vec![65536, 0],
            vec![16384, 0],
            vec![8192, 0],
            vec![4096, 0],
            vec![1024, 0],
            vec![256, 0],
            vec![64, 0],
            vec![16, 0],
            vec![4, 0],
            vec![1, 0],
        ];
        let pre_cert = 1;
		let key_charges = 1;

		let probs = utils::lifetimes_to_probs(&key_dist);
		let prob_0 = probs[0];
		let n_prob_90 = (0.1f64.log2() / (1.0-prob_0).log2()).ceil() as usize;
		println!("prob_0: {:?}", prob_0);
		println!("iprob_0: {:?}", 1.0 / prob_0);
		println!("n_prob_90: {:?}", n_prob_90);

        let sender_params = SenderParams {
            id_filename: "id_filename".to_string(),
            seed: 42,
            key_dist,
            pre_cert,
            max_piece_size: 0,
            datagram_size: 0,
            receiver_lifetime: Duration::from_secs(0),
            sender_addr: "".to_string(),
            key_charges: Some(key_charges),
            dgram_delay: Duration::from_secs(0),
            running: Arc::new(AtomicBool::new(true)),
            alt_output: None,
        };

        let receiver_params = ReceiverParams {
            running: Arc::new(AtomicBool::new(true)),
            target_addr: "".to_string(),
            target_name: "alice".to_string(),
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


		// Receive until prob of having all keys is at lest 0.9
		println!("Receiving until prob of having all keys is at lest 0.9: {n_prob_90} receives...");
		for _ in 0..n_prob_90 {
			let signed_message = sender.broadcast(0);
			receiver.receive(signed_message);
		}
		println!("Keys cached...");

        for miss in 1..1000 {
			// Copy the instances
			let mut sender = sender.clone();
			let mut receiver = receiver.clone();

			let mut res = vec![];
			let mut cnt = 0;
			for _ in 0..REPS{		

				// Miss
				for _ in 0..miss {
					sender.broadcast(0);
				}

				// Try to reauthenticate
				let mut x = 0;
				for i in 0..n_prob_90 {
					let signed_message = sender.broadcast(0);
					let verify_result = receiver.receive(signed_message);

					match verify_result.verification {
						MessageAuthentication::Authenticated(_) => {
							x = i +1;
							cnt+=1;
							break;
						},
						_ => ()
					}
				}
				res.push(x);
			}
			if res.len() == 0 {
				break;
			}

			res.sort();
			let half = res.len() / 2;
			println!("miss: {}, len: {}, Median: {}",miss,cnt,  res[half]);

            //println!("RES: {:?}", verify_result.verification);
            //utils::input();
        }

        println!("Finished.");
    }
}
