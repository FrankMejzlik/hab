use std::sync::Arc;
use std::sync::{mpsc::channel, atomic::AtomicBool};
use std::time::Duration;
// ---
#[allow(unused_imports)]
use hab::{debug, error, info, log_input, trace, warn};
use hab::{
    Receiver, ReceiverParams, ReceiverTrait, Sender, SenderParams,  SenderTrait,
};

use crate::config::{BlockSignerInst, self};

#[derive(Debug)]
pub struct BenchmarkerParams {
	pub running: Arc<AtomicBool>,	
	pub sender_addr: String,
	pub target_addr: String,
	pub target_name: String,
	pub seed: u64,
	/// A number of signatures one keypair can generate.
	pub key_lifetime: usize,
	pub cert_interval: usize,
	pub max_piece_size: usize,
	pub delivery_deadline: Duration,
	pub key_dist: Vec<Vec<usize>>,
	pub id_dir: String,
	pub id_filename: String,
	pub datagram_size: usize,
	pub net_buffer_size: usize,
	pub subscriber_lifetime: Duration,
}

pub struct Benchmarker {
    sender: Sender<BlockSignerInst>,
    receiver: Receiver<BlockSignerInst>,
}

impl Benchmarker {
    pub fn new(params: BenchmarkerParams) -> Self {
        let (sender_output, receiver_input) = channel();

        let receiver = Receiver::new(ReceiverParams {
            running: params.running.clone(),
            target_addr: params.target_addr.clone(),
            target_name: params.target_name.clone(),
            id_dir: params.id_dir.clone(),
            id_filename: params.id_filename.clone(),
            datagram_size: params.datagram_size,
            net_buffer_size: params.net_buffer_size,
            key_lifetime: params.key_lifetime,
            cert_interval: params.cert_interval,
            delivery_deadline: params.delivery_deadline,
            alt_input: Some(receiver_input),
        });

        let sender = Sender::new(SenderParams {
            addr: params.sender_addr.clone(),
            running: params.running.clone(),
            seed: params.seed,
            id_dir: params.id_dir,
            id_filename: params.id_filename,
            datagram_size: params.datagram_size,
            net_buffer_size: params.net_buffer_size,
            subscriber_lifetime: params.subscriber_lifetime,
            key_lifetime: params.key_lifetime,
            cert_interval: params.cert_interval,
            max_piece_size: params.max_piece_size,
            key_dist: params.key_dist.clone(),
            alt_output: Some(sender_output),
        });

        Benchmarker { receiver, sender }
    }

    pub fn benchmark_reauth(&mut self) {}
}
