use hab::common::MsgVerification;
use rand::{Rng, SeedableRng};
use std::io::BufWriter;
use std::io::Write;
use std::sync::Arc;
use std::sync::{atomic::AtomicBool, mpsc::channel};
use std::time::Duration;
// ---
// ---
#[allow(unused_imports)]
use hab::{debug, error, info, log_input, trace, warn};
use hab::{Receiver, ReceiverParams, ReceiverTrait, Sender, SenderParams, SenderTrait};

use crate::config::{self, BlockSignerInst};

#[derive(Debug)]
pub struct BenchmarkerParams {
    pub running: Arc<AtomicBool>,
}

pub struct Benchmarker {
    params: BenchmarkerParams,
}

impl Benchmarker {
    pub fn new(params: BenchmarkerParams) -> Self {
        Benchmarker { params }
    }

    pub fn benchmark_reauth(&mut self) {
        let running = self.params.running.clone();
        let sender_addr = "0.0.0.0:5555".to_string();
        let target_addr = "127.0.0.1:5555".to_string();
        let target_name = "alice".to_string();
        let max_delivery_deadline = Duration::from_millis(100);
        let max_piece_size = 1024 * 1024 * 4;
        let subscriber_lifetime = Duration::from_secs(5);
        let id_dir = config::ID_DIR.to_string();
        let datagram_size = 2_usize.pow(15);
        let net_buffer_size = 2_usize.pow(16);

        // ---

        let seed_seed = 42;

        let key_selection_name = "skip-exponential";
        let key_dist = vec![
            vec![65536, 100],
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
        let key_lifetime = 1;
        let pre_cert = 1;

        const REPS: usize = 200;
        let NUMS_MISSED  : Vec<usize> = (1..=200).collect();
        const MAX_REAUTH_ITER: usize = 500;

        let message = b"hello".to_vec();

        // Open TSV file for writing per-line
        let file = std::fs::File::create("reauth_time.tsv").unwrap();
        let mut writer = BufWriter::new(file);
        writeln!(
            writer,
            "key_selection\tkey_lifetime\tPC\tnum_received\tnum_missed\tnum_to_reauth"
        )
        .unwrap();

        // Seed an RNG with 42
        let mut seed_rng = rand::rngs::StdRng::seed_from_u64(seed_seed);

        for num_miss in NUMS_MISSED {
            let num_received = num_miss * 2;
            let mut ress = vec![];
            for _ in 0..REPS {
                // Sample from `seed_rng` to get a new seed
                let seed = seed_rng.gen::<u64>();

                // Remove identity file
                let _ = std::fs::remove_file(format!("{}/.identity_sender_01", id_dir.clone()));
                let _ = std::fs::remove_file(format!("{}/.identity_receiver_01", id_dir.clone()));

                let (sender_output, receiver_input) = channel();

                let mut receiver: Receiver<BlockSignerInst> = Receiver::new(ReceiverParams {
                    running: running.clone(),
                    target_addr: target_addr.clone(),
                    target_name: target_name.clone(),
                    id_dir: id_dir.clone(),
                    id_filename: ".identity_receiver_01".to_string(),
                    datagram_size: datagram_size,
                    net_buffer_size: net_buffer_size,
                    key_lifetime: key_lifetime,
                    cert_interval: pre_cert,
                    delivery_deadline: max_delivery_deadline,
                    alt_input: Some(receiver_input),
                });

                let mut sender: Sender<BlockSignerInst> = Sender::new(SenderParams {
                    addr: sender_addr.clone(),
                    running: running.clone(),
                    seed: seed,
                    id_dir: id_dir.clone(),
                    id_filename: ".identity_sender_01".to_string(),
                    datagram_size: datagram_size,
                    net_buffer_size: net_buffer_size,
                    subscriber_lifetime: subscriber_lifetime,
                    key_lifetime: key_lifetime,
                    cert_interval: pre_cert,
                    max_piece_size: max_piece_size,
                    key_dist: key_dist.clone(),
                    alt_output: Some(sender_output),
                });

                //
                // Receive `num_rec` messages
                //
                for _ in 0..num_received {
                    sender.broadcast(message.clone()).unwrap();
                    let received_data = receiver.receive().unwrap();

                    assert_eq!(
                        message, received_data.data,
                        "The received message is incorrect!"
                    );
                }

                //
                // Miss `num_miss` messages
                //
                receiver.ignore_next(num_miss);
                for _ in 0..num_miss {
                    sender.broadcast(message.clone()).unwrap();
                }

                //
                // Count when re-auth happens
                //
                let mut reauth_count = MAX_REAUTH_ITER;
                for reauth_i in 0..MAX_REAUTH_ITER {
                    sender.broadcast(message.clone()).unwrap();
                    let received_data = receiver.receive().unwrap();

                    if let MsgVerification::Verified(_) = received_data.sender {
                        reauth_count = reauth_i;
                        break;
                    }
                }
                let re_auth_at = reauth_count + 1;
                ress.push(re_auth_at);
                writeln!(writer, "{key_selection_name}\t{key_lifetime}\t{pre_cert}\t{num_received}\t{num_miss}\t{re_auth_at}").unwrap();
            }
            println!(
                "num_rec: {}; num_miss: {}; reauth_i: {:?}",
                num_received, num_miss, ress
            );
        }
        writer.flush().unwrap()
    }
}
