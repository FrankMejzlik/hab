use std::io::BufWriter;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
// ---
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rayon::prelude::*;
// ---
use hab::common::MessageAuthentication;
use hab::utils;
use hab::ReceiverSim;
use hab::SenderSim;
#[allow(unused_imports)]
use hab::{debug, error, info, log_input, trace, warn};
use hab::{ReceiverParams, SenderParams};

#[derive(Debug)]
pub struct BenchmarkerParams {
    pub running: Arc<AtomicBool>,
}

pub struct Benchmarker {
    #[allow(dead_code)]
    params: BenchmarkerParams,
}

impl Benchmarker {
    pub fn new(params: BenchmarkerParams) -> Self {
        Benchmarker { params }
    }

    pub fn benchmark_reauth(&mut self) {
        const REPS: usize = 1000;

		let configs = vec![
			("exp", vec![
				vec![1024, 0],
				vec![256, 0],
				vec![64, 0],
				vec![16, 0],
				vec![4, 0],
				vec![1, 0],
			]),
			("lin", vec![
				vec![1354, 0],
				vec![1083, 0],
				vec![812, 0],
				vec![542, 0],
				vec![271, 0],
				vec![1, 0],
			]),
			("log", vec![
				vec![1360, 0],
				vec![1357, 0],
				vec![1344, 0],
				vec![1286, 0],
				vec![1040, 0],
				vec![1, 0],
			]),
		];
        
		configs.par_iter().for_each(|(key_strat_name, key_dist)| {
			
			// let pre_certs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
			// let key_chargess = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 25, 30];

			let pre_certs = [4, 6, 8];
			let key_chargess = [10, 20];

			// Desired probability to have the highest level keys in the identity
			let p_w = 0.99;
			let p_w_c = 1f64 - p_w;

			let probs = utils::lifetimes_to_probs(&key_dist);
			let prob_0 = probs[0];
			let n_prob_90 = (p_w_c.log2() / (1.0 - prob_0).log2()).ceil() as usize;
			println!("prob_0: {:?}", prob_0);
			println!("iprob_0: {:?}", 1.0 / prob_0);
			println!("n_prob_90: {:?}", n_prob_90);
			println!("It is required to receive at least {n_prob_90} messages to have {p_w} probability of having the highest level keys in the identity...");

			
			// Run in parallel over the configurations
			key_chargess.par_iter().for_each(|key_charges| {
				pre_certs.par_iter().for_each(|pre_cert| {
					println!("key_charges: {key_charges}, pre_cert: {pre_cert}");

					// Calculate appropriate number of missed messages
					let max_missed = (pre_cert + 1) * key_charges * 1500;

					let mut nums_mised: Vec<usize> = (1..=200).collect();
					let mut next2: Vec<usize> = (200..=1500).step_by(5).collect();
					let mut next3: Vec<usize> = (1500..=max_missed).step_by(10).collect();
					nums_mised.append(&mut next2);
					nums_mised.append(&mut next3);

					// Open TSV file for writing per-line
					let file = std::fs::File::create(format!(
						"plots/data/reauth_approx/reauth__{key_strat_name}__{key_charges}__{pre_cert}.tsv"
					))
					.unwrap();
					let mut writer = BufWriter::new(file);
					writeln!(
						writer,
						"key_strategy\tkey_charges\tPC\tnum_received\tnum_missed\tnum_to_reauth"
					).unwrap();

					// Compute theoretical approximation
					let (xs, ys) = calc_reauth_times(&key_dist, *pre_cert);

					for (x, y) in xs.into_iter().zip(ys.into_iter()) {
						let x = x.round() as usize;
						let y = y.round() as usize;
						writeln!(writer, "{key_strat_name}\t{key_charges}\t{pre_cert}\t0\t{x}\t{y}").unwrap();
					}
					writer.flush().unwrap();

					// Open TSV file for writing per-line
					let file = std::fs::File::create(format!(
						"plots/data/reauth/reauth__{key_strat_name}__{key_charges}__{pre_cert}.tsv"
					))
					.unwrap();
					let mut writer = BufWriter::new(file);
					writeln!(
						writer,
						"key_strategy\tkey_charges\tPC\tnum_received\tnum_missed\tnum_to_reauth"
					)
					.unwrap();

					

					// Seed the RNG
					let mut seed_rng = ChaCha20Rng::seed_from_u64(42);

					// Iterate over the number repetitions
					for rep in 0..REPS {
						println!("\t\tRepetition: {rep}");

						// Seed the iteration
						let seed = seed_rng.gen::<u64>();

						let sender_params = SenderParams {
							id_filename: String::default(),
							seed: seed,
							key_dist: key_dist.clone(),
							pre_cert: *pre_cert,
							max_piece_size: 0,
							datagram_size: 0,
							receiver_lifetime: Duration::from_secs(0),
							sender_addr: "".to_string(),
							key_charges: Some(*key_charges),
							dgram_delay: Duration::from_secs(0),
							running: Arc::new(AtomicBool::new(true)),
							alt_output: None,
						};

						let receiver_params = ReceiverParams {
							running: Arc::new(AtomicBool::new(true)),
							target_addr: "".to_string(),
							target_name: "alice".to_string(),
							id_filename: String::default(),
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
						for _ in 0..n_prob_90 {
							let signed_message = sender.broadcast(0);
							receiver.receive(signed_message);
						}

						// Iterate over the list of number of misses
						let mut prev_miss = 0;
						for num_miss in nums_mised.iter() {
							let to_miss = num_miss - prev_miss;
							prev_miss = *num_miss;
							// println!("num_miss: {num_miss}, to_miss: {to_miss}");
							// Miss
							for _ in 0..to_miss {
								sender.broadcast(0);
							}

							// Take local copies with the correct number of missed messages
							let mut sender3 = sender.clone();
							let mut receiver3 = receiver.clone();

							// Try to reauthenticate
							let mut re_auth_at = 0;
							for i in 0..n_prob_90 {
								let signed_message = sender3.broadcast(0);
								
								let verify_result = receiver3.receive(signed_message);

								match verify_result.verification {
									MessageAuthentication::Authenticated(_) => {
										re_auth_at = i + 1;
										break;
									}
									_ => (),
								}
							}
							let re_auth_str = if re_auth_at == 0 {
								"NA".to_string()
							}else {
								re_auth_at.to_string()
							};
							writeln!(writer, "{key_strat_name}\t{key_charges}\t{pre_cert}\t{n_prob_90}\t{num_miss}\t{re_auth_str}").unwrap();

							// println!("{num_miss}\t{re_auth_at}");
							// utils::input();
						}
						writer.flush().unwrap()
					}
				});
			});
		});
    }
}

fn durs_to_irates(key_durs: &Vec<usize>) -> (Vec<f64>, Vec<f64>) {

    // Find the maximum from key_durs
    let max_key_dur = key_durs.iter().cloned().fold(usize::MIN, usize::max);

    // Convert key durations to key probabilities
    let key_weights: Vec<usize> = key_durs.iter().map(|&k_dur| max_key_dur / k_dur).collect();

    let total_weight: f64 = key_weights.iter().sum::<usize>() as f64;
    let key_probs: Vec<f64> = key_weights.iter().map(|&k_w| k_w as f64 / total_weight).collect();

    // Convert key probabilities to key rates
    let key_rates: Vec<f64> = key_probs.iter().map(|&k_p| 1.0 / k_p).collect();

    (key_rates, key_probs)
}

fn calc_reauth_times(durss: &Vec<Vec<usize>>, pc: usize) -> (Vec<f64>, Vec<f64>) {
	let durs: Vec<usize> = durss.iter().map(|tuple| tuple[0]).collect();

    let (irates, probs) = durs_to_irates(&durs);

    let mut xs = irates.into_iter().rev().collect::<Vec<f64>>();
    xs.iter_mut().for_each(|x| *x = *x * (pc as f64 + 1.0));

    let mut ys = vec![];
    let key_probs = probs.into_iter().rev().collect::<Vec<f64>>();

    for (i, _) in key_probs.iter().enumerate() {
        let mut prob = 0.0;
        for it in i..key_probs.len() {
            prob += key_probs[it];
        }

        ys.push(1.0 / prob);
    }

    (xs, ys)
}
