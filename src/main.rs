mod horst;
mod merkle_tree;
mod signature_scheme;
mod utils;
// ---
use clap::Parser;
use log::debug;
use simple_logger::SimpleLogger;
// ---
use horst::{HorstPublicKey, HorstSecretKey, HorstSigScheme};
use signature_scheme::SignatureScheme;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// PRNG seed
    #[clap(short, long, default_value_t = 42)]
    seed: u64,
}

fn main() {
    SimpleLogger::new().init().unwrap();
    let args = Args::parse();

	for h in 0..4 {
		debug!("h: {}", h);
	}

	for h in (0..4).rev() {
		debug!("h: {}", h);
	}

    let msg = b"Hello, world!";

    let mut alice_signer = HorstSigScheme::new(args.seed);
    let mut eve_signer = HorstSigScheme::new(args.seed);

    //
    // Alice signs
    //
    let alice_key_pair = alice_signer.gen_key_pair();
    debug!("{}", alice_key_pair);
    let alice_sign = alice_signer.sign(msg);
    debug!("{}", alice_sign);

    //
    // Eve attacker signs
    //
    let eve_key_pair = eve_signer.gen_key_pair();
    debug!("{}", eve_key_pair);
    let eve_sign = eve_signer.sign(msg);
	debug!("{}", eve_sign);

    //
    // Bob verifies
    //
    let bob_from_alice_valid = HorstSigScheme::verify(&alice_sign, &alice_key_pair.public);
    assert!(bob_from_alice_valid, "The valid signature was rejected!");

    let bob_from_eve_valid = HorstSigScheme::verify(&eve_sign, &alice_key_pair.public);
    assert!(!bob_from_eve_valid, "The invalid signature was rejected!");
}
