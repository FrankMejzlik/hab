mod common;
mod crypto_hash;
mod lamport_signer;
mod signer;
mod utils;
// ---
use clap::Parser;
// ---
use crate::signer::Signer;
use lamport_signer::LamportSigner;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// PRNG seed
    #[clap(short, long, default_value_t = 42)]
    seed: u64,
}

fn main() {
    let args = Args::parse();

    let signer = LamportSigner::new(args.seed);

	let msg = b"Hello, world!";
	let (priv_key, pub_key) = signer.gen_key_pair();

	let packet = signer.sign(msg, priv_key);

	let is_ok = signer.verify(&packet.sign, pub_key);
	println!("is_ok: {}", is_ok);
}
