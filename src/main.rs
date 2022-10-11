mod common;
mod crypto_hash;
mod lamport_signer;
mod signer;
mod utils;
// ---
use clap::Parser;
use sha3::{Digest, Keccak256, Keccak512};
// ---
use crate::signer::Signer;
use lamport_signer::LamportSigner;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {}

fn main() {
    let _args = Args::parse();

    let small_hash = Keccak256::new();
    let large_hash = Keccak512::new();

    let _signer = LamportSigner::new(small_hash, large_hash);
}
