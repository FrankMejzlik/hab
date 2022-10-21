mod lamport_signature_scheme;
mod signature_scheme;
mod utils;
// ---
use clap::Parser;
// ---
use crate::signature_scheme::SignatureScheme;
use lamport_signature_scheme::LamportSignatureScheme;

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

    let msg = b"Hello, world!";

    let mut alice_signer = LamportSignatureScheme::new(args.seed);
    let mut eve_signer = LamportSignatureScheme::new(args.seed);
    let bob_verifier = LamportSignatureScheme::new(args.seed);

    //
    // Alice signs
    //
    let alice_key_pair = alice_signer.gen_key_pair();
    let alice_packet = alice_signer.sign(msg, &alice_key_pair.private);

    //
    // Eve attacker signs
    //
    let eve_key_pair = eve_signer.gen_key_pair();
    let eve_packet = eve_signer.sign(msg, &eve_key_pair.private);

    //
    // Bob verifies
    //
    let bob_from_alice_valid = bob_verifier.verify(&alice_packet.sign, &alice_key_pair.public);
    assert!(bob_from_alice_valid, "The valid signature was rejected!");

    let bob_from_eve_valid = bob_verifier.verify(&eve_packet.sign, &alice_key_pair.public);
    assert!(!bob_from_eve_valid, "The invalid signature was rejected!");
}
