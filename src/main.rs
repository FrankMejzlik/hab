mod lamport_signature_scheme;
mod merkle_tree;
mod signature_scheme;
mod utils;
// ---
use clap::Parser;
use hex::{decode, encode};
use log::debug;
use sha3::{Digest, Sha3_256 };
use simple_logger::SimpleLogger;
// ---
use crate::signature_scheme::SignatureScheme;
use lamport_signature_scheme::LamportSignatureScheme;
use merkle_tree::MerkleTree;

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
    let _args = Args::parse();

    const T: usize = 4;
	const BLOCK_SIZE: usize = 32;

    let leaves: Vec<[u8;BLOCK_SIZE]> = (0usize..T)
        .map(|i| Sha3_256::digest(i.to_le_bytes()).try_into().unwrap())
        .collect();

    let tree = MerkleTree::construct::<Sha3_256>(leaves);
	debug!("{}", tree);

    // return;
    // let byte_str_orig = "7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a";
    // let bytes = decode(byte_str_orig).unwrap();
    // let hashed_bytes = Keccak256::digest(bytes);
    // let hashed_str = encode(hashed_bytes);
    // println!("byte_str_orig: {}", byte_str_orig);
    // println!("hashed: {}", hashed_str);

    // let msg = b"Hello, world!";

    // let mut alice_signer = LamportSignatureScheme::new(args.seed);
    // let mut eve_signer = LamportSignatureScheme::new(args.seed);
    // let bob_verifier = LamportSignatureScheme::new(args.seed);

    // //
    // // Alice signs
    // //
    // let alice_key_pair = alice_signer.gen_key_pair();
    // debug!(
    //     "alice_key_pair:\npriv:\n{}\npub:\n{}",
    //     alice_key_pair.private, alice_key_pair.public
    // );
    // let alice_packet = alice_signer.sign(msg, &alice_key_pair.private);

    // //
    // // Eve attacker signs
    // //
    // let eve_key_pair = eve_signer.gen_key_pair();
    // debug!("{}", eve_key_pair);
    // let eve_packet = eve_signer.sign(msg, &eve_key_pair.private);

    // //
    // // Bob verifies
    // //
    // let bob_from_alice_valid = bob_verifier.verify(&alice_packet.sign, &alice_key_pair.public);
    // assert!(bob_from_alice_valid, "The valid signature was rejected!");

    // let bob_from_eve_valid = bob_verifier.verify(&eve_packet.sign, &alice_key_pair.public);
    // assert!(!bob_from_eve_valid, "The invalid signature was rejected!");
}
