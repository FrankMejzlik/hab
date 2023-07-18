extern crate hab;

use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;
use chrono::Local;
// ---
use rand_chacha::ChaCha20Rng;
use sha3::Sha3_256;
// ---
use hab::{HorstSigScheme, Sender, SenderParams, SenderTrait};

/// Size of the hashes in a Merkle tree
const N: usize = 256 / 8;
/// Number of SK segments in signature
const K: usize = 64;
/// Depth of the Merkle tree (without the root layer)
const TAU: usize = 4;
/// A seedable CSPRNG used for number generation
type CsPrng = ChaCha20Rng;
/// Maximum number of secure signature per one key
const KEY_CHARGES: usize = 16;
// Hash function to be used
type HashFn = Sha3_256;
// Compute the T parameter
const T: usize = 2_usize.pow(TAU as u32);

// The final signer type
pub type SignerInst = HorstSigScheme<N, K, TAU, { TAU + 1 }, T, KEY_CHARGES, CsPrng, HashFn>;

/// Blocks until some input is available (the next timestamp string as bytes)
fn read_input() -> Vec<u8> {
    std::thread::sleep(std::time::Duration::from_secs(1));
    let msg = Local::now().format("%d-%m-%Y %H:%M:%S").to_string();
    msg.into_bytes()
}
fn main() {
    
    // To see the parameters, please see the `SenderParams` definition
    let params = SenderParams {
        sender_addr: "127.0.0.1:8080".to_string(),
        running: Arc::new(AtomicBool::new(true)),
        seed: 42,
        id_filename: "sender.id".to_string(),
        datagram_size: 1500,
        receiver_lifetime: Duration::from_secs(10),
        pre_cert: 2,
        max_piece_size: 1024*1024,
        key_dist: vec![ vec![4, 100], vec![2, 50], vec![1, 0] ],
        key_charges: Some(10),
        dgram_delay: Duration::from_micros(100),
        alt_output: None,
    };
    
    
    println!("Running the example broadcaster at '{}'...", params.sender_addr);
    let mut bcaster = Sender::<SignerInst>::new(params);
    loop {
        let data = read_input();
        println!("SEND: |{}|", String::from_utf8_lossy(&data));
        if let Err(e) = bcaster.broadcast(data) {
            eprintln!("Failed to broadcast! ERROR: {e}");
            continue;
        }
    }
}