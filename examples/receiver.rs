extern crate hab;

use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;
// ---
use rand_chacha::ChaCha20Rng;
use sha3::Sha3_256;
// ---
use hab::{HorstSigScheme, Receiver, ReceiverParams, ReceiverTrait};

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

fn main() {
    
    // To see the parameters, please see the `ReceiverParams` definition
    let params = ReceiverParams {
        running: Arc::new(AtomicBool::new(true)),
        target_addr: "127.0.0.1:8080".to_string(),
        target_name: "alice".to_string(),
        id_filename: "receiver.id".to_string(),
        distribute: None,
        heartbeat_period: Duration::from_secs(5),
        delivery_delay: Duration::from_secs(1),
        frag_timeout: Duration::from_secs(5),
        dgram_delay: Duration::from_micros(100),
        receiver_lifetime: Duration::from_secs(10),
        deliver: true,
        alt_input: None,
    };
    
    
    println!("Running the example receiver that receives from '{}'...", params.target_addr);
    let mut receiver = Receiver::<SignerInst>::new(params);
    loop {
        let msg = match receiver.receive() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Unable to receive! ERROR: {e}");
                continue;
            }
        };
        println!("RECV: |{:?}|{}|{}|", msg.authentication, msg.seq, String::from_utf8_lossy(&msg.message));
    }
}