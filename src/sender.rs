//!
//! The main module providing high-level API for the sender of the data.
//!

use crate::block_signer::BlockSigner;
use crate::FtsSchemeTrait;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
// ---
// ---
use crate::common::{BlockSignerParams, Error};
use crate::net_sender::{NetSender, NetSenderParams};
use crate::traits::{IntoFromBytes, MessageSignerTrait, SenderTrait};
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct SenderParams {
    /// A filename where the identity will be serialized.
    pub id_filename: String,
    /// A seed for the pseudo-random number generator.
    pub seed: u64,
    /// A distribution for key selection algorithm.
    pub key_dist: Vec<Vec<usize>>,
    /// Number of keys to certificate in advance.
    pub pre_cert: usize,
    /// A maximum byte size of one piece.
    pub max_piece_size: usize,
    /// A maximum byte size of one datagram.
    pub datagram_size: usize,
    /// A maximum time between two heartbeats from the given receiver.
    pub receiver_lifetime: Duration,
    /// An address and port where the sender will be listening for heartbeats.
    pub sender_addr: String,
    /// Number of signatures one key can sign.
    pub key_charges: Option<usize>,
    /// Delay between sending two datagrams.
    pub dgram_delay: Duration,
    /// A flag that indicates if the application should run or terminate.
    pub running: Arc<AtomicBool>,
    /// An alternative output destination instead of a network (useful for testing).
    pub alt_output: Option<mpsc::Sender<Vec<u8>>>,
}

pub struct Sender<Signer: FtsSchemeTrait> {
    params: SenderParams,
    signer: BlockSigner<Signer>,
    net_sender: NetSender,
}
impl<Signer: FtsSchemeTrait> Sender<Signer> {
    pub fn new(params: SenderParams) -> Self {
        let block_signer_params = BlockSignerParams {
            seed: params.seed,
            id_filename: params.id_filename.clone(),
            target_petname: String::default(), //< Not used in `Sender`
            key_charges: params.key_charges,
            pre_cert: Some(params.pre_cert),
            max_piece_size: params.max_piece_size,
            key_dist: params.key_dist.clone(),
        };
        let signer = BlockSigner::new(block_signer_params);

        let net_sender_params = NetSenderParams {
            addr: params.sender_addr.clone(),
            running: params.running.clone(),
            subscriber_lifetime: params.receiver_lifetime,
            datagram_size: params.datagram_size,
            max_piece_size: params.max_piece_size,
            dgram_delay: params.dgram_delay,
            alt_output: params.alt_output.clone(),
        };
        let net_sender = NetSender::new(net_sender_params);

        info!(tag: "sender", "Running sender with params: {:#?}.\n\nkey_charges, pre_cert, key_dist are ignored if loaded from existing identity", params);

        Sender {
            params,
            signer,
            net_sender,
        }
    }
}

impl<Signer: FtsSchemeTrait> SenderTrait for Sender<Signer> {
    fn broadcast(&mut self, data: Vec<u8>) -> Result<(), Error> {
        // Iterate over pieces
        for message in data.chunks(self.params.max_piece_size) {
            let mut piece = vec![0; message.len()];
            piece.copy_from_slice(message);

            // Increment the sequence number
            let msg_seq = self.signer.next_seq();

            let _msg_size = piece.len();
            let _msg_hash = xxhash_rust::xxh3::xxh3_64(&piece);

            // Sign along with the pubkeys
            let signed_msg = match self.signer.sign(piece, msg_seq) {
                Ok(x) => x,
                Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
            };

            #[cfg(feature = "log_input_output")]
            {
                use crate::traits::SignedBlockTrait;
                // Check & log
                let hash = signed_msg.hash();
                debug!(tag: "sender", "[{msg_seq}][{hash}][{_msg_size}] {_msg_hash}");
            }

            // Broadcast over the network
            let signed_msg_bytes = signed_msg.into_network_bytes();
            let _signed_msg_size = signed_msg_bytes.len();

            info!(tag: "sender", "Broadcasting {_signed_msg_size} vs _msg_size: {_msg_size}, OH: {}", _signed_msg_size - _msg_size);

            if let Err(e) = self.net_sender.broadcast(&signed_msg_bytes) {
                return Err(Error::new(&format!("{:?}", e)));
            };
        }
        Ok(())
    }
}
