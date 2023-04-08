//!
//! The main module providing high-level API for the sender of the data.
//!

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use std::sync::mpsc;
// ---
// ---
use crate::common::{BlockSignerParams, Error};
use crate::net_sender::{NetSender, NetSenderParams};
use crate::traits::{BlockSignerTrait, IntoFromBytes, SenderTrait};
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct SenderParams {
    pub id_filename: String,
    pub seed: u64,
    pub key_dist: Vec<Vec<usize>>,
    pub pre_cert: usize,
    pub key_lifetime: usize,
    pub max_piece_size: usize,
    pub datagram_size: usize,
    pub receiver_lifetime: Duration,
	// ---
	pub sender_addr: String,
    pub running: Arc<AtomicBool>,
    /// An alternative output destination instread of network.
    pub alt_output: Option<mpsc::Sender<Vec<u8>>>,
}

pub struct Sender<BlockSigner: BlockSignerTrait> {
    #[allow(dead_code)]
    params: SenderParams,
    signer: BlockSigner,
    net_sender: NetSender,
}
impl<BlockSigner: BlockSignerTrait> Sender<BlockSigner> {
    pub fn new(params: SenderParams) -> Self {
        let block_signer_params = BlockSignerParams {
            seed: params.seed,
            id_filename: params.id_filename.clone(),
            target_petname: String::default(), //< Not used in `Sender`
            key_lifetime: params.key_lifetime,
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
            alt_output: params.alt_output.clone(),
        };
        let net_sender = NetSender::new(net_sender_params);

        Sender {
            params,
            signer,
            net_sender,
        }
    }
}

impl<BlockSigner: BlockSignerTrait> SenderTrait for Sender<BlockSigner> {
    fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        // Iterate over pieces
        for msg_piece in msg.chunks(self.params.max_piece_size) {
            let mut piece = vec![0; msg_piece.len()];
            piece.copy_from_slice(msg_piece);

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
