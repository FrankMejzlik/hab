//!
//! The main module providing high-level API for the sender of the data.
//!

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
// ---
// ---
use crate::common::{BlockSignerParams, Error, MsgMetadata};
use crate::net_sender::{NetSender, NetSenderParams};
use crate::traits::{BlockSignerTrait, SenderTrait};
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct SenderParams {
    pub seed: u64,
    pub addr: String,
    pub running: Arc<AtomicBool>,
    pub id_dir: String,
    pub id_filename: String,
    pub subscriber_lifetime: Duration,
    pub net_buffer_size: usize,
    pub datagram_size: usize,
    pub key_lifetime: usize,
    pub cert_interval: usize,
    pub max_piece_size: usize,
    pub key_dist: Vec<Vec<usize>>,
    /// An alternative output destination instread of network.
    pub alt_output: Option<std::sync::mpsc::Sender<Vec<u8>>>,
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
            id_dir: params.id_dir.clone(),
            id_filename: params.id_filename.clone(),
            target_petname: String::default(), //< Not used in `Sender`
            key_lifetime: params.key_lifetime,
            cert_interval: params.cert_interval,
            max_piece_size: params.max_piece_size,
            key_dist: params.key_dist.clone(),
        };
        let signer = BlockSigner::new(block_signer_params);

        let net_sender_params = NetSenderParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
            subscriber_lifetime: params.subscriber_lifetime,
            net_buffer_size: params.net_buffer_size,
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

    ///
    /// Writes the additional data in the message and returns it along with the clean message.
    ///
    fn write_metadata(msg: &mut Vec<u8>, metadata: MsgMetadata) {
        let seq_bytes = metadata.seq.to_le_bytes();
        msg.extend_from_slice(&seq_bytes);
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

            // Add the metadata to the message
            Self::write_metadata(&mut piece, MsgMetadata { seq: msg_seq });

            // Sign along with the pubkeys
            let signed_msg = match self.signer.sign(piece) {
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
            let signed_msg_bytes =
                bincode::serialize(&signed_msg).expect("Should be seriallizable.");
            if let Err(e) = self.net_sender.broadcast(&signed_msg_bytes) {
                return Err(Error::new(&format!("{:?}", e)));
            };
        }
        Ok(())
    }
}
