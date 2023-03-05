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
use crate::traits::{BlockSignerTrait, SenderTrait, SignedBlockTrait};
#[allow(unused_imports)]
use crate::{debug, error, info, log_input, trace, warn};

#[derive(Debug)]
pub struct SenderParams {
    pub seed: u64,
    pub layers: usize,
    pub addr: String,
    pub running: Arc<AtomicBool>,
    pub id_dir: String,
    pub id_filename: String,
    pub subscriber_lifetime: Duration,
    pub net_buffer_size: usize,
    pub datagram_size: usize,
}

pub struct Sender<BlockSigner: BlockSignerTrait> {
    #[allow(dead_code)]
    params: SenderParams,
    signer: BlockSigner,
    net_sender: NetSender,
    next_seq: usize,
}
impl<BlockSigner: BlockSignerTrait> Sender<BlockSigner> {
    pub fn new(params: SenderParams) -> Self {
        let block_signer_params = BlockSignerParams {
            seed: params.seed,
            layers: params.layers,
            id_dir: params.id_dir.clone(),
            id_filename: params.id_filename.clone(),
            target_petname: String::default(), //< Not used in `Sender`
            pub_key_layer_limit: usize::default(), //< Not used un `Sender`
        };
        let signer = BlockSigner::new(block_signer_params);

        let net_sender_params = NetSenderParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
            subscriber_lifetime: params.subscriber_lifetime,
            net_buffer_size: params.net_buffer_size,
            datagram_size: params.datagram_size,
        };
        let net_sender = NetSender::new(net_sender_params);

        Sender {
            params,
            signer,
            net_sender,
            next_seq: 0,
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
    fn broadcast(&mut self, mut msg: Vec<u8>) -> Result<(), Error> {
        // Increment the sequence number
        self.next_seq += 1;

        #[cfg(feature = "log_input_output")]
        let msg_clone = msg.clone();

        // Add the metadata to the message
        Self::write_metadata(&mut msg, MsgMetadata { seq: self.next_seq });

        // Sign along with the pubkeys
        let signed_msg = match self.signer.sign(msg) {
            Ok(x) => x,
            Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
        };

        #[cfg(feature = "log_input_output")]
        {
            // Check & log
            let hash = signed_msg.hash();
            let input_string = String::from_utf8_lossy(&msg_clone).to_string();
            debug!(tag: "sender", "[{}][{}] {input_string}", self.next_seq, hash);
            log_input!(self.next_seq, hash, &msg_clone);
        }

        // Broadcast over the network
        let signed_msg_bytes = bincode::serialize(&signed_msg).expect("Should be seriallizable.");
        if let Err(e) = self.net_sender.broadcast(&signed_msg_bytes) {
            return Err(Error::new(&format!("{:?}", e)));
        };

        Ok(())
    }
}
