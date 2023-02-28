//!
//! The main module providing high-level API for the sender of the data.
//!

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
// ---
// ---
use crate::common::Error;
use crate::net_sender::{NetSender, NetSenderParams};
use crate::traits::{BlockSignerParams, BlockSignerTrait, Config, SenderTrait, SignedBlockTrait};
#[allow(unused_imports)]
use crate::{debug, error, info, log_input, trace, warn};

#[derive(Debug)]
pub struct SenderParams {
    pub seed: u64,
    pub layers: usize,
    pub addr: String,
    pub running: Arc<AtomicBool>,
}

pub struct Sender<BlockSigner: BlockSignerTrait> {
    #[allow(dead_code)]
    params: SenderParams,
    signer: BlockSigner,
    net_sender: NetSender,
}
impl<BlockSigner: BlockSignerTrait> Sender<BlockSigner> {
    pub fn new(params: SenderParams, config: Config) -> Self {
        // Re-assign the log directory for this lib
        let mut guard = crate::common::LOGS_DIR
            .write()
            .expect("Should be lockable!");
        *guard = config.logs_dir.clone();

        let block_signer_params = BlockSignerParams {
            seed: params.seed,
            layers: params.layers,
        };
        let signer = BlockSigner::new(block_signer_params, config.clone());

        let net_sender_params = NetSenderParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
        };
        let net_sender = NetSender::new(net_sender_params, config);

        Sender {
            params,
            signer,
            net_sender,
        }
    }
}

impl<BlockSigner: BlockSignerTrait> SenderTrait for Sender<BlockSigner> {
    fn broadcast(&mut self, data: Vec<u8>) -> Result<(), Error> {
        let input_string = String::from_utf8_lossy(&data).to_string();

        let signed_block = match self.signer.sign(data) {
            Ok(x) => x,
            Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
        };

        trace!(tag: "sender", "[{}] {input_string}", signed_block.hash());

        let signed_data_bytes =
            bincode::serialize(&signed_block).expect("Should be seriallizable.");
        if let Err(e) = self.net_sender.broadcast(&signed_data_bytes) {
            return Err(Error::new(&format!("{:?}", e)));
        };

        Ok(())
    }
}
