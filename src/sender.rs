//!
//! The main module providing high-level API for the sender of the data.
//!


use std::sync::atomic::{AtomicBool};
use std::sync::Arc;
// ---
use crate::block_signer::BlockSignerParams;
use crate::common::Error;
use xxhash_rust::xxh3::xxh3_64;
// ---
use crate::config::BlockSignerInst;
use crate::net_sender::{NetSender, NetSenderParams};
use crate::traits::{BlockSignerTrait, SenderTrait};
#[allow(unused_imports)]
use crate::{debug, error, info, log_input, trace, warn};


#[derive(Debug)]
pub struct SenderParams {
    pub seed: u64,
    pub layers: usize,
    pub addr: String,
    pub running: Arc<AtomicBool>,
}

pub struct Sender {
    #[allow(dead_code)]
    params: SenderParams,
    signer: BlockSignerInst,
    net_sender: NetSender,
}

impl Sender {
    pub fn new(params: SenderParams) -> Self {
        let block_signer_params = BlockSignerParams {
            seed: params.seed,
            layers: params.layers,
        };
        let signer = BlockSignerInst::new(block_signer_params);

        let net_sender_params = NetSenderParams {
            addr: params.addr.clone(),
            running: params.running.clone(),
        };
        let net_sender = NetSender::new(net_sender_params);

        Sender {
            params,
            signer,
            net_sender,
        }
    }
}

impl SenderTrait for Sender {
    fn broadcast(&mut self, data: Vec<u8>) -> Result<(), Error>{
		let input_string = String::from_utf8_lossy(&data).to_string();

		let signed_block = match self.signer.sign(data) {
			Ok(x) =>  x,
			Err(e) => panic!("Failed to sign the data block!\nERROR: {:?}", e),
		};

		trace!(tag: "sender", "[{}] {input_string}", signed_block.hash());
	
		let signed_data_bytes = bincode::serialize(&signed_block).expect("Should be seriallizable.");
		if let Err(e) = self.net_sender.broadcast(&signed_data_bytes) {
			return Err(Error::new(&format!("{:?}", e)))

		};
		
		Ok(())
    }
}
