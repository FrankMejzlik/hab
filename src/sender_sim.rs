//!
//! SenderSim is a simulation of the Sender, which is used for testing.
//!

use crate::SenderParams;

// ---
// ---
use crate::common::{BlockSignerParams, SeqType};

#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

pub struct SignedMessageSim {
    pub message: u64,
    pub seq: SeqType,
    pub signature: u64,
}

struct BlockSenderSim {
    #[allow(dead_code)]
    params: BlockSignerParams,
    next_seq: u64,
}

impl BlockSenderSim {
    pub fn new(params: BlockSignerParams) -> Self {
        BlockSenderSim {
            params,
            next_seq: 0,
        }
    }

    fn sign(&mut self, message: u64, seq: SeqType) -> SignedMessageSim {
        // Simulates the signing key
        let selected_key = 33;
        SignedMessageSim {
            message,
            seq,
            signature: selected_key,
        }
    }

    fn next_seq(&mut self) -> u64 {
        let res = self.next_seq;
        self.next_seq += 1;
        res
    }
}

pub struct SenderSim {
    signer: BlockSenderSim,
}
impl SenderSim {
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
        let signer = BlockSenderSim::new(block_signer_params);

        println!("Running simulated sender with params: {:#?}.\n\nkey_charges, pre_cert, key_dist are ignored if loaded from existing identity", params);

        SenderSim { signer }
    }

    pub fn broadcast(&mut self, data: u64) -> SignedMessageSim {
        let msg_seq = self.signer.next_seq();
        self.signer.sign(data, msg_seq)
    }
}
