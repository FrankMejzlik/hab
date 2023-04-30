//!
//! The main module providing high-level API for the receiver of the data.
//!

use crate::sender_sim::SignedMessageSim;
use crate::ReceiverParams;
// ---
// ---
use crate::common::{BlockSignerParams, MessageAuthentication, SeqType};

// ---
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct VerifyResultSim {
    pub msg: u64,
    pub seq: SeqType,
    pub verification: MessageAuthentication,
}

struct BlockVerifierSim {
    #[allow(dead_code)]
    params: BlockSignerParams,
}

impl BlockVerifierSim {
    pub fn new(params: BlockSignerParams) -> Self {
        Self { params }
    }

    fn verify(&mut self, piece: SignedMessageSim) -> VerifyResultSim {
        VerifyResultSim {
            msg: piece.message,
            seq: 0,
            verification: MessageAuthentication::Unverified,
        }
    }
}

pub struct ReceiverSim {
    verifier: BlockVerifierSim,
}

impl ReceiverSim {
    pub fn new(params: ReceiverParams) -> Self {
        let block_signer_params = BlockSignerParams {
            seed: 0, //< Not used
            id_filename: params.id_filename.clone(),
            target_petname: params.target_name.clone(),
            pre_cert: None,    //< Not used
            max_piece_size: 0, //< Not used
            key_charges: None, //< Not used
            key_dist: vec![],  //< Not used
        };

        println!("Running simulated receiver with params: {:#?}.\n\nkey_charges, pre_cert, key_dist are ignored if loaded from existing identity", params);

        ReceiverSim {
            verifier: BlockVerifierSim::new(block_signer_params),
        }
    }

    pub fn receive(&mut self, signed_block: SignedMessageSim) -> VerifyResultSim {
        self.verifier.verify(signed_block)
    }
}
