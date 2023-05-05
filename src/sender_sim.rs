//!
//! SenderSim is a simulation of the Sender, which is used for testing.
//!

use std::collections::VecDeque;
use std::fmt::{Display, Formatter};

// ---
use rand::distributions::Distribution;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
// ---
use crate::common::{BlockSignerParams, DiscreteDistribution, SeqType, UnixTimestamp};
use crate::{utils, SenderParams};

#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Clone, Debug, PartialEq)]
struct KeyPairStoreContSim {
    key: u64,
    last_cerified: UnixTimestamp,
    lifetime: usize,
    cert_count: usize,
}

impl Display for KeyPairStoreContSim {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{:03} -> {:02} ({:03})",
            self.key,
            //utils::unix_ts_to_string(self.last_cerified),
            self.lifetime,
            self.cert_count
        )
    }
}

#[derive(Debug, Clone)]
pub struct KeyLayersSim {
    /// The key containers in their layers (indices).
    data: Vec<VecDeque<KeyPairStoreContSim>>,
    /// List of seq number when the key layer can be used once again (default 0)
    ready_at: Vec<f64>,
    /// The average rate at which this layer signs.
    avg_sign_rate: Vec<f64>,
    /// True if the first sign is to come.
    first_sign: bool,
    /// A number of signatures that one keypair can generate.
    key_lifetime: usize,
    /// A number of certificates to keep per layer.
    cert_window: usize,
    next_seq: SeqType,
    next_key: u64,
}

impl KeyLayersSim {
    pub fn new(
        depth: usize,
        key_lifetime: usize,
        cert_interval: usize,
        avg_sign_rate: Vec<f64>,
        next_key: u64,
    ) -> Self {
        KeyLayersSim {
            data: vec![VecDeque::new(); depth],
            ready_at: vec![0.0; depth],
            avg_sign_rate,
            first_sign: true,
            next_seq: 0,
            key_lifetime,
            cert_window: utils::calc_cert_window(cert_interval),
            next_key,
        }
    }

    /// Returns true if the key on the given layer can be scheduled already.
    fn is_ready(&self, level: usize) -> bool {
        info!(tag: "sender", "{:#?} < {:#?}", self.ready_at[level], self.next_seq);
        self.ready_at[level] < self.next_seq as f64
    }

    fn insert(&mut self, level: usize, keypair: u64) {
        let key_cont = KeyPairStoreContSim {
            key: keypair,
            last_cerified: 0,
            lifetime: self.key_lifetime,
            cert_count: 0,
        };

        self.data[level].push_back(key_cont);
    }

    ///
    /// Takes the key from the provided layer, updates it and
    /// returns it (also bool indicating that the new key is needed).
    ///
    fn poll(&mut self, layer: usize) -> Vec<(u64, u8)> {
        let signing_idx = self.cert_window / 2;
        let resulting_key;
        {
            let signing_key = &mut self.data[layer][signing_idx];
            signing_key.lifetime -= 1;
            signing_key.last_cerified = utils::unix_ts();
            resulting_key = self.data[layer][signing_idx].clone();
        }

        let rate = self.avg_sign_rate[layer];
        if rate > 0.0 {
            self.ready_at[layer] = (self.next_seq - 1) as f64 + rate;
        }

        //
        // Determine what keys to certify with this key
        //

        let mut pks = vec![];
        // The first keys is the one to use for verification
        pks.push((resulting_key.key, layer as u8));

        // Fill in the rest of pubkeys
        for (l_idx, layer) in self.data.iter_mut().enumerate() {
            for k in layer.iter_mut() {
                // Skip the signing key
                if k.key == resulting_key.key {
                    continue;
                }
                pks.push((k.key, l_idx as u8));
                k.cert_count += 1;
            }
        }

        // If this key just died
        let died = if (resulting_key.lifetime) == 0 {
            // Remove it
            self.data[layer].pop_front();
            // And indicate that we need a new one
            true
        } else {
            false
        };

        // If needed generate a new key for the given layer
        if died {
            let new_key = self.gen_key_pair();
            self.insert(layer, new_key);
        }

        self.first_sign = false;
        pks
    }

    fn gen_key_pair(&mut self) -> u64 {
        let x = self.next_key;
        self.next_key += 1;
        x
    }
}

impl Display for KeyLayersSim {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mut res = String::new();

        for (l_idx, layer) in self.data.iter().enumerate() {
            res.push_str(&format!("|{:.1}|", self.ready_at[l_idx]));
            for (i, kc) in layer.iter().enumerate() {
                res.push_str(&format!("[{}] {} ", l_idx, kc));
                if i % self.cert_window == (self.cert_window - 1) {
                    res.push('\n')
                } else {
                    res.push_str("++ ");
                }
            }
        }

        write!(f, "{}", res)
    }
}

pub struct SignedMessageSim {
    pub message: u64,
    pub seq: SeqType,
    pub signature: Vec<(u64, u8)>,
}

#[derive(Debug, Clone)]
struct BlockSenderSim {
    #[allow(dead_code)]
    params: BlockSignerParams,
    layers: KeyLayersSim,
    distr: DiscreteDistribution,

    rng: ChaCha20Rng,
}

impl BlockSenderSim {
    pub fn new(params: BlockSignerParams) -> Self {
        let rng = ChaCha20Rng::seed_from_u64(params.seed);
        let cw_size = utils::calc_cert_window(params.pre_cert.unwrap());
        let num_layers = params.key_dist.len();
        let key_charges = params.key_charges.unwrap();

        let (distr, avg_sign_rate) = utils::lifetimes_to_distr(&params.key_dist);

        let mut layers = KeyLayersSim::new(
            num_layers,
            key_charges,
            params.pre_cert.unwrap(),
            avg_sign_rate,
            0,
        );
        let mut next_key = 0;
        for l_idx in 0..num_layers {
            // Generate the desired number of keys per layer to forward & backward certify them
            for _ in 0..cw_size {
                layers.insert(l_idx, next_key);
                next_key += 1;
            }
			
        }

        layers.next_key = next_key;

        BlockSenderSim {
            params,
            layers,
            distr,
            rng,
        }
    }

    fn sign(&mut self, message: u64, seq: SeqType) -> SignedMessageSim {
        
        // Select the key to sign with
        let pub_keys = self.next_key();

        //println!("{}", self.layers);
        SignedMessageSim {
            message,
            seq,
            signature: pub_keys,
        }
    }

    fn next_key(&mut self) -> Vec<(u64, u8)> {
        // Sample what layer to use
        let mut sign_layer;
        loop {
            sign_layer = if self.layers.first_sign {
                0
            } else {
                self.distr.sample(&mut self.rng)
            };

            if self.layers.is_ready(sign_layer) {
                break;
            }
        }
        let pks = self.layers.poll(sign_layer);

        pks
    }

    fn next_seq(&mut self) -> u64 {
        let res = self.layers.next_seq;
        self.layers.next_seq += 1;
        res
    }
}

#[derive(Debug, Clone)]
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

        //println!("Running simulated sender with params: {:#?}.", params);

        SenderSim { signer }
    }

    pub fn broadcast(&mut self, data: u64) -> SignedMessageSim {
        let msg_seq = self.signer.next_seq();
        self.signer.sign(data, msg_seq)
    }
}
