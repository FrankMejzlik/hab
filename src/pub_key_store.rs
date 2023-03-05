#[allow(unused_imports)]
use petgraph::algo::tarjan_scc;
use petgraph::graph::DiGraph;
use std::cmp::{Ord, Ordering};
use std::collections::{BTreeMap, BTreeSet};
// ---
use crate::block_signer::PubKeyTransportCont;
use serde::{Deserialize, Serialize};
// ---
use crate::common::{SenderId, SenderIdentity, UnixTimestamp};
use crate::traits::PublicKeyBounds;
use crate::utils;

///
/// A wrapper struct for sotred public key that also holds the time the key was first
/// received and a layer it belongs to.
///
#[derive(Debug, Serialize, Deserialize, Clone, Eq)]
pub struct StoredPubKey<PublicKey: PublicKeyBounds> {
    pub key: PublicKey,
    pub layer: u8,
    pub received: UnixTimestamp,
    pub id: Option<SenderIdentity>,
    pub certified_by: Vec<SenderIdentity>,
}

impl<PublicKey: PublicKeyBounds> PartialEq for StoredPubKey<PublicKey> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}
impl<PublicKey: PublicKeyBounds> Ord for StoredPubKey<PublicKey> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort in reverse order
        if self.key == other.key {
            Ordering::Equal
        } else if self.key < other.key {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl<PublicKey: PublicKeyBounds> PartialOrd for StoredPubKey<PublicKey> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Sort in reverse order
        if self.key == other.key {
            Some(Ordering::Equal)
        } else if self.key < other.key {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Greater)
        }
    }
}

impl<PublicKey: PublicKeyBounds> StoredPubKey<PublicKey> {
    pub fn new(key_cont: &PubKeyTransportCont<PublicKey>) -> Self {
        Self {
            key: key_cont.key.clone(),
            layer: key_cont.layer,
            received: utils::unix_ts(),
            id: None,
            certified_by: vec![],
        }
    }
    pub fn from_raw(raw_key: PublicKey) -> Self {
        Self {
            key: raw_key,
            layer: 0,
            received: utils::unix_ts(),
            id: None,
            certified_by: vec![],
        }
    }
}

///
/// A structure for storing the public keys for different sender identities. The identities are assigned
/// an integer ID and whenever the two identities are detected to be the same (some public key lies in both of
/// them) we merge the identities.
///
///
#[derive(Debug, Serialize, Deserialize)]
pub struct PubKeyStore<PublicKey: PublicKeyBounds> {
    pub keys: BTreeMap<SenderIdentity, BTreeSet<StoredPubKey<PublicKey>>>,
    pub graph: DiGraph<StoredPubKey<PublicKey>, ()>,
    pub next_id: SenderId,
    /// The target identity we're currently subscribed to.
    pub target_id: Option<SenderIdentity>,
}

impl<PublicKey: PublicKeyBounds> PubKeyStore<PublicKey> {
    pub fn new() -> Self {
        PubKeyStore {
            keys: BTreeMap::new(),
            graph: DiGraph::new(),
            next_id: 0,
            target_id: None,
        }
    }

    pub fn set_target_id(&mut self, id: SenderIdentity) -> Option<SenderIdentity> {
        let old_id = self.target_id.clone();
        self.target_id = Some(id);
        old_id
    }
}
