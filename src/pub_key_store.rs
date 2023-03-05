#[allow(unused_imports)]
use petgraph::algo::tarjan_scc;
use petgraph::csr::NodeIndex;
use petgraph::graph::DiGraph;
use std::cmp::{Ord, Ordering};
use std::collections::BTreeMap;
use std::fmt;
// ---
use crate::block_signer::PubKeyTransportCont;
use petgraph::adj::IndexType;
use serde::{Deserialize, Serialize};
// ---
use crate::common::{SenderId, SenderIdentity, UnixTimestamp};
use crate::traits::PublicKeyBounds;
use crate::utils;

///
/// A wrapper struct for sotred public key that also holds the time the key was first
/// received and a layer it belongs to.
///
#[derive(Serialize, Deserialize, Clone)]
pub struct StoredPubKey<PublicKey: PublicKeyBounds> {
    pub key: PublicKey,
    pub layer: u8,
    pub received: UnixTimestamp,
    pub id: Option<SenderIdentity>,
    pub certified_by: Vec<SenderIdentity>,
}

impl<PublicKey: PublicKeyBounds> fmt::Debug for StoredPubKey<PublicKey> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_str = if let Some(x) = &self.id {
            x.petname.clone().unwrap_or("--NONE--".into())
        } else {
            "--NONE--".to_string()
        };

        let mut certids = vec![];

        for x in self.certified_by.iter() {
            certids.push(x.id);
        }
        write!(f, "{:?}\n<{:?}>\n{:?}", self.key, id_str, certids)
    }
}

impl<PublicKey: PublicKeyBounds> PartialEq for StoredPubKey<PublicKey> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<PublicKey: PublicKeyBounds> Eq for StoredPubKey<PublicKey> {}

impl<PublicKey: PublicKeyBounds> Ord for StoredPubKey<PublicKey> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl<PublicKey: PublicKeyBounds> PartialOrd for StoredPubKey<PublicKey> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.key.cmp(&other.key))
    }
}

impl<PublicKey: PublicKeyBounds> StoredPubKey<PublicKey> {
    pub fn new_with_identity(
        key_cont: &PubKeyTransportCont<PublicKey>,
        id: SenderIdentity,
    ) -> Self {
        Self {
            key: key_cont.key.clone(),
            layer: key_cont.layer,
            received: utils::unix_ts(),
            id: Some(id.clone()),
            certified_by: vec![id],
        }
    }
    pub fn new_with_certified(
        key_cont: &PubKeyTransportCont<PublicKey>,
        id: SenderIdentity,
    ) -> Self {
        Self {
            key: key_cont.key.clone(),
            layer: key_cont.layer,
            received: utils::unix_ts(),
            id: None,
            certified_by: vec![id],
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
    pub keys: BTreeMap<StoredPubKey<PublicKey>, usize>,
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

    ///
    /// Sets the target identity that we're subscribed to.
    ///
    pub fn set_target_id(&mut self, id: SenderIdentity) -> Option<SenderIdentity> {
        let old_id = self.target_id.clone();
        self.target_id = Some(id);
        old_id
    }

    ///
    /// Gets the target identity that we're subscribed to.
    ///
    pub fn get_target_id(&self) -> Option<SenderIdentity> {
        if let Some(x) = self.target_id.clone() {
            Some(x)
        } else {
            None
        }
    }
    pub fn insert_key(&mut self, verify_key_idx: usize, key: StoredPubKey<PublicKey>) {
        let from = NodeIndex::new(verify_key_idx);

        let to_node = if self.keys.contains_key(&key) {
            NodeIndex::new(*self.keys.get(&key).expect("Should be present!"))
        } else {
            let new_idx = self.graph.add_node(key.clone());
            self.keys.insert(key.clone(), new_idx.index());
            new_idx
        };
        // Only add the edge if does not exist already
        if self.graph.edges_connecting(from, to_node).next().is_none() {
            self.graph.add_edge(from, to_node, ());
        }
    }

    pub fn insert_identity_keys(&mut self, keys: Vec<StoredPubKey<PublicKey>>) {
        // Make sure that these keys do not already exists
        // If they do, then something horrible happened or the user trusted someone wicked!
        for k in keys.iter() {
            for x in self.graph.node_weights() {
                assert!(*x != *k);
            }
        }

        assert!(keys.len() > 0, "There must be at least one key!");
        let mut keys_it = keys.into_iter();
        let fst_key = keys_it.next().expect("There must be at least one key!");
        let from = self.graph.add_node(fst_key.clone());
        self.keys.insert(fst_key, from.index());

        // We create cycles between the first node and each other node
        for k in keys_it {
            let to = self.graph.add_node(k.clone());
            self.keys.insert(k, to.index());
            self.graph.add_edge(from, to, ());
            self.graph.add_edge(to, from, ());
        }
    }

    pub fn target_keys_iter(&self) -> impl Iterator<Item = (usize, &StoredPubKey<PublicKey>)> {
        self.graph
            .node_indices()
            .filter_map(move |i| match self.graph.node_weight(i) {
                Some(node) => {
                    if let Some(id) = &self.target_id {
                        if node.certified_by.contains(id) {
                            Some((i.index(), node))
                        } else {
                            None
                        }
                    } else {
                        Some((i.index(), node))
                    }
                }
                _ => None,
            })
    }
}
