#[allow(unused_imports)]
use petgraph::algo::tarjan_scc;
use petgraph::graph::DiGraph;
use petgraph::graph::NodeIndex;
use petgraph::visit::IntoNodeReferences;
use std::cmp::{Ord, Ordering};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
// ---
use crate::block_signer::PubKeyTransportCont;
use crate::common::SeqNum;
//use petgraph::algo::has_path_connecting;
use serde::{Deserialize, Serialize};
// ---
use crate::common::{SenderId, SenderIdentity, UnixTimestamp};
use crate::traits::PublicKeyBounds;
use crate::utils;
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

///
/// A wrapper struct for sotred public key that also holds the time the key was first
/// received and a layer it belongs to.
///
#[derive(Serialize, Deserialize, Clone)]
pub struct StoredPubKey<PublicKey: PublicKeyBounds> {
    pub key: PublicKey,
    pub layer: u8,
    pub received: UnixTimestamp,
    pub receiverd_seq: u64,
    pub id: Option<SenderIdentity>,
    pub certified_by: Vec<SenderIdentity>,
}

impl<PublicKey: PublicKeyBounds> fmt::Debug for StoredPubKey<PublicKey> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_str = if let Some(x) = &self.id {
            x.petname.clone().unwrap_or("".into())
        } else {
            "".to_string()
        };
        write!(f, "{:?}\nID: {}", self.key, id_str)
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
    pub fn new_empty(key_cont: &PubKeyTransportCont<PublicKey>) -> Self {
        Self {
            key: key_cont.key.clone(),
            layer: 0,
            received: 0,
            receiverd_seq: 0,
            id: None,
            certified_by: vec![],
        }
    }
    pub fn new_with_identity(
        key_cont: &PubKeyTransportCont<PublicKey>,
        id: SenderIdentity,
        seq: u64,
    ) -> Self {
        Self {
            key: key_cont.key.clone(),
            layer: key_cont.layer,
            received: utils::unix_ts(),
            receiverd_seq: seq,
            id: Some(id.clone()),
            certified_by: vec![id],
        }
    }
    pub fn new_with_certified(
        key_cont: &PubKeyTransportCont<PublicKey>,
        id: SenderIdentity,
        seq: u64,
    ) -> Self {
        Self {
            key: key_cont.key.clone(),
            layer: key_cont.layer,
            received: utils::unix_ts(),
            receiverd_seq: seq,
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
    /// Directed graph representing "has certified" binary relation
    pub graph: DiGraph<StoredPubKey<PublicKey>, ()>,
    /// Map: PK -> NodeIndex
    pub pk_to_node_idx: BTreeMap<StoredPubKey<PublicKey>, NodeIndex>,
    /// Map: SenderIdentity -> { NodeIndex } (Set of nodes in WEAKLY connected component)
    pub id_to_ccomp: BTreeMap<SenderIdentity, BTreeSet<NodeIndex>>,
    /// The target identity we're currently subscribed to.
    pub target_id: Option<SenderIdentity>,
    // ---
    /// Next ID to assign when generating a new sender ID
    pub next_id: SenderId,
    pub cert_window: usize,
}

impl<PublicKey: PublicKeyBounds> PubKeyStore<PublicKey> {
    pub fn new(cert_interval: usize) -> Self {
        PubKeyStore {
            graph: DiGraph::new(),
            pk_to_node_idx: BTreeMap::new(),
            id_to_ccomp: BTreeMap::new(),
            next_id: 0,
            target_id: None,
            cert_window: 2 * utils::calc_cert_window(cert_interval) - 1,
        }
    }

    pub fn get_key(
        &self,
        key: &StoredPubKey<PublicKey>,
    ) -> Option<(usize, &StoredPubKey<PublicKey>)> {
        let idx = self.pk_to_node_idx.get(key);

        if let Some(x) = idx {
            let node = self.graph.node_weight(*x);
            node.map(|y| (x.index(), y))
        } else {
            None
        }
    }

    pub fn get_id_cc(&self, petname: &str) -> Option<(&SenderIdentity, &BTreeSet<NodeIndex>)> {
        for (k, v) in self.id_to_ccomp.iter() {
            if let Some(x) = &k.petname {
                if x == petname {
                    return Some((k, v));
                }
            }
        }
        None
    }

    ///
    /// Sets the target identity that we're subscribed to.
    ///
    pub fn set_target_id(&mut self, id: SenderIdentity) -> Option<SenderIdentity> {
        if !self.id_to_ccomp.contains_key(&id) {
            self.id_to_ccomp.insert(id.clone(), BTreeSet::new());
        }

        let old_id = self.target_id.clone();
        self.target_id = Some(id);
        old_id
    }

    ///
    /// Gets the target identity that we're subscribed to.
    ///
    pub fn get_target_id(&self) -> Option<SenderIdentity> {
        self.target_id.clone()
    }

    pub fn add_node(&mut self, pk: StoredPubKey<PublicKey>) -> NodeIndex {
        let from = self.graph.add_node(pk.clone());

        // Map pubkey to node in the graph
        self.pk_to_node_idx.insert(pk, from);

        // Map SenderIdentity to CC
        let set = self
            .id_to_ccomp
            .get_mut(self.target_id.as_ref().expect("Should be there!"))
            .expect("Should be there!");
        set.insert(from);

        NodeIndex::new(from.index())
    }
    pub fn get_node(&mut self, idx: usize) -> Option<&StoredPubKey<PublicKey>> {
        self.graph.node_weight(NodeIndex::new(idx))
    }

    pub fn insert_key(&mut self, verify_key_idx: usize, key: StoredPubKey<PublicKey>) {
        let from = NodeIndex::new(verify_key_idx);

        let to_node = if self.pk_to_node_idx.contains_key(&key) {
            *self.pk_to_node_idx.get(&key).expect("Should be present!")
        } else {
            self.add_node(key)
        };

        // Only add the edge if does not exist already
        //if !has_path_connecting(&self.graph, from, to_node.into(), None) {
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

        assert!(!keys.is_empty(), "There must be at least one key!");
        let mut keys_it = keys.into_iter();

        // Insert the first key
        let fst_key = keys_it.next().expect("There must be at least one key!");
        let fst_key_node = self.add_node(fst_key);
        let mut from = fst_key_node;

        // We create one huge cycle
        for k in keys_it {
            let to = self.add_node(k.clone());
            self.graph.add_edge(from, to, ());
            from = to;
        }

        // Add the edge from the last to the first
        self.graph.add_edge(from, fst_key_node, ());
    }

    // pub fn target_keys_iter(&self) -> impl Iterator<Item = (usize, &StoredPubKey<PublicKey>)> {
    //     self.graph
    //         .node_indices()
    //         .filter_map(move |i| match self.graph.node_weight(i) {
    //             Some(node) => {
    //                 if let Some(id) = &self.target_id {
    //                     if node.certified_by.contains(id) {
    //                         Some((i.index(), node))
    //                     } else {
    //                         None
    //                     }
    //                 } else {
    //                     Some((i.index(), node))
    //                 }
    //             }
    //             _ => None,
    //         })
    // }

    pub fn proces_nodes(&mut self) {
        let mut sccs = tarjan_scc(&self.graph);
        for comp in sccs.iter_mut() {
            // Detect what ID belongs to this component
            let mut comp_id = None;
            for n_idx in comp.iter_mut() {
                let key = self.graph.node_weight(*n_idx).expect("Should be set!");
                if let Some(x) = &key.id {
                    if let Some(y) = comp_id {
                        assert_eq!(y, x.clone(), "There must not be two distict identities in the same strongly connected component!");
                    }

                    comp_id = Some(x.clone());
                }
            }

            // Set the component for all the nodes
            for n_idx in comp.iter_mut() {
                let key = self.graph.node_weight_mut(*n_idx).expect("Should be set!");
                key.id = comp_id.clone();
            }
        }
    }

    pub fn prune_graph(&mut self) {
        let cmp_key = |x: &(SeqNum, NodeIndex)| x.0;

        let mut hist_layers = vec![];
        let mut indices_to_delete = vec![];

        let target_id = self.get_target_id().expect("Should be set!");

        // Assign the nodes into layers for the target identity
        for (idx, key) in self.graph.node_references() {
            if !key.certified_by.contains(&target_id) {
                continue;
            }

            let layer = key.layer as usize;

            if layer >= hist_layers.len() {
                hist_layers.resize(layer + 1, vec![]);
            }

            hist_layers[layer].push((key.receiverd_seq, idx));
        }

        // Sort the keys within the layers
        for layer in hist_layers.iter_mut() {
            layer.sort_by_key(cmp_key);
        }

        for layer in hist_layers.iter_mut() {
            let to_drain = std::cmp::max(0, layer.len() as i64 - self.cert_window as i64) as usize;
            let to_delete = layer.drain(..to_drain);

            for x in to_delete {
                indices_to_delete.push(x.1);
            }
        }

        // Delete the nodes
        self.graph
            .retain_nodes(|_, node_idx| -> bool { !indices_to_delete.contains(&node_idx) });

        // Rebuild pk_to_node_idx
        // Rebuild id_to_ccomp
        self.pk_to_node_idx.clear();
        for x in self.id_to_ccomp.iter_mut() {
            x.1.clear();
        }

        for (idx, key) in self.graph.node_references() {
            self.pk_to_node_idx.insert(key.clone(), idx);

            if let Some(x) = &key.id {
                let set = self.id_to_ccomp.get_mut(x).expect("Should be present!");
                set.insert(idx);
            }
        }
    }
}
