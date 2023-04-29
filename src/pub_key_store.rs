#[allow(unused_imports)]
use petgraph::algo::tarjan_scc;
use petgraph::graph::DiGraph;
use petgraph::graph::NodeIndex;
use petgraph::visit::IntoNodeReferences;
use std::cmp::{Ord, Ordering};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::vec;
// ---
use crate::block_signer::PubKeyTransportCont;
use crate::common::SeqType;
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
    pub certified_by: BTreeSet<SenderIdentity>,
}

impl<PublicKey: PublicKeyBounds> fmt::Debug for StoredPubKey<PublicKey> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_str = if let Some(x) = &self.id {
            format!("{:?}", x.petnames)
        } else {
            "".to_string()
        };

        let mut c_str = String::new();
        for x in self.certified_by.iter() {
            c_str.push_str(&format!("{:?}", x.ids))
        }

        write!(f, "{:?}\nID: {}\n{:?}", self.key, id_str, c_str)
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
        seq: u64,
    ) -> Self {
        let mut certified_by = BTreeSet::new();
        certified_by.insert(id.clone());
        Self {
            key: key_cont.key.clone(),
            layer: key_cont.layer,
            received: utils::unix_ts(),
            receiverd_seq: seq,
            id: Some(id),
            certified_by,
        }
    }
    pub fn new_with_certified(
        key_cont: &PubKeyTransportCont<PublicKey>,
        id: SenderIdentity,
        seq: u64,
    ) -> Self {
        let mut certified_by = BTreeSet::new();
        certified_by.insert(id);
        Self {
            key: key_cont.key.clone(),
            layer: key_cont.layer,
            received: utils::unix_ts(),
            receiverd_seq: seq,
            id: None,
            certified_by,
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
    pub pk_to_node_idx: BTreeMap<PublicKey, NodeIndex>,
    /// Map: SenderIdentity -> { NodeIndex } (Set of nodes in WEAKLY connected component)
    pub id_to_scc: BTreeMap<SenderIdentity, BTreeSet<NodeIndex>>,
    // ---
    /// Next ID to assign when generating a new sender ID
    pub next_id: SenderId,
    pub cert_window: Option<usize>,
}

impl<PublicKey: PublicKeyBounds> PubKeyStore<PublicKey> {
    pub fn new() -> Self {
        PubKeyStore {
            graph: DiGraph::new(),
            pk_to_node_idx: BTreeMap::new(),
            id_to_scc: BTreeMap::new(),
            next_id: 0,
            cert_window: None,
        }
    }

    pub fn store_pks_for_identity(
        &mut self,
        cert_by_key_idx: NodeIndex,
        pub_keys: Vec<PubKeyTransportCont<PublicKey>>,
        sender_id: &mut SenderIdentity,
        seq: SeqType,
    ) {
        let mut width = 0;
        for kw in pub_keys.iter() {
            // Get a key to store
            let key_to_store = StoredPubKey::new_with_certified(kw, sender_id.clone(), seq);

            if kw.layer == 0 {
                width += 1;
            }

            // Insert the key to the graph
            self.insert_key(cert_by_key_idx, key_to_store);
        }
        sender_id.cert_window = Some(width);
    }

    pub fn get_key(&self, key: &PublicKey, target_id: &SenderIdentity) -> Option<NodeIndex> {
        let idx = self.pk_to_node_idx.get(key);
        if let Some(x) = idx {
            let node = self.graph.node_weight(*x);

            if let Some(key) = node {
                if key.certified_by.contains(target_id) {
                    return Some(*x);
                }
            }
        }
        None
    }

    pub fn get_id_cc(&self, petname: &str) -> Option<(&SenderIdentity, &BTreeSet<NodeIndex>)> {
        for (k, v) in self.id_to_scc.iter() {
            if k.petnames.contains(&petname.to_string()) {
                return Some((k, v));
            }
        }
        None
    }

    pub fn add_node(&mut self, pk: StoredPubKey<PublicKey>) -> NodeIndex {
        let new_node_idx = self.graph.add_node(pk.clone());

        // Map pubkey to node in the graph
        self.pk_to_node_idx.insert(pk.key, new_node_idx);

        // If this node belongs to some identity, create a mapping
        if let Some(x) = &pk.id {
            let set = self.id_to_scc.get_mut(x).expect("Should be there!");
            set.insert(new_node_idx);
        }

        new_node_idx
    }
    pub fn get_node(&self, idx: NodeIndex) -> Option<&StoredPubKey<PublicKey>> {
        self.graph.node_weight(idx)
    }

    pub fn insert_key(&mut self, from: NodeIndex, key: StoredPubKey<PublicKey>) {
        let mut identity = key.certified_by.clone();
        let to_node = if self.pk_to_node_idx.contains_key(&key.key) {
            *self
                .pk_to_node_idx
                .get(&key.key)
                .expect("Should be present!")
        } else {
            self.add_node(key)
        };

        // Make sure that the certified is filled in
        let node_mut = self
            .graph
            .node_weight_mut(to_node)
            .expect("Should be present!");
        node_mut.certified_by.append(&mut identity);

        // Only add the edge if does not exist already
        //if !has_path_connecting(&self.graph, from, to_node.into(), None) {
        if self.graph.edges_connecting(from, to_node).next().is_none() {
            self.graph.add_edge(from, to_node, ());
        }
    }

    ///
    /// Inserts the provided `key` into the graph as one with the provided `identity`.
    /// This method is called whenever the receiver receives the first ever message from some
    /// target and marks it as trusted.
    ///
    pub fn insert_identity_key(
        &mut self,
        key: StoredPubKey<PublicKey>,
        identity: &SenderIdentity,
    ) -> NodeIndex {
        //info!(tag: "receiver", "Inserting identity key: {:?}", key);
        // Try to detect already existing identity
        for existing_key in self.graph.node_weights_mut() {
            if *existing_key == key {
                if let Some(ref mut existing_id) = &mut existing_key.id {
                    existing_id.merge(identity.clone());
                } else {
                    existing_key.id = Some(identity.clone())
                }
                break;
            }
        }

        for (idx, existing_key) in self.graph.node_references() {
            if *existing_key == key && existing_key.id.is_some() {
                return idx;
            }
        }

        if !self.id_to_scc.contains_key(identity) {
            self.id_to_scc.insert(identity.clone(), BTreeSet::new());
        }

        // Else add it into the graph
        self.add_node(key)
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
            let mut comp_ids = BTreeSet::new();
            for n_idx in comp.iter_mut() {
                let key = self.graph.node_weight(*n_idx).expect("Should be set!");
                if let Some(x) = &key.id {
                    comp_ids.insert(x.clone());
                }
            }

            // Merge the identity
            let new_comp_id = if comp_ids.len() == 1 {
                Some(comp_ids.first().expect("Should be there!").clone())
            } else if comp_ids.len() == 2 {
                let mut it = comp_ids.clone().into_iter();
                let mut new_comp_id = it.next().expect("Should be there!");
                new_comp_id.merge(it.next().expect("Should be there!"));

                // Unify the previous identities to this new one
                for key_cont in self.graph.node_weights_mut() {
                    for prev_id in comp_ids.iter() {
                        // Add the new one
                        if key_cont.certified_by.contains(prev_id) {
                            key_cont.certified_by.insert(new_comp_id.clone());
                        }
                        // Remove the old ones
                        key_cont.certified_by.remove(prev_id);
                    }
                }

                Some(new_comp_id)
            } else {
                assert_eq!(comp_ids.len(), 0, "Cannot merge more then two identities!");
                None
            };

            // Set the component for all the nodes
            for n_idx in comp.iter_mut() {
                let key = self.graph.node_weight_mut(*n_idx).expect("Should be set!");
                key.id = new_comp_id.clone();
            }
        }
    }

    pub fn prune_graph(&mut self, target_id: &SenderIdentity) {
        let cmp_key = |x: &(SeqType, NodeIndex)| x.0;

        let mut hist_layers = vec![];
        let mut indices_to_delete = vec![];

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
            let to_drain = std::cmp::max(
                0,
                layer.len() as i64 - (2 * target_id.cert_window.unwrap() - 1) as i64,
            ) as usize;
            let to_delete = layer.drain(..to_drain);

            for (_, idx) in to_delete {
                let node = self.graph.node_weight_mut(idx).expect("Should be there!");

                // Remove this identity from the certified list
                node.certified_by.retain(|x| x != target_id);

                // Only delete it if empty
                if node.certified_by.is_empty() {
                    indices_to_delete.push(idx);
                }
            }
        }

        // Delete the nodes
        self.graph
            .retain_nodes(|_, node_idx| -> bool { !indices_to_delete.contains(&node_idx) });

        // Rebuild pk_to_node_idx
        // Rebuild id_to_ccomp
        self.pk_to_node_idx.clear();
        self.id_to_scc.clear();

        for (idx, key) in self.graph.node_references() {
            self.pk_to_node_idx.insert(key.key.clone(), idx);

            if let Some(x) = &key.id {
                if !self.id_to_scc.contains_key(&x) {
                    self.id_to_scc.insert(x.clone(), BTreeSet::new());
                }

                let set = self.id_to_scc.get_mut(x).expect("Should be present!");
                set.insert(idx);
            }
        }
    }
}
