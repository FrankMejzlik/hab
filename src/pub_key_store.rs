use std::cmp::{Ord, Ordering};
use std::collections::{BTreeMap, BTreeSet};
// ---
use serde::{Deserialize, Serialize};
// ---
use crate::common::{SenderIdentity, UnixTimestamp, SenderId};

///
/// A wrapper struct for sotred public key that also holds the time the key was first
/// received and a layer it belongs to.
///
#[derive(Debug, Serialize, Deserialize, Clone, Eq)]
pub struct StoredPubKey<PublicKey: PartialEq + Eq + PartialOrd> {
    pub key: PublicKey,
    pub received: UnixTimestamp,
    pub layer: u8,
}

impl<PublicKey: PartialEq + Eq + PartialOrd> PartialEq for StoredPubKey<PublicKey> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}
impl<PublicKey: PartialEq + Eq + PartialOrd> Ord for StoredPubKey<PublicKey> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort in reverse order
        if self.key == other.key {
			Ordering::Equal
		} else if self.key < other.key {
			Ordering::Less
		}
		else {
			Ordering::Greater
		}
    }
}

impl<PublicKey: PartialEq + Eq + PartialOrd> PartialOrd for StoredPubKey<PublicKey> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Sort in reverse order
        if self.key == other.key {
			Some(Ordering::Equal)
		} else if self.key < other.key {
			Some(Ordering::Less)
		}
		else {
			Some(Ordering::Greater)
		}
    }
}

///
/// A structure for storing the public keys for different sender identities. The identities are assigned
/// an integer ID and whenever the two identities are detected to be the same (some public key lies in both of
/// them) we merge the identities.
///
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PubKeyStore<PublicKey: Ord> {
    pub keys: BTreeMap<SenderIdentity, BTreeSet<StoredPubKey<PublicKey>>>,
	pub next_id: SenderId,
}

impl<PublicKey: Ord> PubKeyStore<PublicKey> {
    pub fn new() -> Self {
        PubKeyStore {
            keys: BTreeMap::new(),
			next_id: 0,
        }
    }
}
