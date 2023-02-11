//!
//! Module for broadcasting the data over the network to `NetReceiver`s.
//!

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
// ---
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use tokio::runtime::Runtime;
use tokio::time::sleep;
// ---
use crate::common::UnixTimestamp;

#[derive(Debug)]
pub enum NetSenderError {}

#[derive(Debug)]
pub struct NetSenderParams {
    pub port: u32,
}

///
/// Sends the data blocks over the network.
///
/// # See
/// * `struct NetReceiver`
///
pub struct NetSender {
    /// A table of the subscribed receivers with the UNIX timestamp of the current lifetime.
    subscribers: Arc<Mutex<BTreeMap<String, UnixTimestamp>>>,
    rt: Runtime,
}

impl NetSender {
    pub fn new(_params: NetSenderParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        // Spawn the task that will accept the receiver heartbeats
        rt.spawn(Self::registrator_task());

        NetSender {
            subscribers: Arc::new(Mutex::new(BTreeMap::new())),
            rt,
        }
    }

    pub fn broadcast(&self, data: &[u8]) -> Result<(), NetSenderError> {
        trace!("\t...broadcasting {} bytes...", data.len());
        Ok(())
    }

    async fn registrator_task() {
        loop {
            debug!("\t ... accepting receiver heartbeats ...");
            sleep(Duration::from_secs(5)).await;
        }
    }
}
