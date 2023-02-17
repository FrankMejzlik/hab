//!
//! Module for broadcasting the data over the network to `NetReceiver`s.
//!

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
// ---
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
// ---
use crate::common::UnixTimestamp;
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub enum NetSenderError {}

#[derive(Debug)]
pub struct NetSenderParams {
    pub addr: String,
    pub running: Arc<AtomicBool>,
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
    pub fn new(params: NetSenderParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        // Spawn the task that will accept the receiver heartbeats
        rt.spawn(Self::registrator_task(params.addr, params.running));

        NetSender {
            subscribers: Arc::new(Mutex::new(BTreeMap::new())),
            rt,
        }
    }

    pub fn broadcast(&self, data: &[u8]) -> Result<(), NetSenderError> {
        debug!(tag: "sender", "\t...broadcasting {} bytes...", data.len());
        Ok(())
    }

    async fn registrator_task(addr: String, running: Arc<AtomicBool>) {
        let addr = match SocketAddrV4::from_str(&addr) {
            Ok(x) => x,
            Err(e) => panic!("Failed to parse the address '{addr}! ERROR: {e}'"),
        };
        let socket = match UdpSocket::bind(&addr).await {
            Ok(x) => x,
            Err(e) => panic!("Failed to bind to socket! ERROR: {}", e),
        };
        info!(tag: "registrator_task", "Accepting heartbeats from receivers at {addr}...");

        while running.load(Ordering::Acquire) {
            let mut buf = [0; 1024];
            let (recv, peer) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    warn!(tag: "registrator_task", "Failed to read the datagram! ERROR: {}!", e);
                    continue;
                }
            };
            debug!(tag: "registrator_task", "Received a heartbeat from '{}': {:?}", peer, &buf[..recv]);
        }
    }
}
