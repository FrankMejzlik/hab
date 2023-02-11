//!
//! Module for broadcasting the data over the network to `NetReceiver`s.
//!

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
// ---
use std::net::{Ipv4Addr, SocketAddrV4};
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
    pub fn new(params: NetSenderParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        // Spawn the task that will accept the receiver heartbeats
        rt.spawn(Self::registrator_task(params.port));

        NetSender {
            subscribers: Arc::new(Mutex::new(BTreeMap::new())),
            rt,
        }
    }

    pub fn broadcast(&self, data: &[u8]) -> Result<(), NetSenderError> {
        debug!(tag: "sender", "\t...broadcasting {} bytes...", data.len());
        Ok(())
    }

    async fn registrator_task(port: u32) {
        let addr = SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0),
            port.try_into().expect("Failed to convert to u16!"),
        );
        let socket = match UdpSocket::bind(&addr).await {
            Ok(x) => x,
            Err(e) => panic!("Failed to bind to socket! ERROR: {}", e),
        };
        info!(tag: "registrator", "Accepting heartbeats from receivers...");

        loop {
            let mut buf = [0; 1024];
            let (recv, peer) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    warn!(tag: "registrator", "Failed to read the datagram! ERROR: {}!", e);
                    continue;
                }
            };
            debug!(tag: "registrator", "Received a heartbeat from '{}': {:?}", peer, &buf[..recv]);
        }
    }
}
