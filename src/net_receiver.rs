//!
//! Module for receiving the data broadcasted by the `NetSender`.
//!

use std::net::{Ipv4Addr, SocketAddrV4};
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
// ---
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
// ---
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct NetReceiverParams {
    pub addr: String,
    pub running: Arc<AtomicBool>,
}

///
/// Receives the data blocks over the network from the `NetSender`.
///
/// # See
/// * `struct NetSender`
///
#[allow(dead_code)]
pub struct NetReceiver {
    rt: Runtime,
}

impl NetReceiver {
    #[allow(dead_code)]
    pub fn new(params: NetReceiverParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        // Spawn the task that will accept the receiver heartbeats
        rt.spawn(Self::lookup_task(params.addr, params.running));

        NetReceiver { rt }
    }

    async fn lookup_task(addr: String, running: Arc<AtomicBool>) {
        let addr = SocketAddrV4::from_str(&addr).expect("Failed to parse the address!");

        let socket = match UdpSocket::bind(addr).await {
            Ok(x) => x,
            Err(e) => panic!("Failed to bind to socket! ERROR: {}", e),
        };
        info!(tag: "registrator", "Accepting heartbeats from receivers...");

        while running.load(Ordering::Acquire) {
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
