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
use tokio::time::{sleep, Duration};
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
    socket: UdpSocket,
}

impl NetReceiver {
    #[allow(dead_code)]
    pub fn new(params: NetReceiverParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        // Bind on some available port
        let socket = match rt.block_on(UdpSocket::bind("0.0.0.0:0")) {
            Ok(x) => x,
            Err(e) => panic!("Failed to bind to the receiver socket! ERROR: {}", e),
        };
        info!(tag: "receiver", "The receiver thread is bound at '{}'...", socket.local_addr().unwrap());

        // Spawn the task that will send periodic hearbeats to the sender
        rt.spawn(Self::heartbeat_task(params.addr, params.running));

        NetReceiver { rt, socket }
    }

    async fn heartbeat_task(addr: String, running: Arc<AtomicBool>) {
        let addr = match SocketAddrV4::from_str(&addr) {
            Ok(x) => x,
            Err(e) => panic!("Failed to parse the address '{addr}! ERROR: {e}'"),
        };
        info!(tag: "heartbeat_task", "Subscribing to the sender at '{addr}'....");

        // The task loop
        while running.load(Ordering::Acquire) {
            debug!(tag: "heartbeat_task", "Sending a heartbeat to the sender at '{addr}'...");
            sleep(Duration::from_secs(5)).await;
        }
    }
}
