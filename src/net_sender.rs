//!
//! Module for broadcasting the data over the network to `NetReceiver`s.
//!

use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
// ---
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use xxhash_rust::xxh3::xxh3_64;
// ---
use crate::common;
use crate::common::SubscribersMapArc;
use crate::config;
use crate::utils;
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
    rt: Runtime,
    /// A socked used for sending the data to the subscribers.
    sender_socket: UdpSocket,
    /// A table of the subscribed receivers with the UNIX timestamp of the current lifetime.
    subscribers: SubscribersMapArc,
}

impl NetSender {
    pub fn new(params: NetSenderParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        let subscribers = Arc::new(Mutex::new(BTreeMap::new()));

        // Spawn the task that will accept the receiver heartbeats
        rt.spawn(Self::registrator_task(
            params.addr,
            params.running,
            subscribers.clone(),
        ));

        // Spawn the sender UDP socket
        let sender_socket = match rt.block_on(UdpSocket::bind("0.0.0.0:0")) {
            Ok(x) => x,
            Err(e) => panic!("Failed to bind to the sender socket! ERROR: {}", e),
        };

        NetSender {
            rt,
            sender_socket,
            subscribers,
        }
    }

    //
    // Splits the provided data payload into datagrams of specific size containing metadata
    // to reconstruct the payload after receiving.
    //
    // +-----------------+-----------+-----------+-----------------------------------+
    // |    hash (8B)    |  idx (4B) | total (4B)| payload (up to max datagram size) |
    // +-----------------+-----------+-----------+-----------------------------------+
    //
    fn split_to_datagrams(data: &[u8]) -> Vec<Vec<u8>> {
        let mut in_cursor = std::io::Cursor::new(data);

        let mut res = vec![];

        let hash = xxh3_64(data);
        let hash = hash.to_le_bytes();

        let (_, _, payload_size) = common::get_datagram_sizes();
        let data_size = data.len();

        let num_dgrams: u32 = ((data_size + payload_size - 1) / payload_size)
            .try_into()
            .expect("!");

        for dgram_idx in 0..num_dgrams {
            let mut out_buffer: Vec<u8> = Vec::new();
            let mut out_cursor = std::io::Cursor::new(&mut out_buffer);

            _ = out_cursor.write(&hash).expect("!");
            _ = out_cursor.write(&dgram_idx.to_le_bytes()).expect("!");
            _ = out_cursor.write(&num_dgrams.to_le_bytes()).expect("!");

            let mut lc = in_cursor.take(payload_size as u64);
            lc.read_to_end(&mut out_buffer).expect("!");
            in_cursor = lc.into_inner();
            res.push(out_buffer);
        }

        res
    }
    // ---

    pub fn broadcast(&self, data: &[u8]) -> Result<(), NetSenderError> {
        let subs_guard = self.subscribers.lock().expect("Should be lockable!");

        let datagrams = Self::split_to_datagrams(data);

        for (dest_sock_addr, _valid_until) in subs_guard.iter() {
            debug!(tag: "sender", "\t\tSending to '{dest_sock_addr}'.");
            for dgram in datagrams.iter() {
                if let Err(e) = self
                    .rt
                    .block_on(self.sender_socket.send_to(dgram, *dest_sock_addr))
                {
                    warn!("Failed to send datagram to '{dest_sock_addr:?}'! ERROR: {e}");
                };
            }
        }

        Ok(())
    }

    async fn registrator_task(addr: String, running: Arc<AtomicBool>, subs: SubscribersMapArc) {
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
            let mut buf = [0; config::BUFFER_SIZE];
            let (recv, peer) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    warn!(tag: "registrator_task", "Failed to read the datagram! ERROR: {}!", e);
                    continue;
                }
            };
            // We expect 2 byte port as a payload
            if recv != 2 {
                warn!("Incorect heartbeat received from '{peer}'!");
                continue;
            }

            // Read the port that the receiver will listen for the data
            let mut two_bytes = [0; 2];
            two_bytes.copy_from_slice(&buf[..2]);
            let recv_port = u16::from_ne_bytes(two_bytes);
            let recv_socket = SocketAddr::new(peer.ip(), recv_port);

            // Insert/update this subscriber
            let mut subs_guard = subs.lock().expect("Should be lockable!");
            subs_guard.insert(recv_socket, utils::unix_ts() + config::SUBSCRIBER_LIFETIME);
            debug!(tag: "subscribers", "SUBSCRIBERS: {subs_guard:#?}");

            debug!(tag: "registrator_task", "Accepted a heartbeat from '{peer}' listening for data at port {recv_port}.");
        }
    }
}

#[cfg(test)]
mod tests {

    use rand::Rng;
    // ---
    use super::*;

    #[test]
    fn test_split_to_datagrams() {
        //
        // +-----------------+-----------+-----------+-----------------------------------+
        // |    hash (8B)    |  idx (4B) | total (4B)| payload (up to max datagram size) |
        // +-----------------+-----------+-----------+-----------------------------------+
        //

        let (dgram_size, header_size, _) = common::get_datagram_sizes();

        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..20000).map(|_| rng.gen()).collect();

        let hash = xxh3_64(&data);
        let num_dgrams = (data.len() as f32 / (dgram_size - header_size) as f32).ceil() as u32;

        let datagrams = NetSender::split_to_datagrams(&data);

        let mut act_payload = vec![];

        for (idx, d) in datagrams.iter().enumerate() {
            let index = idx as u32;

            // Check hash
            assert_eq!(&d[0..8], &hash.to_le_bytes());
            // Check datagram indices
            assert_eq!(&d[8..12], &index.to_le_bytes());
            // Check datagram count
            assert_eq!(&d[12..16], &num_dgrams.to_le_bytes());

            act_payload.extend_from_slice(&d[16..]);
        }
        assert_eq!(act_payload, data);
    }
}
