//!
//! Module for broadcasting the data over the network to `NetReceiver`s.
//!

use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::mpsc::Sender;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
// ---
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use xxhash_rust::xxh3::xxh3_64;

// ---
use crate::common::{self, UnixTimestamp};
use crate::utils;
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

#[derive(Debug)]
pub enum NetSenderError {}

#[derive(Debug)]
pub struct NetSenderParams {
    pub addr: String,
    pub running: Arc<AtomicBool>,
    pub datagram_size: usize,
    pub subscriber_lifetime: Duration,
    pub net_buffer_size: usize,
    pub max_piece_size: usize,
    /// An alternative output destination instread of network.
    pub alt_output: Option<Sender<Vec<u8>>>,
}

///
/// Sends the data blocks over the network.
///
/// # See
/// * `struct NetReceiver`
///
pub struct NetSender {
    params: NetSenderParams,
    rt: Runtime,
    /// A socked used for sending the data to the subscribers.
    sender_socket: UdpSocket,
    /// A table of the subscribed receivers with the UNIX timestamp of the current lifetime.
    subscribers: Subscribers,
    // ---
    #[allow(dead_code)]
    messages: Vec<Vec<u8>>,
}

impl NetSender {
    pub fn new(params: NetSenderParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        let subscribers = Subscribers::new();

        // Spawn the task that will accept the receiver heartbeats
        rt.spawn(Self::registrator_task(
            params.addr.clone(),
            params.running.clone(),
            subscribers.clone(),
            params.subscriber_lifetime.as_millis(),
            params.net_buffer_size,
        ));

        // Spawn the sender UDP socket
        let sender_socket = match rt.block_on(UdpSocket::bind("0.0.0.0:0")) {
            Ok(x) => x,
            Err(e) => panic!("Failed to bind to the sender socket! ERROR: {}", e),
        };

        NetSender {
            params,
            rt,
            sender_socket,
            subscribers,
            messages: vec![],
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
    fn split_to_datagrams(data: &[u8], dgram_size: usize) -> Vec<Vec<u8>> {
        let mut in_cursor = std::io::Cursor::new(data);

        let mut res = vec![];

        let hash = xxh3_64(data);
        let hash = hash.to_le_bytes();

        let (_, _, payload_size) = common::get_datagram_sizes(dgram_size);
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

    pub fn broadcast(&mut self, data: &[u8]) -> Result<(), NetSenderError> {
        #[cfg(feature = "simulate_out_of_order")]
        {
            use rand::seq::SliceRandom;
            use rand::thread_rng;

            self.messages.push(data.to_vec());

            #[cfg(feature = "simulate_fake_msgs")]
            {
                use crate::block_signer::SignedBlock;
                use crate::horst::HorstPublicKey;
                use crate::horst::HorstSignature;

                let mut x: SignedBlock<HorstSignature<32, 32, 17>, HorstPublicKey<32>> =
                    bincode::deserialize(&data).expect("!");
                x.signature.data[0][0][0] = 0;
                let xdata = bincode::serialize(&x).expect("!");
                self.messages.push(xdata);
            }
            let mut rng = thread_rng();
            self.messages.shuffle(&mut rng);

            if self.messages.len() >= 5 {
                for data in self.messages.iter() {
                    let mut dead_subs = vec![];
                    {
                        let subs_guard = self.subscribers.0.lock().expect("Should be lockable!");

                        let datagrams = Self::split_to_datagrams(data, self.params.datagram_size);

                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Should be positive.")
                            .as_millis();
                        for (dest_sock_addr, valid_until) in subs_guard.iter() {
                            // If the subscriber is dead already
                            if *valid_until < now {
                                dead_subs.push(*dest_sock_addr);
                                continue;
                            }

                            trace!(tag: "sender", "\t\tSending to '{dest_sock_addr}'.");
                            for dgram in datagrams.iter() {
                                if let Err(e) = self
                                    .rt
                                    .block_on(self.sender_socket.send_to(dgram, *dest_sock_addr))
                                {
                                    warn!("Failed to send datagram to '{dest_sock_addr:?}'! ERROR: {e}");
                                };
                            }
                        }
                    }

                    // Remove dead subscribers
                    for dead_sub in dead_subs {
                        self.subscribers.remove(&dead_sub);
                        debug!(tag:"sender", "Deleted the dead subscriber '{dead_sub}'.");
                    }
                }
                self.messages.clear()
            } else {
                debug!(tag:"sender", "Just cached the message.");
            }
            Ok(())
        }

        #[cfg(not(feature = "simulate_out_of_order"))]
        {
            let datagrams = Self::split_to_datagrams(data, self.params.datagram_size);

            // If the alternative sender is set
            if let Some(alt_tx) = &mut self.params.alt_output {
                for dgram in datagrams.iter() {
                    if let Err(e) = alt_tx.send(dgram.clone()) {
                        warn!(tag: "sender", "Failed to send datagram to the alternative output! ERROR: {}!",e);
                    }
                    std::thread::sleep(Duration::from_micros(10));
                }
            }
            // Else use the network as an output
            else {
                let mut dead_subs = vec![];
                {
                    let subs_guard = self.subscribers.0.lock().expect("Should be lockable!");

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Should be positive.")
                        .as_millis();
                    for (dest_sock_addr, valid_until) in subs_guard.iter() {
                        // If the subscriber is dead already
                        if *valid_until < now {
                            dead_subs.push(*dest_sock_addr);
                            continue;
                        }

                        trace!(tag: "sender", "\t\tSending to '{dest_sock_addr}'.");
                        for dgram in datagrams.iter() {
                            if let Err(e) = self
                                .rt
                                .block_on(self.sender_socket.send_to(dgram, *dest_sock_addr))
                            {
                                warn!(tag: "sender", "Failed to send datagram to '{dest_sock_addr:?}'! ERROR: {e}");
                            };
                            std::thread::sleep(Duration::from_micros(10));
                        }
                    }
                }

                // Remove dead subscribers
                for dead_sub in dead_subs {
                    self.subscribers.remove(&dead_sub);
                    debug!(tag:"sender", "Deleted the dead subscriber '{dead_sub}'.");
                }
            }

            Ok(())
        }
    }

    async fn registrator_task(
        addr: String,
        running: Arc<AtomicBool>,
        mut subs: Subscribers,
        lifetime: UnixTimestamp,
        buffer_size: usize,
    ) {
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
            let mut buf = vec![0; buffer_size];
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
            let recv_port = u16::from_le_bytes(two_bytes);
            let recv_socket = SocketAddr::new(peer.ip(), recv_port);

            // Insert/update this subscriber
            subs.insert(recv_socket, lifetime);

            debug!(tag: "registrator_task", "Accepted a heartbeat from '{peer}' listening for data at port {recv_port}.");
        }
    }
}

///
/// Structure representing a shared table of active subscribers that want to receive a stream of data.
/// Cloning this structure you're creating new owning reference to the table itself.
///
#[derive(Debug, Clone)]
struct Subscribers(Arc<Mutex<BTreeMap<SocketAddr, UnixTimestamp>>>);

impl Subscribers {
    pub fn new() -> Self {
        Subscribers(Arc::new(Mutex::new(BTreeMap::new())))
    }

    pub fn insert(
        &mut self,
        sub_sock: SocketAddr,
        lifetime: UnixTimestamp,
    ) -> Option<UnixTimestamp> {
        let mut subs_guard = self.0.lock().expect("Should be lockable!");
        let res = subs_guard.insert(sub_sock, utils::unix_ts() + lifetime);
        debug!(tag: "subscribers", "SUBSCRIBERS: {subs_guard:#?}");
        res
    }
    pub fn remove(&mut self, sub_sock: &SocketAddr) {
        let mut subs_guard = self.0.lock().expect("Should be lockable!");
        subs_guard.remove(sub_sock);
        debug!(tag: "subscribers", "SUBSCRIBERS: {subs_guard:#?}");
    }
}

#[cfg(test)]
mod tests {

    use rand::Rng;
    // ---
    use super::*;

    const DGRAM_SIZE: usize = 512;

    #[test]
    fn test_split_to_datagrams() {
        //
        // +-----------------+-----------+-----------+-----------------------------------+
        // |    hash (8B)    |  idx (4B) | total (4B)| payload (up to max datagram size) |
        // +-----------------+-----------+-----------+-----------------------------------+
        //

        let (dgram_size, header_size, _) = common::get_datagram_sizes(DGRAM_SIZE);

        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..20000).map(|_| rng.gen()).collect();

        let hash = xxh3_64(&data);
        let num_dgrams = (data.len() as f32 / (dgram_size - header_size) as f32).ceil() as u32;

        let datagrams = NetSender::split_to_datagrams(&data, DGRAM_SIZE);

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
