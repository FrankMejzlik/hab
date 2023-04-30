//!
//! Module for broadcasting the data over the network to `NetReceiver`s.
//!

use std::collections::BTreeMap;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
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

use crate::common::FragmentOffset;
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
    pub max_piece_size: usize,
    pub dgram_delay: Duration,
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
    sender_socket: Arc<UdpSocket>,
    /// A table of the subscribed receivers with the UNIX timestamp of the current lifetime.
    subscribers: ActiveReceivers,
    dgram_delay: Duration,
    // ---
    #[allow(dead_code)]
    messages: Vec<Vec<u8>>,
}

impl NetSender {
    pub fn new(params: NetSenderParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        let subscribers = ActiveReceivers::new();

        // Spawn the sender UDP socket
        let sender_socket = match rt.block_on(UdpSocket::bind(params.addr.clone())) {
            Ok(x) => Arc::new(x),
            Err(e) => panic!("Failed to bind to the sender socket! ERROR: {}", e),
        };

        // Spawn the task that will accept the receiver heartbeats
        rt.spawn(Self::registrator_task(
            sender_socket.clone(),
            params.running.clone(),
            subscribers.clone(),
            params.subscriber_lifetime.as_millis(),
            params.datagram_size * 2,
        ));

        let dgram_delay = params.dgram_delay;
        NetSender {
            params,
            rt,
            sender_socket,
            subscribers,
            dgram_delay,
            messages: vec![],
        }
    }

    ///
    /// Splits the provided data payload into fragments of specific size do they fit within the
    /// single datagram of a configured size of `max_dgram_size`. In BE.
    ///
    /// +-----------------+-------------+-----------+----------------------------------------+
    /// | fragment_id (8B)| offset (31b)| more (1b) | payload (up to max datagram size - 8B) |
    /// +-----------------+-------------+-----------+----------------------------------------+
    ///
    fn split_to_datagrams(data: &[u8], max_dgram_size: usize) -> Vec<Vec<u8>> {
        // Calculate the size of the payload
        let (_, _, payload_size) = common::get_fragment_dgram_sizes(max_dgram_size);
        let data_size = data.len();

        // Compute how many dgrams will be needed to send the data
        let num_dgrams = (data_size + payload_size - 1) / payload_size;

        // Compute the hash of the data
        let fragment_id = xxh3_64(data).to_be_bytes();

        // The resulting datagrams
        let mut dgram_payloads = vec![];

        // Instantiate a cursor over the borrowd buffer
        let mut in_cursor = Cursor::new(data);

        // Iterate of the number of dgrams to create
        for _ in 0..num_dgrams {
            // The bytes holding 31 bits of the offset and 1 bit of more flag
            let mut offset_more = (in_cursor.position() as FragmentOffset).to_be_bytes();
            let _offset = in_cursor.position();

            let mut payload_bytes = vec![0; payload_size];
            if let Ok(written) = in_cursor.read(&mut payload_bytes) {
                let unwritten = payload_size - written;
                // If is the last one, truncate the buffer
                if unwritten > 0 {
                    payload_bytes.truncate(written);
                }
            }

            // If this is the last datagram, set the more flag to 0
            if in_cursor.position() != data_size as u64 {
                // Set the MSb
                offset_more[0] |= 0b1000_0000;
            }

            let mut out_cursor = Cursor::new(vec![]);
            _ = out_cursor.write(&fragment_id).unwrap();
            _ = out_cursor.write(&offset_more).unwrap();
            _ = out_cursor.write(&payload_bytes).unwrap();

            dgram_payloads.push(out_cursor.into_inner());
        }

        dgram_payloads
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
                            std::thread::sleep(self.dgram_delay);
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
        socket: Arc<UdpSocket>,
        running: Arc<AtomicBool>,
        mut subs: ActiveReceivers,
        lifetime: UnixTimestamp,
        buffer_size: usize,
    ) {
        info!(tag: "registrator_task", "Accepting heartbeats from receivers at {}...", socket.local_addr().unwrap());

        // The main loop
        while running.load(Ordering::Acquire) {
            let mut buf = vec![0; buffer_size];
            let (recv, peer) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    warn!(tag: "registrator_task", "Failed to read the datagram! ERROR: {}!", e);
                    continue;
                }
            };
            // We expect 2 byte magic word 0xBEAD
            if recv != 2 {
                warn!(tag: "registrator_task", "Incorrect heartbeat received from '{peer}'! Received {recv} B.");
                continue;
            }

            // Read the magic
            let mut magic_bytes = [0; 2];
            magic_bytes.copy_from_slice(&buf[..2]);

            if magic_bytes != [0xBE, 0xAD] {
                warn!(tag: "registrator_task", "Incorrect heartbeat received from '{peer}'! Incorrect magic word.");
                continue;
            }

            let recv_port = peer.port();
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
struct ActiveReceivers(Arc<Mutex<BTreeMap<SocketAddr, UnixTimestamp>>>);

impl ActiveReceivers {
    pub fn new() -> Self {
        ActiveReceivers(Arc::new(Mutex::new(BTreeMap::new())))
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
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..20000).map(|_| rng.gen()).collect();

        let hash = xxh3_64(&data);
        let exp_payload_size = DGRAM_SIZE - 20; // UDP + our header

        let datagrams = NetSender::split_to_datagrams(&data, DGRAM_SIZE);

        let mut act_payload = vec![];

        for (idx, d) in datagrams.iter().enumerate() {
            let index = (idx * exp_payload_size) as u32;
            let mut offset = index.to_be_bytes();
            if idx != datagrams.len() - 1 {
                offset[0] |= 0b1000_0000;
            }

            // Check hash
            assert_eq!(&d[0..8], &hash.to_be_bytes());
            // Check datagram indices
            assert_eq!(&d[8..12], &offset);

            act_payload.extend_from_slice(&d[12..]);
        }
        assert_eq!(act_payload, data);
    }
}
