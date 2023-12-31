//!
//! Module for receiving the data broadcasted by the `NetSender`.
//!

use std::collections::HashMap;
use std::fmt;
use std::io::{Cursor, Read};
use std::mem::size_of;
use std::net::SocketAddrV4;
use std::sync::mpsc;
use std::time::SystemTime;
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
// ---
use byteorder::{BigEndian, ReadBytesExt};
//use tokio::net::UdpSocket;
use std::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::time::{sleep, Duration};
// ---
use crate::buffer_tracker::BufferTracker;
use crate::common::{Error, Fragment, FragmentId, FragmentOffset};
use crate::net_sender::{NetSender, NetSenderParams};
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

///
/// Parses the provided data buffer (BE) into a structured fragment.
///
/// +-----------------+-------------+-----------+----------------------------------------+
/// | fragment_id (8B)| offset (31b)| more (1b) | payload (up to max datagram size - 8B) |
/// +-----------------+-------------+-----------+----------------------------------------+
///
pub fn parse_fragment(data: &[u8]) -> Result<Fragment, Error> {
    let mut data_cursor = Cursor::new(data);

    // Read fragment ID
    let fragment_id = match data_cursor.read_u64::<BigEndian>() {
        Ok(x) => x,
        Err(_) => {
            return Err(Error::new("Failed to read fragment ID!"));
        }
    };

    // Read Offet + more bit
    let mut offset_more = [0; size_of::<FragmentOffset>()];
    match data_cursor.read_exact(&mut offset_more) {
        Ok(x) => x,
        Err(_) => {
            return Err(Error::new("Failed to read offset + more bit"));
        }
    };

    // Parse the more flag from the last bit
    let more = offset_more[0] & 0b10000000 > 0;
    // Pull down the last bit
    offset_more[0] &= 0b01111111;

    // Parse the offset
    let offset = FragmentOffset::from_be_bytes(offset_more);

    let mut data = vec![];
    data_cursor.read_to_end(&mut data).unwrap();

    Ok(Fragment {
        id: fragment_id,
        offset,
        more,
        payload: data,
    })
}

#[derive(Debug)]
pub struct FragmentedBlock {
    data: Option<Vec<u8>>,
    buffer_tracker: BufferTracker,
    alive_until: SystemTime,
}
impl fmt::Display for FragmentedBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.buffer_tracker)
    }
}

impl FragmentedBlock {
    pub fn new(frag_timeout: Duration) -> Self {
        FragmentedBlock {
            data: Some(vec![]),
            buffer_tracker: BufferTracker::new(),
            alive_until: SystemTime::now() + frag_timeout,
        }
    }
    pub fn is_alive(&self) -> bool {
        self.alive_until >= SystemTime::now()
    }

    pub fn insert(&mut self, fragment: Fragment) -> Option<Vec<u8>> {
        let offset_from = fragment.offset as usize;
        let offset_to = offset_from as usize + fragment.payload.len();

        // Mark as inserted
        let is_complete = self
            .buffer_tracker
            .mark_received(offset_from, offset_to, fragment.more);

        // Make sure that the buffer is large enough
        if offset_to >= self.data.as_ref().unwrap().len() {
            self.data.as_mut().unwrap().resize(offset_to, 0);
        }

        // Copy the data into its position in the buffer
        _ = &self.data.as_mut().unwrap()[offset_from..offset_to].copy_from_slice(&fragment.payload);

        // Check if is complete
        if is_complete {
            self.data.take()
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct FragmentedPieces {
    blocks: HashMap<FragmentId, FragmentedBlock>,
    frag_timeout: Duration,
    last_cleanup: SystemTime,
    // ---
    last_printed: SystemTime,
}

impl fmt::Display for FragmentedPieces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut str = String::new();

        for (k, v) in self.blocks.iter() {
            str.push_str(&format!("[{k}] -> {v}\n"));
        }

        write!(f, "{}", str)
    }
}

impl FragmentedPieces {
    pub fn new(frag_timeout: Duration) -> Self {
        FragmentedPieces {
            blocks: HashMap::new(),
            frag_timeout,
            last_cleanup: SystemTime::now(),
            last_printed: SystemTime::now(),
        }
    }

    ///
    /// Inserts the new fragment into the partialy received block.
    ///
    pub fn insert(&mut self, fragment: &[u8]) -> Option<Vec<u8>> {
        let fragment = match parse_fragment(fragment) {
            Ok(x) => x,
            Err(_) => return None,
        };
        let fragment_id = fragment.id;

        // If a new hash has came in, create a new record
        let record = self
            .blocks
            .entry(fragment_id)
            .or_insert_with(|| FragmentedBlock::new(self.frag_timeout));

        let res = match record.insert(fragment) {
            Some(x) => {
                self.blocks.remove(&fragment_id);
                Some(x)
            }
            None => None,
        };

        // Cleanup the old records with the configured minimal interval
        if SystemTime::now() > self.last_cleanup + self.frag_timeout {
            let mut keys_to_remove = vec![];

            for (k, v) in self.blocks.iter() {
                if !v.is_alive() {
                    keys_to_remove.push(*k);
                }
            }

            // Remove the keys that are not alive anymore
            for k in keys_to_remove {
                self.blocks.remove(&k);
            }

            self.last_cleanup = SystemTime::now();
        }

        // Print the state with the minimum interval
        if SystemTime::now() > self.last_printed + Duration::from_secs(1) {
            debug!(tag: "fragmented_blocks", "\n{}", self);
            self.last_printed = SystemTime::now();
        }
        res
    }
}

#[derive(Debug)]
pub struct NetReceiverParams {
    pub addr: String,
    pub heartbeat_period: Duration,
    pub running: Arc<AtomicBool>,
    pub frag_timeout: Duration,
    pub distribute: Option<String>,
    pub deliver: bool,
    pub receiver_lifetime: Duration,
    pub dgram_delay: Duration,
    /// An alternative output destination instead of network.
    pub alt_input: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
}

///
/// Receives the data blocks over the network from the `NetSender`.
///
/// # See
/// * `struct NetSender`
///
#[allow(dead_code)]
pub struct NetReceiver {
    params: NetReceiverParams,
    rt: Runtime,
    blocks: FragmentedPieces,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
}

impl NetReceiver {
    pub fn new(mut params: NetReceiverParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        // Bind on some available port
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(x) => Arc::new(x),
            Err(e) => panic!("Failed to bind to the receiver socket! ERROR: {}", e),
        };

        info!(tag: "receiver", "The receiver thread is bound at '{}'...", socket.local_addr().unwrap());

        // Spawn the task that will send periodic heartbeats to the sender
        rt.spawn(Self::heartbeat_task(
            params.addr.clone(),
            params.running.clone(),
            params.heartbeat_period,
            socket.clone(),
        ));

        // Spawn network sender if should run as a distributor
        let mut net_sender = if let Some(distr_addr) = &params.distribute {
            let net_sender_params = NetSenderParams {
                addr: distr_addr.clone(),
                running: params.running.clone(),
                subscriber_lifetime: params.receiver_lifetime,
                datagram_size: 0,  //< Not relevant for distributor
                max_piece_size: 0, //< Not relevant for distributor
                dgram_delay: params.dgram_delay,
                alt_output: None, //< Not relevant for distributor
            };
            Some(NetSender::new(net_sender_params))
        } else {
            None
        };

        info!(tag: "receiver", "params.distribute: {:?}", params.distribute);

        // Create a channel
        let (tx, rx) = mpsc::channel::<Vec<u8>>();

        let mut alt_dgram_receiver = params.alt_input.take();
        let buff_size = 65_536 * 2;
        std::thread::spawn(move || {
            let mut buf = vec![0; buff_size];
            loop {
                // If the alternative receiver is set
                let recv = if let Some(alt_rx) = &mut alt_dgram_receiver {
                    match alt_rx.recv() {
                        Ok(recv_data) => {
                            let recv = recv_data.len();
                            for i in 0..recv {
                                buf[i] = recv_data[i];
                            }
                            recv
                        }
                        Err(e) => {
                            warn!(tag: "receiver", "Failed to receive the datagram from the alternative source, terminating! ERROR: {}!",e);
                            return;
                        }
                    }
                }
                // Else use network as a source
                else {
                    info!(tag: "receiver", "Blocking on {}", socket.local_addr().unwrap());
                    match socket.recv_from(&mut buf) {
                        Ok(x) => {
                            info!(tag: "receiver", "Received {} bytes from '{}'", x.0, x.1);
                            x.0
                        }
                        Err(e) => {
                            warn!(tag: "receiver", "Failed to receive the datagram! ERROR: {}!",e);
                            0
                        }
                    }
                };

                // Copy the actual bytes to the resulting vector
                let mut frag = vec![0; recv];
                frag.copy_from_slice(&buf[..recv]);

                // If the receiver is set to distribute the data, do it
                if let Some(sender) = &mut net_sender {
                    if let Err(e) = sender.broadcast_fragment(&frag) {
                        warn!(tag: "receiver", "Failed to distribute fragment! ERROR: {e:?}");
                    }
                }

                // If the receiver is set to deliver the data, do it
                if params.deliver {
                    if let Err(e) = tx.send(frag) {
                        warn!(tag: "receiver", "Failed to send to the queue! ERROR: {e}");
                    }
                }
            }
        });

        let blocks = FragmentedPieces::new(params.frag_timeout);
        NetReceiver {
            params,
            rt,
            blocks,
            rx,
        }
    }

    pub fn receive(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            if let Ok(dgram) = self.rx.recv() {
                // Insert the datagram and pass it on if the block is now complete
                if let Some(x) = self.blocks.insert(&dgram) {
                    return Ok(x);
                }
            } else {
                return Err(Error::new("Failed to receive from the queue!"));
            }
        }
    }

    async fn heartbeat_task(
        addr: String,
        running: Arc<AtomicBool>,
        period: Duration,
        recv_sock: Arc<UdpSocket>,
    ) {
        let addr = match SocketAddrV4::from_str(&addr) {
            Ok(x) => x,
            Err(e) => panic!("Failed to parse the address '{addr}! ERROR: {e}'"),
        };

        info!(tag: "heartbeat_task", "Subscribing to the sender at '{addr}'....");
        // if recv_sock.connect(addr).is_err() {
        //     panic!("Failed to set source addr '{}'!", addr);
        // }

        // The task loop
        while running.load(Ordering::Acquire) {
            debug!(tag: "heartbeat_task", "Sending a heartbeat to the sender at '{addr}'...");
            match recv_sock.send_to(&[0xBE, 0xAD], addr) {
                Ok(_) => (),
                Err(e) => warn!("Failed to send a heartbeat to '{addr}'! ERROR: {e}"),
            };
            sleep(period).await;
        }
    }
}
