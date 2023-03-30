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
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

///
/// Parses the provided data buffer (BE) into a structured fragment.
///
/// +-----------------+-------------+-----------+----------------------------------------+
/// | fragment_id (8B)| offset (31b)| more (1b) | payload (up to max datagram size - 8B) |
/// +-----------------+-------------+-----------+----------------------------------------+
///
pub fn parse_fragment(data: &[u8]) -> Fragment {
    let mut data_cursor = Cursor::new(data);

    // Read fragment ID
    let fragment_id = data_cursor.read_u64::<BigEndian>().unwrap();
    // Read Offet + more bit
    let mut offset_more = [0; size_of::<FragmentOffset>()];
    _ = data_cursor.read_exact(&mut offset_more);

    // Parse the more flag from the last bit
    let more = offset_more[0] & 0b10000000 > 0;
    // Pull down the last bit
    offset_more[0] &= 0b01111111;

    // Parse the offset
    let offset = FragmentOffset::from_be_bytes(offset_more);

    let mut data = vec![];
    data_cursor.read_to_end(&mut data).unwrap();

    Fragment {
        id: fragment_id,
        offset,
        more,
        payload: data,
    }
}

#[derive(Debug)]
pub struct FragmentedBlock {
    data: Option<Vec<u8>>,
    buffer_tracker: BufferTracker,
}
impl fmt::Display for FragmentedBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.buffer_tracker)
    }
}

impl FragmentedBlock {
    pub fn new() -> Self {
        FragmentedBlock {
            data: Some(vec![]),
            buffer_tracker: BufferTracker::new(),
        }
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
pub struct FragmentedBlocks {
    blocks: HashMap<FragmentId, FragmentedBlock>,
    // ---
    last_printed: SystemTime,
}

impl fmt::Display for FragmentedBlocks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut str = String::new();

        for (k, v) in self.blocks.iter() {
            str.push_str(&format!("[{k}] -> {v}\n"));
        }

        write!(f, "{}", str)
    }
}

impl FragmentedBlocks {
    pub fn new() -> Self {
        FragmentedBlocks {
            blocks: HashMap::new(),
            last_printed: SystemTime::now(),
        }
    }

    ///
    /// Inserts the new fragment into the partialy received block.
    ///
    pub fn insert(&mut self, fragment: &[u8]) -> Option<Vec<u8>> {
        let fragment = parse_fragment(fragment);
        let fragment_id = fragment.id;

        // If a new hash has came in, create a new record
        let record = self
            .blocks
            .entry(fragment_id)
            .or_insert_with(|| FragmentedBlock::new());

        let res = match record.insert(fragment) {
            Some(x) => {
                self.blocks.remove(&fragment_id);
                Some(x)
            }
            None => None,
        };

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
    pub running: Arc<AtomicBool>,
    pub datagram_size: usize,
    pub net_buffer_size: usize,
    /// An alternative output destination instread of network.
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
    blocks: FragmentedBlocks,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
}

impl NetReceiver {
    #[allow(dead_code)]
    pub fn new(mut params: NetReceiverParams) -> Self {
        let rt = Runtime::new().expect("Failed to allocate the new task runtime!");

        // Bind on some available port
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(x) => Arc::new(x),
            Err(e) => panic!("Failed to bind to the receiver socket! ERROR: {}", e),
        };

        info!(tag: "receiver", "The receiver thread is bound at '{}'...", socket.local_addr().unwrap());

        // Spawn the task that will send periodic hearbeats to the sender
        rt.spawn(Self::heartbeat_task(
            params.addr.clone(),
            params.running.clone(),
            socket.clone(),
        ));

        // Create a channel
        let (tx, rx) = mpsc::channel::<Vec<u8>>();

        let mut alt_dgram_receiver = params.alt_input.take();
        let buff_size = params.net_buffer_size;
        std::thread::spawn(move || {
            let mut buf = vec![0; buff_size];
            loop {
                // If the alternative reciever is set
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
                    match socket.recv_from(&mut buf) {
                        Ok(x) => x.0,
                        Err(e) => {
                            warn!(tag: "receiver", "Failed to receive the datagram! ERROR: {}!",e);
                            0
                        }
                    }
                };

                // Copy the actual bytes to the resulting vector
                let mut dgram = vec![0; recv];
                dgram.copy_from_slice(&buf[..recv]);

                if let Err(e) = tx.send(dgram) {
                    warn!(tag: "receiver", "Failed to send to the queue! ERROR: {e}");
                }
            }
        });

        NetReceiver {
            params,
            rt,
            blocks: FragmentedBlocks::new(),
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

    async fn heartbeat_task(addr: String, running: Arc<AtomicBool>, recv_sock: Arc<UdpSocket>) {
        let addr = match SocketAddrV4::from_str(&addr) {
            Ok(x) => x,
            Err(e) => panic!("Failed to parse the address '{addr}! ERROR: {e}'"),
        };

        info!(tag: "heartbeat_task", "Subscribing to the sender at '{addr}'....");
        if recv_sock.connect(addr).is_err() {
            panic!("Failed to set source addr '{}'!", addr);
        }

        // The task loop
        while running.load(Ordering::Acquire) {
            debug!(tag: "heartbeat_task", "Sending a heartbeat to the sender at '{addr}'...");
            match recv_sock.send(&42_u8.to_be_bytes()) {
                Ok(_) => (),
                Err(e) => warn!("Failed to send a heartbeat to '{addr}'! ERROR: {e}"),
            };
            sleep(Duration::from_secs(5)).await;
        }
    }
}
