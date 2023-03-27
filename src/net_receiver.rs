//!
//! Module for receiving the data broadcasted by the `NetSender`.
//!

use std::collections::HashMap;
use std::fmt;
use std::io::{Cursor, Read};
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
use byteorder::{LittleEndian, ReadBytesExt};
//use tokio::net::UdpSocket;
use std::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::time::{sleep, Duration};
// ---
use crate::common::{self, DgramHash, DgramIdx, Error, PortNumber};
#[allow(unused_imports)]
use crate::{debug, error, info, trace, warn};

pub fn parse_datagram(data: &[u8]) -> (DgramHash, DgramIdx, DgramIdx, Vec<u8>) {
    let mut in_cursor = Cursor::new(data);

    let hash = in_cursor
        .read_u64::<LittleEndian>()
        .expect("Parse should not fail!");
    let idx = in_cursor
        .read_u32::<LittleEndian>()
        .expect("Parse should not fail!");
    let count = in_cursor
        .read_u32::<LittleEndian>()
        .expect("Parse should not fail!");
    let mut data = vec![];
    in_cursor
        .read_to_end(&mut data)
        .expect("Parse should not fail!");

    (hash, idx, count, data)
}

#[derive(Debug)]
pub struct FragmentedBlock {
    data: Vec<u8>,
    frag_size: usize,
    missing_indices: HashMap<usize, ()>,
}
impl fmt::Display for FragmentedBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut str = String::new();

        str.push('[');

        for _ in 0..((self.data.len() + self.frag_size - 1) / self.frag_size) {
            str.push('o');
        }

        for (m_i, _) in self.missing_indices.iter() {
            str.replace_range(m_i..&(m_i + 1), "x");
        }

        str.push(']');

        write!(f, "{}", str)
    }
}

impl FragmentedBlock {
    pub fn new(frag_size: usize, num_fragments: usize) -> Self {
        let mut missing_indices = HashMap::new();

        for i in 0..num_fragments {
            missing_indices.insert(i, ());
        }
        FragmentedBlock {
            data: vec![0_u8; frag_size * num_fragments],
            frag_size,
            missing_indices,
        }
    }
    pub fn insert(&mut self, idx: usize, fragment: &[u8]) -> Option<Vec<u8>> {
        let idx_from = idx * self.frag_size;
        let idx_to = idx_from + fragment.len();
        let _ = &self.data[idx_from..idx_to].copy_from_slice(fragment);

        // Mark as ready
        self.missing_indices.remove(&idx);

        // Check if is complete
        if self.missing_indices.is_empty() {
            Some(self.data.clone())
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct FragmentedBlocks {
    blocks: HashMap<DgramHash, FragmentedBlock>,
    datagram_size: usize,
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
    pub fn new(datagram_size: usize) -> Self {
        FragmentedBlocks {
            blocks: HashMap::new(),
            last_printed: SystemTime::now(),
            datagram_size,
        }
    }

    pub fn insert(&mut self, dgram: &[u8]) -> Option<Vec<u8>> {
        let (hash, idx, num_fragments, data) = parse_datagram(dgram);
        let (_, _, payload_size) = common::get_datagram_sizes(self.datagram_size);

        // If a new hash has come
        self.blocks
            .entry(hash)
            .or_insert_with(|| FragmentedBlock::new(payload_size, num_fragments as usize));

        let record = self
            .blocks
            .get_mut(&hash)
            .expect("Should be there already!");

        let res = match record.insert(idx as usize, &data) {
            Some(x) => {
                self.blocks.remove(&hash);
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
            Ok(x) => x,
            Err(e) => panic!("Failed to bind to the receiver socket! ERROR: {}", e),
        };
        let socket_port = socket
            .local_addr()
            .expect("Should have local address!")
            .port();

        info!(tag: "receiver", "The receiver thread is bound at '{}'...", socket.local_addr().unwrap());

        // Spawn the task that will send periodic hearbeats to the sender
        rt.spawn(Self::heartbeat_task(
            params.addr.clone(),
            params.running.clone(),
            socket_port,
        ));
        let datagram_size = params.datagram_size;

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
                            buf.copy_from_slice(&recv_data);
                            recv
                        }
                        Err(e) => {
                            warn!(tag: "receiver", "Failed to receive the datagram from the alternative source! ERROR: {}!",e);
                            0
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
            blocks: FragmentedBlocks::new(datagram_size),
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

    async fn heartbeat_task(addr: String, running: Arc<AtomicBool>, recv_port: PortNumber) {
        let addr = match SocketAddrV4::from_str(&addr) {
            Ok(x) => x,
            Err(e) => panic!("Failed to parse the address '{addr}! ERROR: {e}'"),
        };
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(x) => x,
            Err(e) => panic!("Failed to bind to the heartbeat socket! ERROR: {}", e),
        };

        if socket.connect(addr).is_err() {
            panic!("Failed to connect to '{addr}'!");
        }
        info!(tag: "heartbeat_task", "Subscribing to the sender at '{addr}'....");

        // The task loop
        while running.load(Ordering::Acquire) {
            debug!(tag: "heartbeat_task", "Sending a heartbeat to the sender at '{addr}'...");
            match socket.send(&recv_port.to_le_bytes()) {
                Ok(_) => (),
                Err(e) => warn!("Failed to send a heartbeat to '{addr}'! ERROR: {e}"),
            };
            sleep(Duration::from_secs(5)).await;
        }
    }
}
