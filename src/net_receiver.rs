//!
//! Module for receiving the data broadcasted by the `NetSender`.
//!

use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::hash::Hash;
use std::io::{Cursor, Read};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Instant;
use std::time::SystemTime;
use std::{fmt, num};
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
// ---
use byteorder::WriteBytesExt;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::time::{sleep, Duration};
use tungstenite::http::uri::Port;
// ---
use crate::common;
use crate::common::{DgramHash, DgramIdx};
use crate::common::{Error, PortNumber};
use crate::config;
use crate::traits::NetworkReceiverTrait;
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

        str.push_str("[");

        for _ in 0..((self.data.len() + self.frag_size - 1) / self.frag_size) {
            str.push('o');
        }

        for (m_i, _) in self.missing_indices.iter() {
            str.replace_range(m_i..&(m_i + 1), "x");
        }

        str.push_str("]");

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

    pub fn insert(&mut self, dgram: &[u8]) -> Option<Vec<u8>> {
        let (hash, idx, num_fragments, data) = parse_datagram(dgram);
        let (_, _, payload_size) = common::get_datagram_sizes();

        // If a new hash has come
        if !self.blocks.contains_key(&hash) {
            self.blocks.insert(
                hash,
                FragmentedBlock::new(payload_size, num_fragments as usize),
            );
        };

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
    blocks: FragmentedBlocks,
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
        let socket_port = socket
            .local_addr()
            .expect("Should have local address!")
            .port();
        info!(tag: "receiver", "The receiver thread is bound at '{}'...", socket.local_addr().unwrap());

        // Spawn the task that will send periodic hearbeats to the sender
        rt.spawn(Self::heartbeat_task(
            params.addr,
            params.running,
            socket_port,
        ));

        NetReceiver {
            rt,
            socket,
            blocks: FragmentedBlocks::new(),
        }
    }

    pub fn receive(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            let mut buf = vec![0; config::BUFFER_SIZE];
            let (recv, peer) = match self.rt.block_on(self.socket.recv_from(&mut buf)) {
                Ok(x) => x,
                Err(e) => {
                    return Err(Error::new(&format!(
                        "Failed to receive the datagram! ERROR: {}!",
                        e
                    )))
                }
            };
            //debug!(tag: "receiver", "\t\tReceived {recv} bytes from {peer}.");

            // Copy the actual bytes to the resulting vector
            let mut dgram = vec![0; recv];
            dgram.copy_from_slice(&buf[..recv]);

            // Insert the datagram and pass it on if the block is now complete
            if let Some(x) = self.blocks.insert(&dgram) {
                return Ok(x);
            }
        }
    }

    async fn heartbeat_task(addr: String, running: Arc<AtomicBool>, recv_port: PortNumber) {
        let addr = match SocketAddrV4::from_str(&addr) {
            Ok(x) => x,
            Err(e) => panic!("Failed to parse the address '{addr}! ERROR: {e}'"),
        };
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(x) => x,
            Err(e) => panic!("Failed to bind to the heartbeat socket! ERROR: {}", e),
        };

        if let Err(e) = socket.connect(addr).await {
            panic!("Failed to connect to '{addr}'!");
        }
        info!(tag: "heartbeat_task", "Subscribing to the sender at '{addr}'....");

        // The task loop
        while running.load(Ordering::Acquire) {
            debug!(tag: "heartbeat_task", "Sending a heartbeat to the sender at '{addr}'...");
            match socket.send(&recv_port.to_ne_bytes()).await {
                Ok(_) => (),
                Err(e) => warn!("Failed to send a heartbeat to '{addr}'! ERROR: {e}"),
            };
            sleep(Duration::from_secs(5)).await;
        }
    }
}
