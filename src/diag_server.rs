// use std::thread;
// use std::{
//     net::SocketAddr,
//     sync::{Arc, Mutex},
// };
// // ---
// #[allow(unused_imports)]
// use log::{debug, error, info, trace, warn};
// use websocket::{
//     stream::sync::TcpStream,
//     sync::{Server, Writer},
//     Message,
// };

// // ---
// use crate::common::Error;
// use crate::traits::DiagServerTrait;

// pub struct DiagServer {
//     sender: Arc<Mutex<Option<Writer<TcpStream>>>>,
// }

// impl DiagServer {
//     pub fn new(sockaddr: SocketAddr) -> Self {
//         let out_sender = Arc::new(Mutex::new(None));
//         let out_sender_c = out_sender.clone();
//         thread::spawn(move || {
//             let server = Server::bind(sockaddr).unwrap();
//             info!(
//                 "Spawned the websocket diag server listening at {}...",
//                 sockaddr
//             );

//             for request in server.filter_map(Result::ok) {
//                 let out_sender_clone = out_sender_c.clone();

//                 // Spawn a new thread for each connection.
//                 thread::spawn(move || {
//                     let client = request.use_protocol("rust-websocket").accept().unwrap();

//                     let ip = client.peer_addr().unwrap();
//                     info!("Accepted a client connection from '{}'.", ip);

//                     let (mut _receiver, sender) = client.split().unwrap();

//                     let mut guard = out_sender_clone.lock().unwrap();

//                     // Always keep alive just the newest connection
//                     *guard = Some(sender);
//                 });
//             }
//         });
//         DiagServer { sender: out_sender }
//     }
// }

// impl DiagServerTrait for DiagServer {
//     type Error = Error;

//     fn send_state(&mut self, data: &str) -> Result<(), Self::Error> {
//         let mut guard = self.sender.lock().expect("!");

//         if guard.is_some() {
//             let msg = Message::text(data);
//             guard
//                 .as_mut()
//                 .unwrap()
//                 .send_message(&msg)
//                 .expect("Failed to send!");
//         }
//         Ok(())
//     }
// }

// mod tests {
//     #[allow(unused_imports)]
//     use super::*;
//     // ---
//     #[allow(unused_imports)]
//     use crate::utils;
//     #[test]
//     fn test_diag_server_mss() {
//         let mut diag_server = DiagServer::new("127.0.0.1:9000".parse().unwrap());

//         // Test for 10s
//         for _ in 0..10 {
//             let msg = format!("{}", utils::unix_ts());
//             diag_server
//                 .send_state(&msg)
//                 .expect("Failed to send the message!");
//             thread::sleep(std::time::Duration::from_secs(1));
//         }
//     }
// }
