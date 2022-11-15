//!
//! Module for receiving the data broadcasted by the `Broadcaster`.
//!

#[derive(Debug)]
pub enum ReceiverError {}

#[derive(Debug)]
pub struct ReceiverParams {}

///
/// Receives the data blocks over the network from the `Broadcaster`.
///
/// # See
/// * `struct Broadcaster`
///
pub struct Receiver {}

impl Receiver {
    pub fn new(params: ReceiverParams) -> Self {
        Receiver {}
    }
}
