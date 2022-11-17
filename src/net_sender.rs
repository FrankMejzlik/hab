//!
//! Module for broadcasting the data over the network to `NetReceiver`s.
//!

// ---
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
// ---

#[derive(Debug)]
pub enum NetSenderError {}

#[derive(Debug)]
pub struct NetSenderParams {}

///
/// Sends the data blocks over the network.
///
/// # See
/// * `struct NetReceiver`
///
pub struct NetSender {}

impl NetSender {
    pub fn new(_params: NetSenderParams) -> Self {
        NetSender {}
    }

    pub fn broadcast(&self, data: &[u8]) -> Result<(), NetSenderError> {
        trace!("\t...broadcasting {} bytes...", data.len());
        Ok(())
    }
}
