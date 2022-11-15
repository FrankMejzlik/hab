//!
//! Module for broadcasting the data over the network to `Receiver`s.
//!

// ---
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
// ---

#[derive(Debug)]
pub enum BroadcasterError {}

#[derive(Debug)]
pub struct BroadcasterParams {}

///
/// Sends the data blocks over the network.
///
/// # See
/// * `struct Receiver`
///
pub struct Broadcaster {}

impl Broadcaster {
    pub fn new(_params: BroadcasterParams) -> Self {
        Broadcaster {}
    }

    pub fn broadcast(&self, data: &[u8]) -> Result<(), BroadcasterError> {
        trace!("\t...broadcasting {} bytes...", data.len());
        Ok(())
    }
}
