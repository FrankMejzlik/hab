//!
//! Module for receiving the data broadcasted by the `NetSender`.
//!

#[derive(Debug)]
pub enum NetReceiverError {}

#[derive(Debug)]
pub struct NetReceiverParams {}

///
/// Receives the data blocks over the network from the `NetSender`.
///
/// # See
/// * `struct NetSender`
///
#[allow(dead_code)]
pub struct NetReceiver {}

impl NetReceiver {
    #[allow(dead_code)]
    pub fn new(_params: NetReceiverParams) -> Self {
        NetReceiver {}
    }
}
