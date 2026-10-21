//! Transport-independent Omamori v1 protocol. Callers own transport, clocks,
//! persistence and UI. Drop a session on disconnect or timeout (60 seconds for
//! authentication, 120 seconds for pairing); never reuse it across connections.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod framing;
pub mod host;
pub mod watch;
pub mod wire;

/// Outgoing complete wire messages and local application events, in order.
/// Frame each message with [`framing`] before sending it over GATT.
#[derive(Debug)]
pub struct Output<E> {
    pub messages: Vec<Vec<u8>>,
    pub events: Vec<E>,
}

impl<E> Default for Output<E> {
    fn default() -> Self {
        Self {
            messages: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl<E> Output<E> {
    pub(crate) fn send(&mut self, message: wire::Message) -> Result<(), wire::Error> {
        self.messages.push(message.encode()?);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairFailure {
    Rejected,
    Commitment,
    InvalidKey,
    BadMac,
    Protocol,
}
