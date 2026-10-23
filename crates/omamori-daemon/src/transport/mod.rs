//! Transport carries v1 GATT chunks; all protocol logic stays in omamori-proto.
pub mod bluez;
#[cfg(feature = "test-harness")]
pub mod fake;
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug)]
pub enum Event {
    Connected,
    Disconnected,
    Bytes(Vec<u8>),
    Powered(bool),
}
#[async_trait]
pub trait Transport: Send {
    fn powered(&self) -> bool;
    async fn advertise(&mut self, data: Option<[u8; 9]>, interval_ms: [u16; 2]) -> Result<()>;
    async fn recv(&mut self) -> Option<Event>;
    async fn send(&mut self, chunk: Vec<u8>) -> Result<()>;
    async fn disconnect(&mut self) -> Result<()>;
}
