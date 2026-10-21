//! In-process harness; unavailable in production builds.
use super::{Event, Transport};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use tokio::sync::{mpsc, watch};

pub struct Fake {
    incoming: mpsc::Receiver<Event>,
    outgoing: mpsc::Sender<Vec<u8>>,
    advertising: watch::Sender<Option<[u8; 9]>>,
    powered: bool,
    pub fail_advertise: bool,
}
pub struct Peer {
    pub incoming: mpsc::Sender<Event>,
    pub outgoing: mpsc::Receiver<Vec<u8>>,
    pub advertising: watch::Receiver<Option<[u8; 9]>>,
}
pub fn pair() -> (Fake, Peer) {
    let (tx, rx) = mpsc::channel(256);
    let (out, incoming) = mpsc::channel(256);
    let (advertising, adv) = watch::channel(None);
    (
        Fake {
            incoming: rx,
            outgoing: out,
            advertising,
            powered: true,
            fail_advertise: false,
        },
        Peer {
            incoming: tx,
            outgoing: incoming,
            advertising: adv,
        },
    )
}
#[async_trait]
impl Transport for Fake {
    fn powered(&self) -> bool {
        self.powered
    }
    async fn advertise(&mut self, data: Option<[u8; 9]>) -> Result<()> {
        self.advertising.send_replace(None);
        if data.is_some() && self.fail_advertise {
            return Err(anyhow!("simulated BlueZ registration failure"));
        }
        self.advertising.send_replace(data);
        Ok(())
    }
    async fn recv(&mut self) -> Option<Event> {
        let event = self.incoming.recv().await?;
        if let Event::Powered(value) = event {
            self.powered = value;
        }
        Some(event)
    }
    async fn send(&mut self, chunk: Vec<u8>) -> Result<()> {
        self.outgoing
            .try_send(chunk)
            .map_err(|_| anyhow!("fake watch not reading"))
    }
    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }
}
