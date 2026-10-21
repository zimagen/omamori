#![allow(dead_code)]
use omamori_proto::{
    Output,
    crypto::Key,
    host, watch,
    wire::{Entry, Kind},
};
use rand_core::{CryptoRng, RngCore};

// Deliberately deterministic and confined to tests. Never use for real secrets.
pub struct Rng(pub u64);
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for part in bytes.chunks_mut(8) {
            part.copy_from_slice(&self.next_u64().to_le_bytes()[..part.len()]);
        }
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl CryptoRng for Rng {}

pub fn entry(id: u8, kind: Kind, needs_confirm: bool, age_s: u16) -> Entry {
    Entry {
        req_id: [id; 8],
        kind,
        needs_confirm,
        age_s,
        title: "alice".into(),
        detail: if kind == Kind::Sudo {
            "sudo pacman -Syu on /dev/pts/1".into()
        } else {
            "Unlock".into()
        },
    }
}

pub fn auth(entries: Vec<Entry>) -> (host::Session, watch::Session, Output<watch::Event>, Rng) {
    let mut rng = Rng(42);
    let mut host = host::Session::authenticated([1; 16], "PC", Key::new([2; 32]));
    host.set_pending(entries).unwrap();
    let (mut watch, hello) = watch::Session::authenticated([1; 16], Key::new([2; 32]), &mut rng);
    let pending = host.receive(&hello.messages[0], &mut rng).unwrap();
    let out = watch.receive(&pending.messages[0]).unwrap();
    (host, watch, out, rng)
}
