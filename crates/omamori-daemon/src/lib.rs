//! omamorid I/O and lifecycle. Cryptographic sessions belong to omamori-proto.
pub mod config;
mod engine;
pub mod ipc;
pub mod state;
pub mod transport;

use anyhow::Result;
use config::Config;
use ipc::Policy;
use state::Store;
use std::path::Path;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use transport::Transport;

/// Run until shutdown. Bind and validate state before returning a ready handle.
pub struct Daemon {
    pub shutdown: oneshot::Sender<()>,
    pub task: tokio::task::JoinHandle<Result<()>>,
}
pub fn start<T: Transport + 'static>(
    config: Config,
    state_dir: &Path,
    socket: &Path,
    transport: T,
    policy: Policy,
) -> Result<Daemon> {
    let (store, state) = Store::open(state_dir)?;
    let listener = ipc::bind(socket)?;
    let socket = socket.to_owned();
    let (commands, receiver) = mpsc::channel(128);
    let engine = engine::Engine::new(config, store, state, transport, policy);
    let (shutdown, mut stop) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut engine = tokio::spawn(engine.run(receiver));
        let mut connections = JoinSet::new();
        let mut next = 0u64;
        let result = loop {
            tokio::select! {
                _ = &mut stop => break Ok(()),
                result = &mut engine => break result.unwrap_or_else(|e| Err(e.into())),
                accept = listener.accept() => {
                    let (stream, _) = match accept {Ok(value) => value, Err(e) => break Err(e.into())};
                    next = next.checked_add(1).expect("connection counter exhausted");
                    connections.spawn(ipc::connection(stream, next, commands.clone()));
                }
                Some(_) = connections.join_next() => {}
            }
        };
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        drop(commands);
        if !engine.is_finished() {
            match tokio::time::timeout(std::time::Duration::from_secs(10), &mut engine).await {
                Ok(_) => {}
                Err(_) => engine.abort(),
            }
        }
        drop(listener);
        let _ = std::fs::remove_file(socket);
        result
    });
    Ok(Daemon { shutdown, task })
}
