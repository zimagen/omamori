use anyhow::Result;
use clap::{Parser, ValueEnum};
use omamori_daemon::{config::Config, ipc::Policy, transport::bluez::Bluez};
use std::path::PathBuf;
#[derive(Clone, Copy, ValueEnum)]
enum Transport {
    Bluez,
    #[cfg(feature = "test-harness")]
    Fake,
}
#[derive(Parser)]
#[command(name = "omamorid")]
struct Args {
    #[arg(long, default_value = "/etc/omamori/config.toml")]
    config: PathBuf,
    #[arg(long, default_value = "/var/lib/omamori")]
    state_dir: PathBuf,
    #[arg(long, default_value = "/run/omamori/omamori.sock")]
    socket: PathBuf,
    #[arg(long, value_enum, default_value = "bluez")]
    transport: Transport,
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    #[cfg(feature = "test-harness")]
    let mut fake_peer = None;
    let mut daemon = match args.transport {
        Transport::Bluez => {
            let transport = Bluez::new(&config.adapter, config.adv_interval_ms).await;
            omamori_daemon::start(
                config,
                &args.state_dir,
                &args.socket,
                transport,
                Policy::default(),
            )?
        }
        #[cfg(feature = "test-harness")]
        Transport::Fake => {
            let (transport, peer) = omamori_daemon::transport::fake::pair();
            fake_peer = Some(peer);
            omamori_daemon::start(
                config,
                &args.state_dir,
                &args.socket,
                transport,
                Policy::default(),
            )?
        }
    };
    tracing::info!("omamorid started");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = &mut daemon.task => return result?,
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {}
    }
    let _ = daemon.shutdown.send(());
    daemon.task.await??;
    #[cfg(feature = "test-harness")]
    drop(fake_peer);
    Ok(())
}
