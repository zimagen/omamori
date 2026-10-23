//! BlueZ peripheral. RX uses write callbacks; TX uses device-scoped notify IO.
use super::{Event, Transport};
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bluer::{
    Adapter, AdapterEvent, AdapterProperty, Address,
    adv::{Advertisement, AdvertisementHandle},
    gatt::{
        CharacteristicWriter,
        local::{
            self, Application, ApplicationHandle, Characteristic, CharacteristicControl,
            CharacteristicControlEvent, CharacteristicNotify, CharacteristicNotifyMethod,
            CharacteristicWrite, CharacteristicWriteMethod, Service,
        },
    },
};
use futures::{FutureExt, Stream, StreamExt, future};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use uuid::Uuid;

pub const SERVICE: Uuid = Uuid::from_u128(0x4f6d616d6f7269000001000000000000);
const RX: Uuid = Uuid::from_u128(0x4f6d616d6f7269000001000000000002);
const TX: Uuid = Uuid::from_u128(0x4f6d616d6f7269000001000000000003);
// Keep the payload calculator and its test tied to the advertisement we register.
fn advertisement(data: [u8; 9], interval_ms: Option<[u16; 2]>) -> Advertisement {
    Advertisement {
        service_data: [(SERVICE, data.to_vec())].into_iter().collect(),
        discoverable: Some(true),
        min_interval: interval_ms.map(|v| Duration::from_millis(v[0].into())),
        max_interval: interval_ms.map(|v| Duration::from_millis(v[1].into())),
        ..Default::default()
    }
}

// Kept outside Live so adapter reinitialization retains the fallback decision.
struct Advertising {
    interval_ms: [u16; 2],
    unsupported: bool,
    logged: bool,
}

impl Advertising {
    fn new(interval_ms: [u16; 2]) -> Self {
        Self {
            interval_ms,
            unsupported: false,
            logged: false,
        }
    }

    async fn register<T, F, Fut>(&mut self, data: [u8; 9], mut register: F) -> Result<T>
    where
        F: FnMut(Advertisement) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let ad = advertisement(data, (!self.unsupported).then_some(self.interval_ms));
        let len = legacy_advertisement_len(&ad).context("unsupported advertising field")?;
        anyhow::ensure!(len <= 31, "legacy advertisement exceeds 31 bytes: {len}");
        let result = register(ad).await;
        let handle = match result {
            Err(error) if !self.unsupported => {
                // Remember even if the retry fails, to avoid repeated rejected attempts.
                self.unsupported = true;
                tracing::warn!(%error, "advertising intervals rejected; retrying with BlueZ default");
                register(advertisement(data, None)).await?
            }
            result => result?,
        };
        if !self.logged {
            if self.unsupported {
                tracing::info!("advertising interval: BlueZ default");
            } else {
                let [min, max] = self.interval_ms;
                tracing::info!("advertising interval: {min}-{max} ms");
            }
            self.logged = true;
        }
        Ok(handle)
    }
}

// Only flags and 128-bit service-data ADs are supported. Reject additional
// fields so a future builder change must also update the legacy size budget.
fn legacy_advertisement_len(ad: &Advertisement) -> Option<usize> {
    if !ad.service_uuids.is_empty()
        || !ad.manufacturer_data.is_empty()
        || !ad.solicit_uuids.is_empty()
        || !ad.advertising_data.is_empty()
        || !ad.system_includes.is_empty()
        || ad.local_name.is_some()
        || ad.appearance.is_some()
        || ad.tx_power.is_some()
    {
        return None;
    }
    let flags = if ad.discoverable == Some(true) { 3 } else { 0 };
    Some(
        flags
            + ad.service_data
                .values()
                .map(|data| 2 + 16 + data.len())
                .sum::<usize>(),
    )
}

#[derive(Default)]
struct Gate {
    address: Option<Address>,
    epoch: u64,
}
struct Write {
    address: Address,
    epoch: u64,
    bytes: Vec<u8>,
}
struct Live {
    _session: bluer::Session,
    adapter: Adapter,
    _app: ApplicationHandle,
    control: CharacteristicControl,
    adapter_events: Pin<Box<dyn Stream<Item = AdapterEvent> + Send>>,
    writer: Option<CharacteristicWriter>,
}
type Opening = Pin<Box<dyn Future<Output = Result<(Live, bool)>> + Send>>;

pub struct Bluez {
    adapter_name: String,
    live: Option<Live>,
    gate: Arc<Mutex<Gate>>,
    writes: mpsc::Receiver<Write>,
    write_tx: mpsc::Sender<Write>,
    advertisement: Option<AdvertisementHandle>,
    advertising: Advertising,
    powered: bool,
    retry: tokio::time::Interval,
    opening: Option<Opening>,
}
impl Bluez {
    pub async fn new(adapter_name: &str, adv_interval_ms: [u16; 2]) -> Self {
        let (write_tx, writes) = mpsc::channel(128);
        let mut this = Self {
            adapter_name: adapter_name.into(),
            live: None,
            gate: Arc::new(Mutex::new(Gate::default())),
            writes,
            write_tx,
            advertisement: None,
            advertising: Advertising::new(adv_interval_ms),
            powered: false,
            retry: tokio::time::interval(Duration::from_secs(2)),
            opening: None,
        };
        match Self::open(
            this.adapter_name.clone(),
            this.gate.clone(),
            this.write_tx.clone(),
        )
        .await
        {
            Ok((live, powered)) => {
                this.live = Some(live);
                this.powered = powered;
            }
            Err(e) => tracing::warn!(error = %e, "Bluetooth unavailable; will retry"),
        }
        this.retry.reset();
        this
    }
    async fn open(
        adapter_name: String,
        gate: Arc<Mutex<Gate>>,
        tx: mpsc::Sender<Write>,
    ) -> Result<(Live, bool)> {
        let session = bluer::Session::new().await?;
        let adapter = if adapter_name.is_empty() {
            session.default_adapter().await?
        } else {
            session.adapter(&adapter_name)?
        };
        let powered = adapter.is_powered().await?;
        let adapter_events = Box::pin(adapter.events().await?);
        let (control, handle) = local::characteristic_control();
        let expected_adapter = adapter.name().to_owned();
        let app = Application {
            services: vec![Service {
                uuid: SERVICE,
                primary: true,
                characteristics: vec![
                    Characteristic {
                        uuid: RX,
                        write: Some(CharacteristicWrite {
                            write: true,
                            write_without_response: true,
                            method: CharacteristicWriteMethod::Fun(Box::new(
                                move |bytes, request| {
                                    let gate = gate.clone();
                                    let tx = tx.clone();
                                    let expected_adapter = expected_adapter.clone();
                                    async move {
                                        if request.offset != 0
                                            || request.prepare_authorize
                                            || request.adapter_name != expected_adapter
                                        {
                                            return Err(local::ReqError::NotSupported);
                                        }
                                        let gate = gate.lock().expect("gate mutex");
                                        if gate.address != Some(request.device_address) {
                                            return Err(local::ReqError::NotPermitted);
                                        }
                                        tx.try_send(Write {
                                            address: request.device_address,
                                            epoch: gate.epoch,
                                            bytes,
                                        })
                                        .map_err(|_| local::ReqError::Failed)
                                    }
                                    .boxed()
                                },
                            )),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: TX,
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            method: CharacteristicNotifyMethod::Io,
                            ..Default::default()
                        }),
                        control_handle: handle,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let app = adapter.serve_gatt_application(app).await?;
        Ok((
            Live {
                _session: session,
                adapter,
                _app: app,
                control,
                adapter_events,
                writer: None,
            },
            powered,
        ))
    }
}
#[async_trait]
impl Transport for Bluez {
    fn powered(&self) -> bool {
        self.powered
    }
    async fn advertise(&mut self, data: Option<[u8; 9]>) -> Result<()> {
        self.advertisement = None;
        if let Some(data) = data {
            let live = self.live.as_mut().context("no adapter")?;
            if !live.adapter.is_powered().await? {
                self.powered = false;
                bail!("adapter powered off");
            }
            self.advertisement = Some(
                self.advertising
                    .register(data, |ad| async { Ok(live.adapter.advertise(ad).await?) })
                    .await?,
            );
        }
        Ok(())
    }
    async fn recv(&mut self) -> Option<Event> {
        loop {
            let Some(live) = self.live.as_mut() else {
                if self.opening.is_none() {
                    self.retry.tick().await;
                    self.opening = Some(Box::pin(Self::open(
                        self.adapter_name.clone(),
                        self.gate.clone(),
                        self.write_tx.clone(),
                    )));
                }
                // Keep initialization across cancelled recv calls (IPC and the idle timer
                // regularly interrupt this future). Interval::tick is cancellation-safe too.
                let result = self.opening.as_mut().expect("opening initialized").await;
                self.opening = None;
                self.retry.reset();
                if let Ok((live, powered)) = result {
                    self.live = Some(live);
                    self.powered = powered;
                    return Some(Event::Powered(powered));
                }
                continue;
            };
            tokio::select! {
                control = live.control.next() => {
                    if let Some(CharacteristicControlEvent::Notify(writer)) = control {
                        let address = writer.device_address();
                        if live.writer.is_some() || !self.powered || self.advertisement.is_none() {
                            drop(writer);
                            // Reject a competing central without touching the active one.
                            if self.gate.lock().expect("gate mutex").address != Some(address)
                                && let Ok(device) = live.adapter.device(address) {
                                let _ = tokio::time::timeout(Duration::from_secs(5), device.disconnect()).await;
                            }
                            continue;
                        }
                        live.writer = Some(writer);
                        let mut gate = self.gate.lock().expect("gate mutex");
                        gate.epoch = gate.epoch.wrapping_add(1);
                        gate.address = Some(address);
                        tracing::info!(%address, "BLE central connected");
                        return Some(Event::Connected);
                    }
                    if control.is_none() {
                        self.powered = false; self.live = None;
                        return Some(Event::Powered(false));
                    }
                }
                write = self.writes.recv() => {
                    let write = write?;
                    let gate = self.gate.lock().expect("gate mutex");
                    if gate.address == Some(write.address) && gate.epoch == write.epoch {
                        return Some(Event::Bytes(write.bytes));
                    }
                }
                event = live.adapter_events.next() => {
                    match event {
                        Some(AdapterEvent::PropertyChanged(AdapterProperty::Powered(value))) => {
                            self.powered = value;
                            return Some(Event::Powered(value));
                        }
                        None => { self.powered = false; self.live = None; return Some(Event::Powered(false)); }
                        _ => {}
                    }
                }
                _ = async {
                    match live.writer.as_ref() {
                        Some(writer) => { let _ = writer.closed().await; }
                        None => future::pending().await,
                    }
                } => {
                    // Return before any await: recv is cancellation-safe in the engine's select.
                    live.writer = None;
                    if let Some(address) = self.gate.lock().expect("gate mutex").address.take() {
                        tracing::info!(%address, "BLE central disconnected");
                    }
                    return Some(Event::Disconnected);
                }
            }
        }
    }
    async fn send(&mut self, chunk: Vec<u8>) -> Result<()> {
        let writer = self
            .live
            .as_ref()
            .and_then(|l| l.writer.as_ref())
            .context("no notifying central")?;
        tokio::time::timeout(Duration::from_secs(5), writer.send(&chunk)).await??;
        Ok(())
    }
    async fn disconnect(&mut self) -> Result<()> {
        let address = {
            let mut gate = self.gate.lock().expect("gate mutex");
            gate.epoch = gate.epoch.wrapping_add(1);
            gate.address.take()
        };
        if let Some(address) = address {
            tracing::info!(%address, "BLE central disconnected");
        }
        if let Some(live) = &mut self.live {
            live.writer = None;
            if let Some(address) = address
                && let Ok(device) = live.adapter.device(address)
            {
                tokio::time::timeout(Duration::from_secs(5), device.disconnect()).await??;
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "test-harness"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    async fn slow_adapter_initialization_survives_repeated_receive_cancellation() {
        // A delayed failing initializer models D-Bus setup without touching a bus.
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let (write_tx, writes) = mpsc::channel(1);
        let mut retry = tokio::time::interval(Duration::from_secs(2));
        retry.reset_after(Duration::from_secs(3600));
        let mut transport = Bluez {
            adapter_name: String::new(),
            live: None,
            gate: Arc::new(Mutex::new(Gate::default())),
            writes,
            write_tx,
            advertisement: None,
            advertising: Advertising::new([20, 30]),
            powered: false,
            retry,
            opening: Some(Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                count.fetch_add(1, Ordering::SeqCst);
                Err(anyhow::anyhow!("simulated adapter absence"))
            })),
        };
        for _ in 0..5 {
            assert!(
                tokio::time::timeout(Duration::from_millis(50), transport.recv())
                    .await
                    .is_err()
            );
        }
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        assert!(transport.opening.is_none());
    }
}

#[cfg(test)]
mod advertisement_tests {
    use super::*;

    #[test]
    fn advertisement_fits_legacy_pdu() {
        for mode in [0, 1] {
            let mut data = [0; 9];
            data[8] = mode;
            let ad = advertisement(data, Some([20, 30]));
            assert_eq!(ad.discoverable, Some(true));
            assert_eq!(ad.min_interval, Some(Duration::from_millis(20)));
            assert_eq!(ad.max_interval, Some(Duration::from_millis(30)));
            assert_eq!(ad.service_data.get(&SERVICE), Some(&data.to_vec()));
            let len = legacy_advertisement_len(&ad).expect("unexpected advertising field");
            assert_eq!(len, 30);
            assert!(len <= 31, "legacy advertisement uses {len} bytes");
        }
    }

    #[tokio::test]
    async fn accepted_intervals_are_reused() {
        let mut advertising = Advertising::new([40, 60]);
        for _ in 0..2 {
            let mut attempts = 0;
            advertising
                .register([0; 9], |ad| {
                    attempts += 1;
                    assert_eq!(ad.min_interval, Some(Duration::from_millis(40)));
                    assert_eq!(ad.max_interval, Some(Duration::from_millis(60)));
                    future::ready(Ok(()))
                })
                .await
                .unwrap();
            assert_eq!(attempts, 1);
        }
        assert!(!advertising.unsupported);
    }

    #[tokio::test]
    async fn rejected_intervals_retry_once_and_are_never_attempted_again() {
        // Also retain the decision when registration without intervals fails.
        for fallback_succeeds in [true, false] {
            let mut advertising = Advertising::new([20, 30]);
            let mut attempts = Vec::new();
            let result = advertising
                .register([7; 9], |ad| {
                    assert_eq!(ad.service_data.get(&SERVICE), Some(&vec![7; 9]));
                    attempts.push((ad.min_interval, ad.max_interval));
                    future::ready(if ad.min_interval.is_some() || !fallback_succeeds {
                        Err(anyhow::anyhow!("registration rejected"))
                    } else {
                        Ok(())
                    })
                })
                .await;
            assert_eq!(result.is_ok(), fallback_succeeds);
            assert_eq!(
                attempts,
                vec![
                    (
                        Some(Duration::from_millis(20)),
                        Some(Duration::from_millis(30))
                    ),
                    (None, None),
                ]
            );
            attempts.clear();
            assert!(
                advertising
                    .register([0; 9], |ad| {
                        attempts.push((ad.min_interval, ad.max_interval));
                        future::ready(Err::<(), _>(anyhow::anyhow!("still unavailable")))
                    })
                    .await
                    .is_err()
            );
            assert_eq!(attempts, vec![(None, None)]);
        }
    }
}
