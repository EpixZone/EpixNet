//! Bounded native socket bridge. Android owns sockets; Rust owns HDLC and RNS.
mod framing;

use std::io;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use reticulum::iface::{InterfaceChannel, InterfaceManager, RxMessage};
use tokio::sync::{mpsc, watch, Mutex, Semaphore};

pub const MAX_RADIO_LINKS: usize = 8;
pub const MAX_RADIO_CHUNK: usize = 4096;
const QUEUE_DEPTH: usize = 8;
const MAX_WAIT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct HubState {
    closed: bool,
    links: Vec<Weak<RadioStream>>,
}

/// One runtime generation. Closing it permanently invalidates all its handles.
pub struct RadioHub {
    manager: Arc<Mutex<InterfaceManager>>,
    state: StdMutex<HubState>,
    slots: Arc<Semaphore>,
}

impl RadioHub {
    pub(crate) fn new(manager: Arc<Mutex<InterfaceManager>>) -> Self {
        Self {
            manager,
            state: StdMutex::new(HubState::default()),
            slots: Arc::new(Semaphore::new(MAX_RADIO_LINKS)),
        }
    }

    pub async fn open(&self) -> io::Result<Arc<RadioStream>> {
        let permit = self.slots.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "native radio link limit reached")
        })?;
        let mut manager = tokio::time::timeout(MAX_WAIT, self.manager.lock())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "native radio manager busy"))?;
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(closed_error());
        }
        state
            .links
            .retain(|link| link.upgrade().is_some_and(|link| !link.is_closed()));
        if state.links.len() >= MAX_RADIO_LINKS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native radio link limit reached",
            ));
        }
        manager.cleanup();
        let channel = manager.new_channel(QUEUE_DEPTH);
        let stop = channel.stop.clone();
        let (incoming, incoming_rx) = mpsc::channel(QUEUE_DEPTH);
        let (outgoing, outgoing_rx) = mpsc::channel(QUEUE_DEPTH);
        let (closed, _) = watch::channel(false);
        let stream = Arc::new(RadioStream {
            incoming,
            reader: Mutex::new(Reader {
                outgoing: outgoing_rx,
                pending: Vec::new(),
                offset: 0,
            }),
            closed: closed.clone(),
            cancel_interface: Box::new(move || stop.cancel()),
        });
        state.links.push(Arc::downgrade(&stream));
        tokio::spawn(async move {
            run_interface(channel, incoming_rx, outgoing, closed).await;
            drop(permit);
        });
        Ok(stream)
    }

    pub fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        for link in state.links.drain(..).filter_map(|link| link.upgrade()) {
            link.close();
        }
    }
}

impl Drop for RadioHub {
    fn drop(&mut self) {
        self.close();
    }
}

struct Reader {
    outgoing: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    offset: usize,
}

/// An opaque duplex socket handle. No radio address or identity crosses this API.
pub struct RadioStream {
    incoming: mpsc::Sender<Vec<u8>>,
    reader: Mutex<Reader>,
    closed: watch::Sender<bool>,
    cancel_interface: Box<dyn Fn() + Send + Sync>,
}

pub struct RadioRead {
    pub data: Vec<u8>,
    pub closed: bool,
}

impl RadioStream {
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    pub fn close(&self) {
        (self.cancel_interface)();
        self.closed.send_replace(true);
    }

    pub async fn write(&self, bytes: Vec<u8>, timeout: Duration) -> io::Result<()> {
        if bytes.len() > MAX_RADIO_CHUNK {
            return Err(invalid_size());
        }
        if self.is_closed() {
            return Err(closed_error());
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let mut closed = self.closed.subscribe();
        tokio::select! {
            biased;
            _ = closed.wait_for(|value| *value) => Err(closed_error()),
            result = tokio::time::timeout(timeout.min(MAX_WAIT), self.incoming.reserve()) => {
                let permit = result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "native radio input queue full"))?
                    .map_err(|_| closed_error())?;
                permit.send(bytes);
                Ok(())
            }
        }
    }

    pub async fn read(&self, max_bytes: usize, timeout: Duration) -> io::Result<RadioRead> {
        if max_bytes == 0 || max_bytes > MAX_RADIO_CHUNK {
            return Err(invalid_size());
        }
        let mut closed = self.closed.subscribe();
        tokio::select! {
            biased;
            _ = closed.wait_for(|value| *value) => Ok(RadioRead { data: Vec::new(), closed: true }),
            result = tokio::time::timeout(timeout.min(MAX_WAIT), self.read_chunk(max_bytes)) => {
                match result {
                    Ok(data) => Ok(RadioRead { closed: data.is_none(), data: data.unwrap_or_default() }),
                    Err(_) => Ok(RadioRead { data: Vec::new(), closed: false }),
                }
            }
        }
    }

    async fn read_chunk(&self, max_bytes: usize) -> Option<Vec<u8>> {
        let mut reader = self.reader.lock().await;
        if reader.offset == reader.pending.len() {
            reader.pending = reader.outgoing.recv().await?;
            reader.offset = 0;
        }
        let end = (reader.offset + max_bytes).min(reader.pending.len());
        let bytes = reader.pending[reader.offset..end].to_vec();
        reader.offset = end;
        Some(bytes)
    }
}

impl Drop for RadioStream {
    fn drop(&mut self) {
        self.close();
    }
}

fn invalid_size() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "native radio chunk must fit the advertised bound",
    )
}

fn closed_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "native radio generation or stream is closed",
    )
}

async fn run_interface(
    mut channel: InterfaceChannel,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    closed: watch::Sender<bool>,
) {
    let mut cancelled = closed.subscribe();
    let receive = async {
        let mut decoder = framing::Decoder::default();
        while let Some(bytes) = incoming.recv().await {
            for byte in bytes {
                if let Some(packet) = decoder.push(byte)? {
                    channel
                        .rx_channel
                        .send(RxMessage {
                            address: channel.address,
                            packet,
                        })
                        .await
                        .map_err(|_| closed_error())?;
                }
            }
        }
        Ok::<(), io::Error>(())
    };
    let transmit = async {
        while let Some(message) = channel.tx_channel.recv().await {
            let bytes = framing::encode(&message.packet)?;
            // A stalled platform socket closes only this interface. Never await
            // its queue while the shared RNS manager is broadcasting to others.
            outgoing.try_send(bytes).map_err(|_| closed_error())?;
        }
        Ok::<(), io::Error>(())
    };
    tokio::select! {
        biased;
        _ = cancelled.wait_for(|value| *value) => {},
        _ = channel.stop.cancelled() => {},
        _ = receive => {},
        _ = transmit => {},
    }
    channel.stop.cancel();
    closed.send_replace(true);
}

#[cfg(test)]
mod tests;
