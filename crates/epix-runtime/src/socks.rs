//! One owned endpoint across bootstrap, disabled mode and Tor recovery.

use std::{io, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Notify};
use tokio::task::{JoinHandle, JoinSet};

const MAX_CONNECTIONS: usize = 128;

#[async_trait::async_trait]
trait SocksRoute: Send + Sync {
    async fn serve(&self, stream: TcpStream) -> io::Result<()>;
}

#[cfg(feature = "tor")]
#[async_trait::async_trait]
impl SocksRoute for epix_tor::Tor {
    async fn serve(&self, stream: TcpStream) -> io::Result<()> {
        self.serve_socks_connection(stream).await
    }
}

type Route = Option<Arc<dyn SocksRoute>>;

#[derive(Clone)]
pub(crate) struct SocksControl {
    port: u16,
    route: watch::Sender<Route>,
    stopped: watch::Sender<bool>,
}

impl SocksControl {
    pub(crate) fn bind(start: u16, shutdown: Arc<Notify>) -> io::Result<(Self, JoinHandle<()>)> {
        let listener = epix_core::ports::bind_loopback_listener(start)?;
        let port = listener.local_addr()?.port();
        let listener = TcpListener::from_std(listener)?;
        let (route, receiver) = watch::channel(None);
        let (stopped, stop_receiver) = watch::channel(false);
        let task = tokio::spawn(serve(listener, receiver, stop_receiver, shutdown));
        Ok((
            Self {
                port,
                route,
                stopped,
            },
            task,
        ))
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    #[cfg(feature = "tor")]
    pub(crate) fn enable(&self, tor: epix_tor::Tor) {
        self.route.send_replace(Some(Arc::new(tor)));
    }

    pub(crate) fn disable(&self) {
        self.route.send_replace(None);
    }

    pub(crate) fn stop(&self) {
        self.disable();
        self.stopped.send_replace(true);
    }
}

async fn serve(
    listener: TcpListener,
    mut route: watch::Receiver<Route>,
    mut stopped: watch::Receiver<bool>,
    shutdown: Arc<Notify>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stopped.changed() => break,
            _ = shutdown.notified() => break,
            changed = route.changed() => {
                if changed.is_err() { break; }
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    // A transient accept error must not surrender the published
                    // port to another process. Retain it and avoid a hot loop.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                };
                // No forwarding and no task allocation while Tor is unavailable.
                // Capacity exhaustion also fails closed for just this connection.
                let mut generation = route.clone();
                let handler = generation.borrow_and_update().clone();
                if let Some(handler) = handler.filter(|_| connections.len() < MAX_CONNECTIONS) {
                    connections.spawn(async move {
                        tokio::select! {
                            biased;
                            _ = generation.changed() => {}
                            _ = handler.serve(stream) => {}
                        }
                    });
                }
            }
        }
    }
    // Dropping JoinSet aborts connections, including a stalled SOCKS handshake.
}

#[cfg(test)]
#[path = "socks/tests.rs"]
mod tests;
