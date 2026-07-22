//! The embedded I2P router (emissary), run in-process - the no-sidecar default.
//!
//! Mirrors what `emissary-cli` does to stand up a working router: open storage,
//! reseed if the netdb is thin, build a [`Config`] with a SAMv3 server on an
//! OS-assigned port, construct the [`Router`] (a `Future`), and drive it on the
//! node's Tokio runtime. We hand the discovered SAM port back for the
//! [`yosemite`] client, and poll the router's event stream to keep the shared
//! [`crate::I2pStatus`] (peers, tunnels) fresh for the UI.
//!
//! Without the `embedded` feature this compiles to a stub whose `start` errors,
//! so a build can ship External-only.

#[cfg(feature = "embedded")]
pub use imp::EmbeddedRouter;

#[cfg(not(feature = "embedded"))]
pub use stub::EmbeddedRouter;

#[cfg(not(feature = "embedded"))]
mod stub {
    use crate::SharedStatus;
    use epix_core::{Error, Result};

    pub struct EmbeddedRouter;

    impl EmbeddedRouter {
        pub async fn start(_data_dir: &std::path::Path, _status: SharedStatus) -> Result<Self> {
            Err(Error::Protocol(
                "embedded I2P router not built in; use External mode with a running router".into(),
            ))
        }
        pub fn sam_port(&self) -> u16 {
            0
        }
    }
}

#[cfg(feature = "embedded")]
mod imp {
    use crate::SharedStatus;
    use emissary_core::{events::Event, router::Router, Config, Ntcp2Config, SamConfig, Ssu2Config};
    use emissary_util::{reseeder::Reseeder, runtime::tokio::Runtime, storage::Storage};
    use epix_core::{Error, Result};
    use std::sync::Arc;

    /// Reseed once the known-router set drops below this (emissary's default).
    const RESEED_THRESHOLD: usize = 25;

    /// A running embedded emissary router. Dropping it stops the router task.
    pub struct EmbeddedRouter {
        sam_port: u16,
        _router_task: tokio::task::JoinHandle<()>,
        _stats_task: tokio::task::JoinHandle<()>,
    }

    impl EmbeddedRouter {
        pub async fn start(data_dir: &std::path::Path, status: SharedStatus) -> Result<Self> {
            let _ = std::fs::create_dir_all(data_dir);
            let base = data_dir.to_path_buf();

            let storage = Storage::new::<Runtime>(Some(base.clone()))
                .await
                .map_err(|e| Error::Protocol(format!("i2p storage: {e}")))?;

            // Reuse everything the last run persisted: our transport keys and
            // router identity, plus the cached netdb and peer profiles. This is
            // what emissary-cli's `Config::parse` does. Two payoffs:
            //  - a **stable** router identity across restarts (peers remember us,
            //    profiles stay useful), and
            //  - startup skips the HTTPS reseed whenever the cached netdb is warm
            //    (below), so only a genuinely cold node pays the reseed cost.
            // `Storage::new` just created any missing keys, so these are always
            // present, even on a first run (where `routers` is empty and we do
            // reseed). SSU2/SAM/NTCP2 still bind OS-assigned ports (port 0) so
            // several nodes on one host don't collide - each has its own data dir
            // and thus its own persisted keys.
            let bundle = storage.load().await;

            let mut config = Config {
                net_id: Some(2), // I2P main network.
                ntcp2: Some(Ntcp2Config {
                    ipv4: true,
                    ipv4_host: None,
                    ipv6: false,
                    ipv6_host: None,
                    iv: bundle.ntcp2_iv,
                    key: bundle.ntcp2_key,
                    port: 0,
                    publish_ipv4: true,
                    publish_ipv6: false,
                    max_connections: None,
                    ml_kem: None,
                    disable_pq: false,
                }),
                ssu2: Some(Ssu2Config {
                    disable_pq: false,
                    intro_key: bundle.ssu2_intro_key,
                    ipv4: true,
                    ipv4_host: None,
                    ipv4_mtu: None,
                    ipv6: false,
                    ipv6_host: None,
                    ipv6_mtu: None,
                    port: 0,
                    publish_ipv4: true,
                    publish_ipv6: false,
                    max_connections: None,
                    static_key: bundle.ssu2_static_key,
                    ml_kem: None,
                }),
                samv3_config: Some(SamConfig {
                    tcp_port: 0,
                    udp_port: 0,
                    host: "127.0.0.1".to_string(),
                }),
                routers: bundle.routers,
                profiles: bundle.profiles,
                // Deliberately NOT reusing the persisted local `router_info`: we
                // bind ephemeral ports (port 0) each start, so the stored info
                // advertises last run's addresses. emissary rebuilds our local
                // info from the persistent keys (same identity, same router
                // hash) plus the freshly bound ports.
                router_info: None,
                signing_key: Some(bundle.signing_key),
                static_key: Some(bundle.static_key),
                ..Default::default()
            };

            // Reseed over HTTPS if the netdb is thin, so the router can build
            // tunnels on a fresh install (emissary-cli does the same).
            if config.routers.len() < RESEED_THRESHOLD {
                match Reseeder::reseed::<Runtime>(None, true).await {
                    Ok(routers) => {
                        for info in routers {
                            let _ = storage
                                .store_router_info(info.name, info.router_info.clone())
                                .await;
                            config.routers.push(info.router_info);
                        }
                        status.write().await.reseed_routers = config.routers.len();
                        tracing::info!(target: "epix::i2p", "i2p reseeded: {} routers", config.routers.len());
                    }
                    Err(e) if config.routers.is_empty() => {
                        return Err(Error::Protocol(format!("i2p reseed failed: {e}")));
                    }
                    Err(e) => {
                        tracing::warn!(target: "epix::i2p", "i2p reseed failed, using cached netdb: {e}");
                    }
                }
            } else {
                status.write().await.reseed_routers = config.routers.len();
            }

            let (router, events, _local_info) =
                Router::<Runtime>::new(config, None, Some(Arc::new(storage)))
                    .await
                    .map_err(|e| Error::Protocol(format!("i2p router: {e}")))?;

            // The SAM server binds when the router starts; we asked for port 0,
            // so its actual address is known now.
            let sam_port = router
                .protocol_address_info()
                .sam_tcp
                .map(|a| a.port())
                .ok_or_else(|| Error::Protocol("i2p router did not expose a SAM port".into()))?;

            // Drive the router future for the process lifetime.
            let router_task = tokio::spawn(async move {
                router.await;
            });
            // Poll router status into the shared UI status.
            let stats_task = tokio::spawn(poll_stats(events, status));

            tracing::info!(target: "epix::i2p", "embedded i2p router up, SAM on 127.0.0.1:{sam_port}");
            Ok(Self { sam_port, _router_task: router_task, _stats_task: stats_task })
        }

        pub fn sam_port(&self) -> u16 {
            self.sam_port
        }
    }

    /// Poll the router's event stream and fold its live counts (connected
    /// routers = I2P peers, tunnels built/failed) into the shared status.
    async fn poll_stats(mut events: emissary_core::events::EventSubscriber, status: SharedStatus) {
        loop {
            while let Some(event) = events.router_status() {
                if let Event::RouterStatus { transport, tunnel, .. } = event {
                    let mut s = status.write().await;
                    s.connected_routers = transport.num_connected_routers;
                    s.tunnels_built = tunnel.num_tunnels_built;
                    s.tunnel_failures = tunnel.num_tunnel_build_failures;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}
