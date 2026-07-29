//! `epix-dht-net` - binds `epix-dht` to the wire.
//!
//! The DHT logic in `epix-dht` talks to an abstract `RpcClient`; here that
//! becomes real: [`WireRpcClient`] ships DHT RPCs to peers through an injected
//! [`KadSender`] (the runtime carries them as EDX `Kad` payloads), and
//! [`DhtService`] answers inbound RPCs. Nothing here binds a transport, so the
//! same DHT works over TCP, Tor, I2P, and Reticulum mesh.

mod client;
pub mod pc;
mod service;

pub use client::{KadSender, WireRpcClient};
pub use service::DhtService;
