//! `epix-dht-net` — binds `epix-dht` to the wire.
//!
//! The DHT logic in `epix-dht` talks to an abstract `RpcClient`; here that
//! becomes real: [`WireRpcClient`] dials peers on demand and sends DHT RPCs over
//! their `Connection`, and [`DhtService`] answers inbound RPCs. Because it rides
//! `epix-transport`, the same DHT works over TCP, Tor, and Reticulum mesh.

mod client;
mod service;
pub mod wire;

pub use client::WireRpcClient;
pub use service::DhtService;
