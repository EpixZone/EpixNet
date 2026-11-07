//! IPv4 subnet broadcasts, independent of the default Internet route.

use if_addrs::{IfAddr, Interface};
use std::net::Ipv4Addr;

#[cfg(test)]
#[path = "local_broadcast_tests.rs"]
mod tests;

pub(super) fn destinations() -> std::io::Result<Vec<Ipv4Addr>> {
    if_addrs::get_if_addrs().map(select_destinations)
}

fn select_destinations(interfaces: Vec<Interface>) -> Vec<Ipv4Addr> {
    let mut targets: Vec<_> = interfaces.iter().filter_map(broadcast_address).collect();
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn broadcast_address(interface: &Interface) -> Option<Ipv4Addr> {
    if !interface.is_oper_up() || interface.is_loopback() || interface.is_p2p() {
        return None;
    }
    // The existing LAN wire protocol uses IPv4 UDP. IPv6 has no broadcast.
    let IfAddr::V4(address) = &interface.addr else {
        return None;
    };
    if address.ip.is_unspecified()
        || address.ip.is_multicast()
        || address.ip.is_broadcast()
        || !(1..=30).contains(&address.prefixlen)
    {
        return None;
    }
    let mask = u32::MAX << (32 - address.prefixlen);
    if u32::from(address.netmask) != mask {
        return None;
    }
    let expected = Ipv4Addr::from(u32::from(address.ip) | !mask);
    // Respect the OS broadcast flag/address, including point-to-point and
    // tunnel exclusions. Never substitute a global limited broadcast.
    address.broadcast.filter(|broadcast| *broadcast == expected)
}
