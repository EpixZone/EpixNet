use super::select_destinations;
use if_addrs::{IfAddr, IfOperStatus, Ifv4Addr, Ifv6Addr, Interface};
use std::net::{Ipv4Addr, Ipv6Addr};

fn interface(ip: [u8; 4], prefix: u8) -> Interface {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Interface {
        name: "fixture".into(),
        index: Some(1),
        oper_status: IfOperStatus::Up,
        is_p2p: false,
        addr: IfAddr::V4(Ifv4Addr {
            ip: ip.into(),
            netmask: Ipv4Addr::from(mask),
            prefixlen: prefix,
            broadcast: Some(Ipv4Addr::from(u32::from(Ipv4Addr::from(ip)) | !mask)),
        }),
        #[cfg(windows)]
        adapter_name: "fixture".into(),
    }
}

#[test]
fn chooses_each_connected_subnet_and_link_local_without_a_default_route() {
    let interfaces = vec![
        interface([10, 77, 0, 1], 24),
        interface([192, 168, 5, 3], 24),
        interface([10, 77, 0, 2], 24),
        interface([169, 254, 10, 1], 16),
    ];
    assert_eq!(
        select_destinations(interfaces),
        vec![
            Ipv4Addr::new(10, 77, 0, 255),
            Ipv4Addr::new(169, 254, 255, 255),
            Ipv4Addr::new(192, 168, 5, 255)
        ]
    );
}

#[test]
fn down_loopback_point_to_point_and_ipv6_never_gain_broadcast_fallback() {
    let mut down = interface([10, 0, 0, 1], 24);
    down.oper_status = IfOperStatus::Down;
    let mut point = interface([10, 66, 66, 2], 24);
    point.is_p2p = true;
    let mut ipv6 = interface([10, 0, 0, 1], 24);
    ipv6.addr = IfAddr::V6(Ifv6Addr {
        ip: "fe80::1".parse().unwrap(),
        netmask: Ipv6Addr::UNSPECIFIED,
        prefixlen: 64,
        broadcast: None,
    });
    assert!(select_destinations(vec![down, point, ipv6, interface([127, 0, 0, 1], 8)]).is_empty());
    assert!(select_destinations(Vec::new()).is_empty());
}

#[test]
fn missing_or_inconsistent_broadcast_and_host_masks_are_rejected() {
    let mut missing = interface([10, 77, 0, 1], 24);
    let IfAddr::V4(address) = &mut missing.addr else {
        unreachable!()
    };
    address.broadcast = None;
    let mut foreign = interface([10, 77, 0, 1], 24);
    let IfAddr::V4(address) = &mut foreign.addr else {
        unreachable!()
    };
    address.broadcast = Some(Ipv4Addr::new(192, 168, 1, 255));
    let mut mask = interface([10, 77, 0, 1], 24);
    let IfAddr::V4(address) = &mut mask.addr else {
        unreachable!()
    };
    address.netmask = Ipv4Addr::new(255, 0, 255, 0);
    assert!(select_destinations(vec![
        missing,
        foreign,
        mask,
        interface([10, 0, 0, 1], 0),
        interface([10, 0, 0, 1], 31),
        interface([10, 0, 0, 1], 32)
    ])
    .is_empty());
}
