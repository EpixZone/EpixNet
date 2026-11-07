use super::{IpType, PeerAddr};

#[test]
fn session_handles_cannot_enter_from_text_json_or_compact_addresses() {
    for network in [
        IpType::Ipv4,
        IpType::Ipv6,
        IpType::Onion,
        IpType::I2p,
        IpType::Rns,
    ] {
        let peer = PeerAddr::Session {
            id: [7; 32],
            network,
        };
        assert!(PeerAddr::parse(&peer.to_string()).is_err());
        assert!(serde_json::to_value(&peer).is_err());
        assert!(peer.pack().is_none());
        assert!(peer.is_private(), "session handles never belong in PEX");
    }
    let forged = serde_json::json!({"Session": {"id": vec![7; 32], "network": "Ipv4"}});
    assert!(serde_json::from_value::<PeerAddr>(forged).is_err());
    for parsed in [
        PeerAddr::unpack_ip(&[7; 32]),
        PeerAddr::unpack_onion(&[7; 32]),
        PeerAddr::unpack_i2p(&[7; 32]),
        PeerAddr::unpack_rns(&[7; 32]),
    ] {
        assert!(parsed.is_none_or(|peer| !peer.is_session()));
    }
}

#[test]
fn session_handles_retain_the_authenticated_transport_class() {
    let direct = PeerAddr::Session {
        id: [1; 32],
        network: IpType::Ipv4,
    };
    let onion = PeerAddr::Session {
        id: [2; 32],
        network: IpType::Onion,
    };
    assert_eq!(direct.scheme(), "tcp");
    assert!(!direct.is_overlay());
    assert_eq!(onion.scheme(), "onion");
    assert!(onion.is_overlay());
    assert!(!PeerAddr::Session {
        id: [0; 32],
        network: IpType::Ipv4
    }
    .is_wellformed());
}
