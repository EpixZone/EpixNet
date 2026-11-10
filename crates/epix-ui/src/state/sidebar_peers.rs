//! Sidebar peer sharing and map projection. Share links contain only dialable,
//! public endpoints; importing a link never enables a transport or changes policy.
use super::AppState;
use epix_core::PeerAddr;
use epix_peer::Peer;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

const SHARE_LIMIT: usize = 20;

fn shareable(peer: &PeerAddr) -> bool {
    if !peer.is_wellformed() || peer.is_private() || !Peer::new(peer.clone(), 0).is_connectable() {
        return false;
    }
    match peer {
        PeerAddr::Ip(socket) => public_ip(socket.ip()),
        _ => true,
    }
}

fn public_ip(ip: IpAddr) -> bool {
    if PeerAddr::Ip(SocketAddr::new(ip, 0)).is_private() {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && ip.to_ipv4_mapped().is_none_or(|v4| public_ip(v4.into()))
        }
    }
}

impl AppState {
    /// A portable local-UI link, without private/LAN addresses or session handles.
    /// With no eligible peers it remains a usable ordinary xite link.
    pub async fn sidebar_peer_share_url(&self, address: &str) -> String {
        let canonical = self.canonical_key(address).await;
        let networks = self.dialable_networks().await;
        let mut peers: Vec<String> = self
            .connectable_peers(&canonical, usize::MAX)
            .await
            .into_iter()
            .filter(|peer| shareable(peer) && networks.can_dial(peer))
            .take(SHARE_LIMIT)
            .map(|p| p.to_string())
            .collect();
        // A published onion is safe to share, unlike the operator's external IP.
        if self.is_serving(&canonical).await && self.dialable_networks().await.onion {
            if let Some(host) = self.onion_address().await {
                let endpoint = format!("{host}.onion:{}", self.fileserver_port().await);
                if PeerAddr::parse(&endpoint).is_ok_and(|p| shareable(&p))
                    && !peers.contains(&endpoint)
                {
                    peers.truncate(SHARE_LIMIT - 1);
                    peers.push(endpoint);
                }
            }
        }
        let mut url = reqwest::Url::parse(&format!(
            "http://127.0.0.1:{}/{canonical}/",
            self.ui_port().await
        ))
        .expect("a canonical xite and bound UI port form a URL");
        if !peers.is_empty() {
            url.query_pairs_mut()
                .append_pair("epixnet_peers", &peers.join(","));
        }
        url.into()
    }

    /// Import an untrusted share link for an already registered xite. Unknown,
    /// private, self, unsupported and excess endpoints are ignored independently.
    pub async fn import_sidebar_peers(&self, address: &str, endpoints: &[String]) -> usize {
        if self.ui_restrict().await || !self.has_xite(address).await {
            return 0;
        }
        let nets = self.dialable_networks().await;
        let mut accepted = Vec::new();
        let mut seen = HashSet::new();
        for endpoint in endpoints.iter().take(SHARE_LIMIT) {
            if endpoint.len() > 256 {
                continue;
            }
            let Ok(peer) = PeerAddr::parse(endpoint) else {
                continue;
            };
            if shareable(&peer)
                && nets.can_dial(&peer)
                && !self.is_own_peer(&peer).await
                && seen.insert(peer.clone())
            {
                accepted.push(peer);
            }
        }
        let count = accepted.len();
        if count > 0 {
            self.add_peers(address, accepted).await;
            self.persist_peers().await;
        }
        count
    }

    /// The sidebar map includes this node when it has an advertised public IP.
    /// Overlay-only routing never exposes the node's clearnet location. GeoIP is
    /// local, and missing databases or addresses simply produce no self marker.
    pub async fn peer_globe_data(&self, address: &str) -> Vec<f64> {
        let Some(geoip) = self.geoip.read().await.clone() else {
            return Vec::new();
        };
        if !self.has_xite(address).await {
            return Vec::new();
        }
        let mut pings = self.known_peer_ips(Some(address)).await;
        for peer in self.conn_pool.connected_addrs().await {
            if let PeerAddr::Ip(socket) = &peer {
                if let Some(ping) = pings.get_mut(&socket.ip()) {
                    *ping = self.conn_pool.ping_for(&peer).await;
                }
            }
        }
        let mut points = Vec::new();
        if !epix_core::route_all_via_overlay() && self.tor_status().await.1 != "Always" {
            let configured = self
                .config_get("ip_external")
                .await
                .and_then(|v| v.as_str().map(str::to_string));
            let (open, detected) = self.port_status().await;
            for text in [configured, if open { detected } else { None }]
                .into_iter()
                .flatten()
            {
                let Ok(ip) = text.parse::<IpAddr>() else {
                    continue;
                };
                if !public_ip(ip) || points.iter().any(|p: &MapPoint| p.ip == ip) {
                    continue;
                }
                if let Some(loc) = geoip.locate(ip) {
                    points.push(MapPoint {
                        ip,
                        lat: loc.lat,
                        lon: loc.lon,
                        ping: Some(0),
                        own: true,
                    });
                    pings.remove(&ip);
                }
            }
        }
        for (ip, ping) in pings {
            if let Some(loc) = geoip.locate(ip) {
                points.push(MapPoint {
                    ip,
                    lat: loc.lat,
                    lon: loc.lon,
                    ping,
                    own: false,
                });
            }
        }
        project_points(points)
    }
}

#[derive(Clone)]
struct MapPoint {
    ip: IpAddr,
    lat: f64,
    lon: f64,
    ping: Option<i64>,
    own: bool,
}

fn project_points(mut points: Vec<MapPoint>) -> Vec<f64> {
    // Keep self exact and make offsets stable across refreshes and hash-map order.
    points.sort_by_key(|p| (!p.own, p.ip));
    let pings: Vec<f64> = points
        .iter()
        .filter_map(|p| p.ping.filter(|p| *p > 0).map(|p| p as f64))
        .collect();
    let avg = if pings.is_empty() {
        0.0
    } else {
        pings.iter().sum::<f64>() / pings.len() as f64
    };
    let mut placed = HashSet::new();
    let mut result = Vec::new();
    for point in points {
        if !point.lat.is_finite() || !point.lon.is_finite() {
            continue;
        }
        let (mut lat, mut lon) = (point.lat, point.lon);
        let mut offset = 0u32;
        while !placed.insert((lat.to_bits(), lon.to_bits())) {
            offset += 1;
            let angle = f64::from(offset) * 2.399963229728653;
            // Bars are 2.75 units wide on a radius-200 sphere. A 1.5 degree
            // step clears that width. Use spherical displacement so longitude
            // convergence near the poles does not collapse the separation.
            let radius = (f64::from(offset).sqrt() * 1.5).to_radians();
            let origin = point.lat.to_radians();
            let displaced = (origin.sin() * radius.cos()
                + origin.cos() * radius.sin() * angle.cos())
            .clamp(-1.0, 1.0)
            .asin();
            lat = displaced.to_degrees();
            lon = (point.lon
                + (angle.sin() * radius.sin() * origin.cos())
                    .atan2(radius.cos() - origin.sin() * displaced.sin())
                    .to_degrees()
                + 180.0)
                .rem_euclid(360.0)
                - 180.0;
        }
        let height = if point.own {
            -0.135
        } else {
            match point.ping {
                Some(p) if p > 0 && avg > 0.0 => (1.0 + p as f64 / avg).log(300.0).min(0.20),
                _ => -0.03,
            }
        };
        result.extend_from_slice(&[lat, lon, height]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{project_points, shareable, MapPoint};
    use epix_core::PeerAddr;
    use std::collections::HashSet;

    #[test]
    fn share_endpoints_exclude_private_special_and_invalid_addresses() {
        for endpoint in [
            "127.0.0.1:26552",
            "192.168.1.1:26552",
            "100.64.0.1:26552",
            "[fd00::1]:26552",
            "[::ffff:127.0.0.1]:26552",
            "0.0.0.0:26552",
            "224.0.0.1:26552",
            "255.255.255.255:26552",
            "[::]:26552",
            "[ff02::1]:26552",
            "8.8.8.8:0",
            "8.8.8.8:1",
        ] {
            assert!(
                !shareable(&PeerAddr::parse(endpoint).unwrap()),
                "{endpoint}"
            );
        }
        for endpoint in [
            "8.8.8.8:26552",
            "[2606:4700:4700::1111]:26552",
            "rns:00112233445566778899aabbccddeeff",
        ] {
            assert!(shareable(&PeerAddr::parse(endpoint).unwrap()), "{endpoint}");
        }
    }

    #[test]
    fn globe_preserves_self_and_separates_coincident_points_deterministically() {
        let points: Vec<_> = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "2606:4700::1"]
            .into_iter()
            .enumerate()
            .map(|(i, ip)| MapPoint {
                ip: ip.parse().unwrap(),
                lat: 51.5,
                lon: -0.1,
                ping: if i == 0 { Some(0) } else { Some(35) },
                own: i == 0,
            })
            .collect();
        let data = project_points(points.clone());
        assert_eq!(&data[..3], &[51.5, -0.1, -0.135]);
        let unique: HashSet<_> = data
            .chunks_exact(3)
            .map(|p| (p[0].to_bits(), p[1].to_bits()))
            .collect();
        assert_eq!(unique.len(), 4);
        assert!(data.iter().all(|v| v.is_finite()));
        assert_eq!(data, project_points(points.into_iter().rev().collect()));

        for latitude in [0.0, 37.422, 51.5, 89.99, -89.99] {
            let duplicates = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
                .into_iter()
                .map(|ip| MapPoint {
                    ip: ip.parse().unwrap(),
                    lat: latitude,
                    lon: -122.085,
                    ping: None,
                    own: false,
                })
                .collect();
            let projected = project_points(duplicates);
            for (index, a) in projected.chunks_exact(3).enumerate() {
                for b in projected.chunks_exact(3).skip(index + 1) {
                    let (a_lat, b_lat) = (a[0].to_radians(), b[0].to_radians());
                    let dot = a_lat.sin() * b_lat.sin()
                        + a_lat.cos() * b_lat.cos() * (a[1] - b[1]).to_radians().cos();
                    let chord = 200.0 * (2.0 - 2.0 * dot.clamp(-1.0, 1.0)).sqrt();
                    assert!(
                        chord > 2.75,
                        "map bars overlap"
                    );
                }
            }
        }
    }
}
