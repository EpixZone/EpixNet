//! Peer IP geolocation for the dashboard's world map.
//!
//! Reads any MaxMind-DB-format `.mmdb` (we bundle DB-IP City Lite, CC-BY-4.0)
//! and resolves an IP to `{lat, lon, city, country}` - the shape the Stats
//! page's `chartGetPeerLocations` returns.

use maxminddb::{geoip2, Mmap, Reader};
use std::net::IpAddr;
use std::path::Path;

/// A geolocated point the world map plots.
#[derive(Clone, Debug)]
pub struct Loc {
    pub lat: f64,
    pub lon: f64,
    pub city: Option<String>,
    pub country: Option<String>,
}

/// An open geolocation database (memory-mapped, so opening is near-instant and
/// the OS pages in only the parts a lookup touches).
pub struct GeoIp {
    reader: Reader<Mmap>,
}

impl GeoIp {
    /// Memory-map a `.mmdb` file.
    pub fn open(path: impl AsRef<Path>) -> Option<Self> {
        Reader::open_mmap(path).ok().map(|reader| Self { reader })
    }

    /// Ensure the database exists at `mmdb_path` (decompressing `gz` into it on
    /// first run), then open it. Lets the node ship the db gzipped and expand it
    /// once, so the map works with no runtime download.
    pub fn ensure(gz: &[u8], mmdb_path: impl AsRef<Path>) -> Option<Self> {
        let path = mmdb_path.as_ref();
        if !path.exists() || std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(true) {
            use flate2::read::GzDecoder;
            use std::io::Read;
            let mut out = Vec::new();
            GzDecoder::new(gz).read_to_end(&mut out).ok()?;
            std::fs::write(path, &out).ok()?;
        }
        Self::open(path)
    }

    /// Resolve an IP to a location, or `None` if it is not in the database.
    pub fn locate(&self, ip: IpAddr) -> Option<Loc> {
        let city: geoip2::City = self.reader.lookup(ip).ok().flatten()?;
        let location = city.location?;
        let en = |names: Option<std::collections::BTreeMap<&str, &str>>| {
            names.and_then(|n| n.get("en").map(|s| s.to_string()))
        };
        Some(Loc {
            lat: location.latitude?,
            lon: location.longitude?,
            city: en(city.city.and_then(|c| c.names)),
            country: en(city.country.and_then(|c| c.names)),
        })
    }
}
