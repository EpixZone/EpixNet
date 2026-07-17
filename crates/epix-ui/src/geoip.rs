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
        // SAFETY: the .mmdb is written once by `ensure` (or shipped read-only)
        // and not mutated while mapped, so the mapping stays valid for its life.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { Reader::open_mmap(path) }
            .ok()
            .map(|reader| Self { reader })
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
        let city: geoip2::City = self.reader.lookup(ip).ok()?.decode().ok().flatten()?;
        // In maxminddb 0.27 the sub-records are plain structs (not Option), and
        // localized names are typed fields (`names.english`) rather than a map.
        Some(Loc {
            lat: city.location.latitude?,
            lon: city.location.longitude?,
            city: city.city.names.english.map(|s| s.to_string()),
            country: city.country.names.english.map(|s| s.to_string()),
        })
    }
}
