//! `epix-user` — the local user identity.
//!
//! A user is a **master seed** plus, per xite, a derived identity key. When a
//! xite is first visited the user gets a fresh auth key for it, derived from the
//! master seed and the xite address:
//!
//! ```text
//! index      = int(hex(address_utf8_bytes)) % 100_000_000
//! auth_key   = hd_privatekey(master_seed, index)      // WIF
//! auth_addr  = privatekey_to_address(auth_key)        // epix1…
//! ```
//!
//! This matches EpixNet's `User.generateAuthAddress` byte-for-byte (the fold is
//! `int(binascii.hexlify(address.encode()), 16) % 1e8`, and the crypto is the
//! same `hd_privatekey` / `privatekey_to_address` already validated in
//! `epix-crypt`), so a user's per-xite identity is identical across clients.
//!
//! Certs (a chosen identity from an ID provider, via `certSelect`) attach to a
//! xite later; when present, the cert's auth address is the identity shown.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A cert: an identity issued by an ID-provider xite, bound to a user auth key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cert {
    /// Provider domain, e.g. `zeroid.bit`.
    pub provider: String,
    /// The chosen user name.
    pub user_name: String,
    /// The auth address the cert was issued against.
    pub auth_address: String,
    /// Provider signature over `user_name#auth_type/auth_user_name`.
    pub cert_sign: String,
}

impl Cert {
    /// `user_name@provider`, the identity string xites display.
    pub fn user_id(&self) -> String {
        format!("{}@{}", self.user_name, self.provider)
    }
}

/// The user's identity for one xite.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteAuth {
    pub auth_address: String,
    pub auth_privatekey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<Cert>,
}

/// The local user: master seed + per-xite identities.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub master_seed: String,
    pub master_address: String,
    #[serde(default)]
    pub sites: HashMap<String, SiteAuth>,
}

impl User {
    /// Create a user with a fresh random master seed.
    pub fn generate() -> Self {
        Self::from_seed(&epix_crypt::new_seed()).expect("fresh seed is valid")
    }

    /// Rebuild a user from an existing master seed (32-byte hex).
    pub fn from_seed(master_seed: &str) -> Result<Self, String> {
        let master_address = epix_crypt::privatekey_to_address(master_seed)?;
        Ok(Self {
            master_seed: master_seed.to_string(),
            master_address,
            sites: HashMap::new(),
        })
    }

    /// The BIP32-ish child index for a xite: the address bytes as a big-endian
    /// integer mod 1e8. Folded so no bignum is needed; equals
    /// `int(hex(address_utf8)) % 1e8`.
    pub fn address_auth_index(address: &str) -> u64 {
        let mut acc: u64 = 0;
        for b in address.as_bytes() {
            acc = (acc * 256 + *b as u64) % 100_000_000;
        }
        acc
    }

    /// The user's identity for `address`, creating (deriving) it on first use.
    pub fn site_data(&mut self, address: &str) -> Result<&SiteAuth, String> {
        if !self.sites.contains_key(address) {
            let index = Self::address_auth_index(address);
            let auth_privatekey = epix_crypt::hd_privatekey(&self.master_seed, index)?;
            let auth_address = epix_crypt::privatekey_to_address(&auth_privatekey)?;
            self.sites.insert(
                address.to_string(),
                SiteAuth { auth_address, auth_privatekey, cert: None },
            );
        }
        Ok(&self.sites[address])
    }

    /// The auth address shown for `address` — the cert's if one is selected,
    /// otherwise the xite's own derived auth address.
    pub fn auth_address(&mut self, address: &str) -> Result<String, String> {
        let site = self.site_data(address)?;
        Ok(match &site.cert {
            Some(cert) => cert.auth_address.clone(),
            None => site.auth_address.clone(),
        })
    }

    /// The cert user id (`name@provider`) for `address`, if a cert is selected.
    pub fn cert_user_id(&self, address: &str) -> Option<String> {
        self.sites.get(address)?.cert.as_ref().map(Cert::user_id)
    }

    /// Attach (or replace) the selected cert for a xite.
    pub fn set_cert(&mut self, address: &str, cert: Cert) -> Result<(), String> {
        self.site_data(address)?; // ensure derived
        if let Some(site) = self.sites.get_mut(address) {
            site.cert = Some(cert);
        }
        Ok(())
    }

    /// Load a user from a JSON file, or generate + save a new one if absent.
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        if path.exists() {
            let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
            serde_json::from_slice(&bytes).map_err(|e| format!("parse user: {e}"))
        } else {
            let user = Self::generate();
            user.save(path)?;
            Ok(user)
        }
    }

    /// Persist to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| format!("serialize user: {e}"))?;
        std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_index_folds_like_python() {
        // int(hexlify(addr.encode()),16) % 1e8, verified against Python.
        assert_eq!(User::address_auth_index("talk.epix"), 86281592);
        assert_eq!(
            User::address_auth_index("1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D"),
            98335300
        );
        assert_eq!(User::address_auth_index("x"), 120);
    }

    #[test]
    fn auth_address_is_deterministic_and_per_site() {
        let seed = "5f5e100000000000000000000000000000000000000000000000000000000001";
        let mut u = User::from_seed(seed).unwrap();
        let a1 = u.site_data("talk.epix").unwrap().clone();
        let a2 = u.site_data("blog.epix").unwrap().clone();
        assert!(a1.auth_address.starts_with("epix1"));
        assert!(a2.auth_address.starts_with("epix1"));
        assert_ne!(a1.auth_address, a2.auth_address, "different xite -> different identity");

        // Same seed + same address -> identical identity (deterministic).
        let mut u2 = User::from_seed(seed).unwrap();
        assert_eq!(u2.site_data("talk.epix").unwrap().auth_address, a1.auth_address);
    }

    #[test]
    fn cert_overrides_shown_auth_address() {
        let mut u = User::generate();
        let own = u.site_data("talk.epix").unwrap().auth_address.clone();
        assert_eq!(u.auth_address("talk.epix").unwrap(), own);
        assert_eq!(u.cert_user_id("talk.epix"), None);

        u.set_cert(
            "talk.epix",
            Cert {
                provider: "zeroid.bit".into(),
                user_name: "alice".into(),
                auth_address: "epix1certauthaddressplaceholder00000000".into(),
                cert_sign: "sig".into(),
            },
        )
        .unwrap();
        assert_eq!(u.cert_user_id("talk.epix").as_deref(), Some("alice@zeroid.bit"));
        assert_eq!(
            u.auth_address("talk.epix").unwrap(),
            "epix1certauthaddressplaceholder00000000"
        );
    }

    #[test]
    fn round_trips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.json");
        let mut u = User::generate();
        u.site_data("talk.epix").unwrap();
        u.save(&path).unwrap();

        let loaded = User::load_or_create(&path).unwrap();
        assert_eq!(loaded.master_seed, u.master_seed);
        assert_eq!(loaded.master_address, u.master_address);
        assert_eq!(
            loaded.sites["talk.epix"].auth_address,
            u.sites["talk.epix"].auth_address
        );
    }
}
