//! `epix-user` - the local user identity.
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
//! Certs (a chosen identity from an ID provider, via `certAdd`/`certSelect`)
//! attach to a xite by domain; when present, the cert's auth address is the
//! identity shown.
//!
//! ## On-disk format (`users.json`) is EpixNet-compatible
//! The file is a dict keyed by master address:
//! ```json
//! { "<master_address>": {
//!     "master_seed": "…",
//!     "sites":  { "<addr>": { "auth_address", "auth_privatekey", "cert"?, "privatekey"?, "settings"? } },
//!     "certs":  { "<domain>": { "auth_address", "auth_privatekey", "auth_type", "auth_user_name", "cert_sign" } },
//!     "settings": { "next_identity_index": 100000001, … },
//!     "follows": { … }   // Rust-only (Newsfeed); EpixNet preserves unknown keys
//! } }
//! ```
//! Load takes the (single) identity entry; save preserves any other users'
//! entries, so a Python `users.json` round-trips without losing identities.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;

/// The dedicated index range for standalone identity addresses (separate from
/// site-derived keys), matching EpixNet's `generateNewIdentityAddress`.
const IDENTITY_INDEX_START: u64 = 100_000_001;

/// A cert: an identity issued by an ID-provider xite, bound to a user auth key.
/// Fields mirror EpixNet's cert node exactly for on-disk compatibility.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cert {
    pub auth_address: String,
    pub auth_privatekey: String,
    /// `web`, `xid`, etc.
    pub auth_type: String,
    pub auth_user_name: String,
    pub cert_sign: String,
}

/// The user's identity for one xite.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SiteAuth {
    pub auth_address: String,
    pub auth_privatekey: String,
    /// The domain of the selected cert (a key into [`User::certs`]), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// The xite's own private key, once saved/recovered (owners only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privatekey: Option<String>,
    /// Arbitrary per-site settings a xite stored.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub settings: Map<String, Value>,
}

/// The local user: master seed + per-xite identities + certs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub master_seed: String,
    pub master_address: String,
    #[serde(default)]
    pub sites: HashMap<String, SiteAuth>,
    /// Certs the user obtained, keyed by provider domain.
    #[serde(default)]
    pub certs: HashMap<String, Cert>,
    /// User-level settings (e.g. `next_identity_index`).
    #[serde(default)]
    pub settings: Map<String, Value>,
    /// Newsfeed follows: `site_address -> {feed_name: [query, params]}`.
    #[serde(default)]
    pub follows: HashMap<String, Value>,
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
            certs: HashMap::new(),
            settings: Map::new(),
            follows: HashMap::new(),
        })
    }

    /// Set the Newsfeed follows for a site (`{feed_name: [query, params]}`).
    pub fn set_feed_follow(&mut self, address: &str, feeds: Value) {
        self.follows.insert(address.to_string(), feeds);
    }

    /// The Newsfeed follows for a site (empty object if none).
    pub fn feed_follow(&self, address: &str) -> Value {
        self.follows.get(address).cloned().unwrap_or_else(|| Value::Object(Default::default()))
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
    /// On creation, an active global cert is auto-attached (portable cert),
    /// matching EpixNet's `getSiteData`.
    pub fn site_data(&mut self, address: &str) -> Result<&SiteAuth, String> {
        if !self.sites.contains_key(address) {
            let index = Self::address_auth_index(address);
            let auth_privatekey = epix_crypt::hd_privatekey(&self.master_seed, index)?;
            let auth_address = epix_crypt::privatekey_to_address(&auth_privatekey)?;
            let cert = self.active_cert_domain();
            self.sites.insert(
                address.to_string(),
                SiteAuth { auth_address, auth_privatekey, cert, ..Default::default() },
            );
        }
        Ok(&self.sites[address])
    }

    /// The auth address shown for `address` - the selected cert's if one is
    /// active, otherwise the xite's own derived auth address.
    pub fn auth_address(&mut self, address: &str) -> Result<String, String> {
        // Derive the site first (so the entry exists), then resolve the cert.
        let own = self.site_data(address)?.auth_address.clone();
        Ok(match self.get_cert(address) {
            Some(cert) => cert.auth_address.clone(),
            None => own,
        })
    }

    /// The per-xite CryptMessage **encryption** private key (WIF), derived like
    /// EpixNet: `hd_privatekey(master_seed, auth_index(address) + 1000 + index)`.
    pub fn encrypt_privatekey(&self, address: &str, index: u64) -> Result<String, String> {
        let crypt_index = Self::address_auth_index(address) + 1000 + index;
        epix_crypt::hd_privatekey(&self.master_seed, crypt_index)
    }

    /// Save the xite's own private key (from recovery or user input).
    pub fn set_site_privatekey(&mut self, address: &str, privatekey: &str) -> Result<(), String> {
        self.site_data(address)?;
        if let Some(site) = self.sites.get_mut(address) {
            site.privatekey = Some(privatekey.to_string());
        }
        Ok(())
    }

    /// The saved xite private key, if any.
    pub fn site_privatekey(&self, address: &str) -> Option<String> {
        self.sites.get(address).and_then(|s| s.privatekey.clone())
    }

    // --- Certs --------------------------------------------------------------

    /// Add (or update) a cert for `domain`, bound to the given auth address.
    /// Returns `Ok(true)` if newly added, `Ok(false)` if a *different* cert for
    /// the domain already exists (caller should confirm before replacing), and
    /// `Ok(None)` if identical (no change). Mirrors EpixNet's `addCert`.
    pub fn add_cert(
        &mut self,
        auth_address: &str,
        domain: &str,
        auth_type: &str,
        auth_user_name: &str,
        cert_sign: &str,
    ) -> Result<Option<bool>, String> {
        // Find the private key for this auth address (master or a derived site).
        let auth_privatekey = if auth_address == self.master_address {
            self.master_seed.clone()
        } else {
            self.sites
                .values()
                .find(|s| s.auth_address == auth_address)
                .map(|s| s.auth_privatekey.clone())
                .ok_or_else(|| format!("Auth address {auth_address} not found in sites or master"))?
        };
        let node = Cert {
            auth_address: auth_address.to_string(),
            auth_privatekey,
            auth_type: auth_type.to_string(),
            auth_user_name: auth_user_name.to_string(),
            cert_sign: cert_sign.to_string(),
        };
        match self.certs.get(domain) {
            Some(existing) if existing == &node => Ok(None), // identical
            Some(_) => Ok(Some(false)),                      // different - needs confirm
            None => {
                self.certs.insert(domain.to_string(), node);
                Ok(Some(true))
            }
        }
    }

    /// Remove a cert by domain.
    pub fn delete_cert(&mut self, domain: &str) {
        self.certs.remove(domain);
    }

    /// Select (or clear, with `None`) the cert domain for one xite.
    pub fn set_cert(&mut self, address: &str, domain: Option<&str>) -> Result<(), String> {
        self.site_data(address)?;
        if let Some(site) = self.sites.get_mut(address) {
            site.cert = domain.map(str::to_string);
        }
        Ok(())
    }

    /// Select (or clear) a cert on **all** existing sites (portable cert).
    pub fn set_cert_global(&mut self, domain: Option<&str>) {
        for (addr, site) in self.sites.iter_mut() {
            if addr.starts_with("_identity_") {
                continue;
            }
            site.cert = domain.map(str::to_string);
        }
    }

    /// The globally active cert domain, if any site has a valid cert selected.
    pub fn active_cert_domain(&self) -> Option<String> {
        for (addr, site) in &self.sites {
            if addr.starts_with("_identity_") {
                continue;
            }
            if let Some(domain) = &site.cert {
                if self.certs.contains_key(domain) {
                    return Some(domain.clone());
                }
            }
        }
        None
    }

    /// The cert selected for `address`, if any (looked up by the site's cert
    /// domain).
    pub fn get_cert(&self, address: &str) -> Option<&Cert> {
        let domain = self.sites.get(address)?.cert.as_ref()?;
        self.certs.get(domain)
    }

    /// The cert user id (`name@provider`) for `address`, if a cert is selected.
    pub fn cert_user_id(&self, address: &str) -> Option<String> {
        let domain = self.sites.get(address)?.cert.as_ref()?;
        let cert = self.certs.get(domain)?;
        Some(format!("{}@{}", cert.auth_user_name, domain))
    }

    /// All certs as `[{auth_address, auth_type, auth_user_name, domain,
    /// selected}]` for `certList`; `selected` is true for the cert whose auth
    /// address matches the site's current one.
    pub fn cert_list(&mut self, address: &str) -> Vec<Value> {
        let current = self.auth_address(address).unwrap_or_default();
        self.certs
            .iter()
            .map(|(domain, cert)| {
                serde_json::json!({
                    "auth_address": cert.auth_address,
                    "auth_type": cert.auth_type,
                    "auth_user_name": cert.auth_user_name,
                    "domain": domain,
                    "selected": cert.auth_address == current,
                })
            })
            .collect()
    }

    /// The content directory name for user content on a site: the xID name with
    /// TLD if an xID cert is active, else the auth address (EpixNet's
    /// `getUserDirectory`).
    pub fn user_directory(&mut self, address: &str) -> Result<String, String> {
        if let Some(cert) = self.get_cert(address) {
            if cert.auth_type == "xid" && !cert.auth_user_name.is_empty() {
                return Ok(format!("{}.epix", cert.auth_user_name));
            }
        }
        self.auth_address(address)
    }

    /// Generate a fresh standalone identity address from a dedicated index
    /// range, stored so its private key can be found later (for cert creation).
    /// Returns `(address, privatekey)`. Mirrors `generateNewIdentityAddress`.
    pub fn generate_new_identity_address(&mut self) -> Result<(String, String), String> {
        let index = self
            .settings
            .get("next_identity_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(IDENTITY_INDEX_START);
        let privatekey = epix_crypt::hd_privatekey(&self.master_seed, index)?;
        let address = epix_crypt::privatekey_to_address(&privatekey)?;
        // Store under a synthetic key so add_cert can find the private key.
        if !self.sites.values().any(|s| s.auth_address == address) {
            self.sites.insert(
                format!("_identity_{index}"),
                SiteAuth {
                    auth_address: address.clone(),
                    auth_privatekey: privatekey.clone(),
                    ..Default::default()
                },
            );
        }
        self.settings.insert("next_identity_index".to_string(), Value::from(index + 1));
        Ok((address, privatekey))
    }

    // --- File IO (EpixNet-compatible users.json) ----------------------------

    /// This user as a single `users.json` entry object.
    fn to_file_entry(&self) -> Value {
        serde_json::json!({
            "master_seed": self.master_seed,
            "sites": self.sites,
            "certs": self.certs,
            "settings": self.settings,
            "follows": self.follows,
        })
    }

    /// Build a user from a `users.json` entry (its master address + the object).
    fn from_file_entry(master_address: &str, entry: &Value) -> Option<Self> {
        let master_seed = entry.get("master_seed")?.as_str()?.to_string();
        let sites = entry
            .get("sites")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let certs = entry
            .get("certs")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let settings = entry
            .get("settings")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        let follows = entry
            .get("follows")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        Some(Self {
            master_seed,
            master_address: master_address.to_string(),
            sites,
            certs,
            settings,
            follows,
        })
    }

    /// Load the identity from a `users.json` file, or generate + save one if the
    /// file is absent or holds no usable identity. Takes the first entry (this
    /// node runs one identity; Multiuser switches among several by master seed).
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(Value::Object(users)) = serde_json::from_slice::<Value>(&bytes) {
                for (master_address, entry) in &users {
                    if let Some(user) = Self::from_file_entry(master_address, entry) {
                        // A seed-derived master address must match its key, or
                        // the file is corrupt for that entry - skip it.
                        if epix_crypt::privatekey_to_address(&user.master_seed).as_deref()
                            == Ok(master_address)
                        {
                            return Ok(user);
                        }
                    }
                }
            }
        }
        let user = Self::generate();
        user.save(path)?;
        Ok(user)
    }

    /// Persist to a `users.json` file, preserving any other users' entries so a
    /// multi-identity (or Python-written) file is not clobbered.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut users: Map<String, Value> = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        users.insert(self.master_address.clone(), self.to_file_entry());
        let bytes = serde_json::to_vec_pretty(&Value::Object(users))
            .map_err(|e| format!("serialize user: {e}"))?;
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

        let mut u2 = User::from_seed(seed).unwrap();
        assert_eq!(u2.site_data("talk.epix").unwrap().auth_address, a1.auth_address);
    }

    #[test]
    fn cert_add_select_overrides_auth_address() {
        let mut u = User::generate();
        let auth = u.auth_address("talk.epix").unwrap();
        let own = u.site_data("talk.epix").unwrap().auth_address.clone();
        assert_eq!(auth, own);
        assert_eq!(u.cert_user_id("talk.epix"), None);

        // Add a cert bound to the site's own auth address, then select it.
        assert_eq!(u.add_cert(&own, "zeroid.bit", "web", "alice", "sig").unwrap(), Some(true));
        u.set_cert("talk.epix", Some("zeroid.bit")).unwrap();
        assert_eq!(u.cert_user_id("talk.epix").as_deref(), Some("alice@zeroid.bit"));
        // Cert shares the site's auth address here (bound to it), so auth is same.
        assert_eq!(u.auth_address("talk.epix").unwrap(), own);

        // Re-adding the same cert is a no-op; a different one needs confirmation.
        assert_eq!(u.add_cert(&own, "zeroid.bit", "web", "alice", "sig").unwrap(), None);
        assert_eq!(u.add_cert(&own, "zeroid.bit", "web", "bob", "sig2").unwrap(), Some(false));
    }

    #[test]
    fn cert_list_marks_selected() {
        let mut u = User::generate();
        let own = u.site_data("talk.epix").unwrap().auth_address.clone();
        u.add_cert(&own, "zeroid.bit", "web", "alice", "s").unwrap();
        u.set_cert("talk.epix", Some("zeroid.bit")).unwrap();
        let list = u.cert_list("talk.epix");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["domain"], "zeroid.bit");
        assert_eq!(list[0]["selected"], true);
    }

    #[test]
    fn new_identity_uses_dedicated_index_range() {
        let mut u = User::generate();
        let (addr, _pk) = u.generate_new_identity_address().unwrap();
        assert!(addr.starts_with("epix1"));
        // The index advanced.
        assert_eq!(u.settings["next_identity_index"], 100_000_002);
        // Stored so add_cert can bind to it.
        assert!(u.sites.values().any(|s| s.auth_address == addr));
    }

    #[test]
    fn users_json_is_python_keyed_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.json");
        let mut u = User::generate();
        u.site_data("talk.epix").unwrap();
        let own = u.sites["talk.epix"].auth_address.clone();
        u.add_cert(&own, "zeroid.bit", "web", "alice", "sig").unwrap();
        u.set_cert("talk.epix", Some("zeroid.bit")).unwrap();
        u.save(&path).unwrap();

        // The file is keyed by master address, with a top-level certs map.
        let raw: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let entry = &raw[&u.master_address];
        assert_eq!(entry["master_seed"], u.master_seed);
        assert_eq!(entry["certs"]["zeroid.bit"]["auth_user_name"], "alice");
        assert_eq!(entry["sites"]["talk.epix"]["cert"], "zeroid.bit");

        let loaded = User::load_or_create(&path).unwrap();
        assert_eq!(loaded.master_seed, u.master_seed);
        assert_eq!(loaded.cert_user_id("talk.epix").as_deref(), Some("alice@zeroid.bit"));
    }

    #[test]
    fn save_preserves_other_users() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.json");
        // A pre-existing Python-style file with another identity.
        let other = User::generate();
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                other.master_address.clone(): {
                    "master_seed": other.master_seed,
                    "sites": {}, "certs": {}, "settings": {}
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let mut u = User::generate();
        u.site_data("talk.epix").unwrap();
        u.save(&path).unwrap();

        // Both identities are present after save.
        let raw: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(raw.get(&other.master_address).is_some(), "other user preserved");
        assert!(raw.get(&u.master_address).is_some(), "our user saved");
    }
}
