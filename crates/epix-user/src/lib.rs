//! `epix-user` - the local user identity.
//!
//! A user is a **master seed** plus:
//!
//! - a derived key per xite (the legacy ZeroNet-style per-site key, used today
//!   only to derive the CryptMessage encryption key for legacy mail), and
//! - a list of **identities**: xID names the user has linked on chain, each with
//!   its own auth key. One identity is the node-wide **default**; any xite can
//!   override it with another held identity, or with "none".
//!
//! Browsing needs no identity. Posting (anything signed under `data/users/`)
//! requires one: when no identity is selected for a xite, [`User::auth_address`]
//! and [`User::auth_privatekey`] return [`XID_REQUIRED`].
//!
//! Per-xite keys are derived byte-for-byte like EpixNet's `User.generateAuthAddress`:
//!
//! ```text
//! index      = int(hex(address_utf8_bytes)) % 100_000_000
//! auth_key   = hd_privatekey(master_seed, index)      // WIF
//! auth_addr  = privatekey_to_address(auth_key)        // epix1…
//! ```
//!
//! ## On-disk format (`users.json`)
//! The file is a dict keyed by master address:
//! ```json
//! { "<master_address>": {
//!     "schema_version": 2,
//!     "master_seed": "…",
//!     "xites":  { "<addr>": { "auth_address", "auth_privatekey", "identity"?, "privatekey"?, "settings"? } },
//!     "identities": [ { "auth_address", "auth_privatekey", "name", "tld", "cert_sign", "linked_at"?, "hd_index"? } ],
//!     "default_identity": "epix1…",
//!     "certs":  { "<domain>": { … } },          // non-xID provider certs from schema 1, carried through untouched
//!     "settings": { "next_identity_index": 100000001, … },
//!     "follows": { … }
//! } }
//! ```
//! Schema 1 files (the one `certs["xid.epix"]` slot plus a `cert` domain on every
//! xite, as written by older nodes and by Python EpixNet) migrate on load: the
//! xID cert becomes the first identity and the node-wide default, and the
//! per-xite `cert` fields are dropped. The migration is one-way and idempotent.
//! Load takes the (single) identity entry; save preserves any other users'
//! entries, so a Python `users.json` round-trips without losing identities.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// The dedicated index range for standalone identity addresses (separate from
/// xite-derived keys), matching EpixNet's `generateNewIdentityAddress`.
const IDENTITY_INDEX_START: u64 = 100_000_001;

/// The TLD every xID identity lives under.
pub const XID_TLD: &str = "epix";

/// The provider domain in the signed content wire format (`cert_user_id` is
/// `<name>@xid.epix`). Unchanged from schema 1; peers verify it.
pub const XID_CERT_DOMAIN: &str = "xid.epix";

/// The error every posting path returns when the xite has no identity selected.
pub const XID_REQUIRED: &str = "xID required: select or link an identity for this xite";

/// The users.json entry schema written by this build.
pub const USERS_SCHEMA_VERSION: u64 = 2;

/// A schema-1 provider cert. Kept only so non-xID certs written by an older
/// node round-trip through `users.json`; the node never consults them.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cert {
    pub auth_address: String,
    pub auth_privatekey: String,
    /// `web`, `xid`, etc.
    pub auth_type: String,
    pub auth_user_name: String,
    pub cert_sign: String,
}

fn default_tld() -> String {
    XID_TLD.to_string()
}

/// A linked xID identity: a name on chain, the linked address the user holds
/// the key for, and the self-signed cert that binds them in signed content.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub auth_address: String,
    pub auth_privatekey: String,
    /// The xID name without TLD, e.g. `alice`.
    pub name: String,
    #[serde(default = "default_tld")]
    pub tld: String,
    /// `sign_keccak("<auth_address>#xid/<name>", auth_privatekey)` - the wire
    /// `cert_sign` peers verify against the chain's linked-identity set.
    pub cert_sign: String,
    /// Unix seconds when this node linked the identity (informational).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_at: Option<u64>,
    /// The `_identity_<n>` HD index the address was minted from, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hd_index: Option<u64>,
}

impl Identity {
    /// The user-content directory name, e.g. `alice.epix`.
    pub fn xid(&self) -> String {
        format!("{}.{}", self.name, self.tld)
    }

    /// The wire `cert_user_id`, e.g. `alice@xid.epix`.
    pub fn cert_user_id(&self) -> String {
        format!("{}@{XID_CERT_DOMAIN}", self.name)
    }

    /// The wire `cert_auth_type`.
    pub fn cert_auth_type(&self) -> &'static str {
        "xid"
    }
}

/// How a xite resolves its identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityScope {
    /// No override: the node-wide default applies.
    Inherit,
    /// An explicit identity chosen for this xite.
    Xite,
    /// Explicitly none: browse anonymously even though a default exists.
    None,
}

impl IdentityScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            IdentityScope::Inherit => "inherit",
            IdentityScope::Xite => "xite",
            IdentityScope::None => "none",
        }
    }
}

/// The user's per-xite record: the derived key plus the identity override.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct XiteAuth {
    pub auth_address: String,
    pub auth_privatekey: String,
    /// Schema-1 cert domain. Read for migration only, never written back.
    #[serde(default, skip_serializing)]
    pub cert: Option<String>,
    /// Identity override: absent = inherit the default; `""` = explicitly none;
    /// an address = that held identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// The xite's own private key, once saved/recovered (owners only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privatekey: Option<String>,
    /// Arbitrary per-xite settings a xite stored.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub settings: Map<String, Value>,
}

/// The local user: master seed + per-xite keys + linked identities.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub master_seed: String,
    pub master_address: String,
    // Written as `xites`; the legacy `sites` key is still accepted on read, so
    // a users.json from an older node (or from Python EpixNet) loads as-is and
    // is rewritten under the new name on the next save.
    #[serde(default, alias = "sites")]
    pub xites: HashMap<String, XiteAuth>,
    /// Linked xID identities, in link order.
    #[serde(default)]
    pub identities: Vec<Identity>,
    /// The node-wide default identity (an `identities[*].auth_address`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_identity: Option<String>,
    /// Non-xID provider certs from schema 1, carried through under `certs`.
    #[serde(default, rename = "certs")]
    pub legacy_certs: HashMap<String, Cert>,
    /// User-level settings (e.g. `next_identity_index`).
    #[serde(default)]
    pub settings: Map<String, Value>,
    /// Newsfeed follows: `xite_address -> {feed_name: [query, params]}`.
    #[serde(default)]
    pub follows: HashMap<String, Value>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
            xites: HashMap::new(),
            identities: Vec::new(),
            default_identity: None,
            legacy_certs: HashMap::new(),
            settings: Map::new(),
            follows: HashMap::new(),
        })
    }

    /// Set the Newsfeed follows for a xite (`{feed_name: [query, params]}`).
    pub fn set_feed_follow(&mut self, address: &str, feeds: Value) {
        self.follows.insert(address.to_string(), feeds);
    }

    /// The Newsfeed follows for a xite (empty object if none).
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

    /// The user's derived per-xite record for `address`, creating it on first
    /// use. The derived key is not an identity: it only feeds the legacy
    /// encryption key derivation and the xite's own private key storage.
    pub fn xite_data(&mut self, address: &str) -> Result<&XiteAuth, String> {
        if !self.xites.contains_key(address) {
            let index = Self::address_auth_index(address);
            let auth_privatekey = epix_crypt::hd_privatekey(&self.master_seed, index)?;
            let auth_address = epix_crypt::privatekey_to_address(&auth_privatekey)?;
            self.xites.insert(
                address.to_string(),
                XiteAuth { auth_address, auth_privatekey, ..Default::default() },
            );
        }
        Ok(&self.xites[address])
    }

    /// Derive a brand-new owned-xite keypair from the master seed (EpixNet's
    /// `getNewSiteData`): a random index into `hd_privatekey`, recorded with
    /// the privatekey so publishes auto-sign. Returns (address, privatekey).
    pub fn new_xite_data(&mut self) -> Result<(String, String), String> {
        // Index from fresh key entropy (no extra RNG dependency).
        let entropy = epix_crypt::new_seed();
        let index = u64::from_str_radix(&entropy[..12], 16).map_err(|e| e.to_string())?
            % 100_000_000;
        let privatekey = epix_crypt::hd_privatekey(&self.master_seed, index)?;
        let address = epix_crypt::privatekey_to_address(&privatekey)?;
        if self.xites.contains_key(&address) {
            return Err("Random collision: xite already exists".into());
        }
        self.xite_data(&address)?;
        if let Some(auth) = self.xites.get_mut(&address) {
            auth.privatekey = Some(privatekey.clone());
        }
        Ok((address, privatekey))
    }

    // --- Identities ---------------------------------------------------------

    /// Every linked identity, in link order.
    pub fn identities(&self) -> &[Identity] {
        &self.identities
    }

    /// A held identity by its linked address.
    pub fn identity(&self, auth_address: &str) -> Option<&Identity> {
        self.identities.iter().find(|i| i.auth_address == auth_address)
    }

    /// A held identity by its xID name (`alice` or `alice.epix`).
    pub fn identity_by_name(&self, name: &str) -> Option<&Identity> {
        let name = name.trim().to_lowercase();
        let bare = name.strip_suffix(&format!(".{XID_TLD}")).unwrap_or(&name);
        self.identities.iter().find(|i| i.name == bare)
    }

    /// How `xite` resolves its identity.
    pub fn identity_scope(&self, xite: &str) -> IdentityScope {
        match self.xites.get(xite).and_then(|x| x.identity.as_deref()) {
            None => IdentityScope::Inherit,
            Some("") => IdentityScope::None,
            Some(_) => IdentityScope::Xite,
        }
    }

    /// The identity in effect for `xite`: its override if it has one, else the
    /// node-wide default. `None` means the xite is browsed anonymously.
    pub fn identity_for(&self, xite: &str) -> Option<&Identity> {
        match self.xites.get(xite).and_then(|x| x.identity.as_deref()) {
            Some("") => None,
            Some(addr) => self.identity(addr),
            None => self.default_identity.as_deref().and_then(|addr| self.identity(addr)),
        }
    }

    /// Set (or clear) the identity override for one xite. `None` inherits the
    /// default, `Some("")` is explicitly none, `Some(addr)` must be a held
    /// identity. Returns whether anything changed.
    pub fn select_identity(&mut self, xite: &str, choice: Option<&str>) -> Result<bool, String> {
        if let Some(addr) = choice {
            if !addr.is_empty() && self.identity(addr).is_none() {
                return Err(format!("unknown identity {addr}"));
            }
        }
        self.xite_data(xite)?;
        let entry = self.xites.get_mut(xite).expect("derived above");
        let next = choice.map(str::to_string);
        if entry.identity == next {
            return Ok(false);
        }
        entry.identity = next;
        Ok(true)
    }

    /// Set (or clear) the node-wide default identity. Returns whether it changed.
    pub fn set_default_identity(&mut self, auth_address: Option<&str>) -> Result<bool, String> {
        let next = match auth_address {
            Some(addr) if !addr.is_empty() => {
                if self.identity(addr).is_none() {
                    return Err(format!("unknown identity {addr}"));
                }
                Some(addr.to_string())
            }
            _ => None,
        };
        if self.default_identity == next {
            return Ok(false);
        }
        self.default_identity = next;
        Ok(true)
    }

    /// Record a linked identity. The private key for `auth_address` must be
    /// held (master, a xite key, or a minted `_identity_<n>` address). An
    /// existing identity for the address is updated in place (`Ok(false)`); a
    /// new one is appended (`Ok(true)`) and becomes the default when there was
    /// none.
    pub fn add_identity(
        &mut self,
        name: &str,
        auth_address: &str,
        cert_sign: &str,
        hd_index: Option<u64>,
    ) -> Result<bool, String> {
        let name = name.trim().to_lowercase();
        let name = name.strip_suffix(&format!(".{XID_TLD}")).unwrap_or(&name).to_string();
        if name.is_empty() {
            return Err("identity name is empty".into());
        }
        let auth_privatekey = self
            .privatekey_for(auth_address)
            .ok_or_else(|| format!("no private key held for {auth_address}"))?;
        let hd_index = hd_index.or_else(|| self.hd_index_of(auth_address));
        if let Some(existing) = self.identities.iter_mut().find(|i| i.auth_address == auth_address) {
            existing.name = name;
            existing.cert_sign = cert_sign.to_string();
            if existing.hd_index.is_none() {
                existing.hd_index = hd_index;
            }
            return Ok(false);
        }
        self.identities.push(Identity {
            auth_address: auth_address.to_string(),
            auth_privatekey,
            name,
            tld: XID_TLD.to_string(),
            cert_sign: cert_sign.to_string(),
            linked_at: Some(now_secs()),
            hd_index,
        });
        if self.default_identity.is_none() {
            self.default_identity = Some(auth_address.to_string());
        }
        Ok(true)
    }

    /// Forget a linked identity. Clears the default and any per-xite override
    /// that pointed at it. The minted `_identity_<n>` key entry stays, so the
    /// address can be re-linked later. Returns whether it existed.
    pub fn remove_identity(&mut self, auth_address: &str) -> bool {
        let before = self.identities.len();
        self.identities.retain(|i| i.auth_address != auth_address);
        if self.identities.len() == before {
            return false;
        }
        if self.default_identity.as_deref() == Some(auth_address) {
            self.default_identity = None;
        }
        for xite in self.xites.values_mut() {
            if xite.identity.as_deref() == Some(auth_address) {
                xite.identity = None;
            }
        }
        true
    }

    /// Minted identity addresses that are not (yet) linked identities - the
    /// candidates the link flow offers as "New".
    pub fn unlinked_identity_addresses(&self) -> Vec<String> {
        self.identity_addresses()
            .into_iter()
            .filter(|addr| self.identity(addr).is_none())
            .collect()
    }

    /// The wire `cert_user_id` (`name@xid.epix`) for `xite`, if it has an identity.
    pub fn cert_user_id(&self, xite: &str) -> Option<String> {
        self.identity_for(xite).map(Identity::cert_user_id)
    }

    /// The user-content directory name (`name.epix`) for `xite`, if it has an
    /// identity. Anonymous browsing has no directory.
    pub fn user_directory(&self, xite: &str) -> Option<String> {
        self.identity_for(xite).map(Identity::xid)
    }

    /// The identity address that signs user content on `xite`, or
    /// [`XID_REQUIRED`] when the xite has no identity.
    pub fn auth_address(&self, xite: &str) -> Result<String, String> {
        self.identity_for(xite)
            .map(|i| i.auth_address.clone())
            .ok_or_else(|| XID_REQUIRED.to_string())
    }

    /// The private key (WIF) that signs as [`Self::auth_address`], or
    /// [`XID_REQUIRED`] when the xite has no identity.
    pub fn auth_privatekey(&self, xite: &str) -> Result<String, String> {
        self.identity_for(xite)
            .map(|i| i.auth_privatekey.clone())
            .ok_or_else(|| XID_REQUIRED.to_string())
    }

    /// The identity rows a picker or `siteInfo` renders for `xite`:
    /// `{xid, name, tld, auth_address, directory, cert_user_id, selected,
    /// default, linked_at}`. `selected` marks the identity in effect for the
    /// xite, `default` the node-wide default.
    pub fn identity_list(&self, xite: &str) -> Vec<Value> {
        let selected = self.identity_for(xite).map(|i| i.auth_address.as_str());
        self.identities
            .iter()
            .map(|i| {
                serde_json::json!({
                    "xid": i.xid(),
                    "name": i.name,
                    "tld": i.tld,
                    "auth_address": i.auth_address,
                    "directory": i.xid(),
                    "cert_user_id": i.cert_user_id(),
                    "selected": selected == Some(i.auth_address.as_str()),
                    "default": self.default_identity.as_deref() == Some(i.auth_address.as_str()),
                    "linked_at": i.linked_at,
                })
            })
            .collect()
    }

    /// The per-xite CryptMessage **encryption** private key (WIF), derived like
    /// EpixNet's `getEncryptPrivatekey`:
    /// `hd_privatekey(master_seed, auth_index(address) + 1000 + index)`. When
    /// the xite has an identity the index is shifted by the xID provider
    /// domain's auth index, exactly as a selected `xid.epix` cert shifted it in
    /// schema 1 - so legacy mail encrypted to that key still decrypts here.
    pub fn encrypt_privatekey(&self, address: &str, param_index: u64) -> Result<String, String> {
        let index = if self.identity_for(address).is_some() {
            param_index + Self::address_auth_index(XID_CERT_DOMAIN)
        } else {
            param_index
        };
        let crypt_index = Self::address_auth_index(address) + 1000 + index;
        epix_crypt::hd_privatekey(&self.master_seed, crypt_index)
    }

    /// The per-xite settings a xite stored via `userSetSettings` (EpixNet's
    /// `xite_data["settings"]` - e.g. notification_seen baselines).
    pub fn xite_settings(&self, address: &str) -> Value {
        self.xites
            .get(address)
            .map(|s| Value::Object(s.settings.clone()))
            .unwrap_or_else(|| Value::Object(Default::default()))
    }

    /// Replace a xite's stored per-xite settings (`userSetSettings`).
    pub fn set_xite_settings(&mut self, address: &str, settings: Value) -> Result<(), String> {
        self.xite_data(address)?;
        if let Some(xite) = self.xites.get_mut(address) {
            xite.settings = settings.as_object().cloned().unwrap_or_default();
        }
        Ok(())
    }

    /// Save the xite's own private key (from recovery or user input). An empty
    /// key clears it - that is what the sidebar's "forget private key" sends,
    /// and storing `Some("")` would leave the xite still claiming to hold one.
    pub fn set_xite_privatekey(&mut self, address: &str, privatekey: &str) -> Result<(), String> {
        self.xite_data(address)?;
        if let Some(xite) = self.xites.get_mut(address) {
            xite.privatekey =
                if privatekey.is_empty() { None } else { Some(privatekey.to_string()) };
        }
        Ok(())
    }

    /// The saved xite private key, if any. An empty stored value is no key -
    /// users.json written before `set_xite_privatekey` cleared properly can
    /// still hold `""`, and every caller would otherwise try to sign with it.
    pub fn xite_privatekey(&self, address: &str) -> Option<String> {
        self.xites.get(address).and_then(|s| s.privatekey.clone()).filter(|k| !k.is_empty())
    }

    // --- Identity addresses (the minted `_identity_<n>` series) --------------

    /// The standalone identity addresses (`_identity_*` entries), in index
    /// order. These are the addresses a user links to xID names. Xite-derived
    /// auth addresses are not included.
    pub fn identity_addresses(&self) -> Vec<String> {
        let mut entries: Vec<(u64, String)> = self
            .xites
            .iter()
            .filter_map(|(key, s)| {
                let idx = key.strip_prefix("_identity_")?.parse::<u64>().ok()?;
                Some((idx, s.auth_address.clone()))
            })
            .collect();
        entries.sort_by_key(|(idx, _)| *idx);
        entries.into_iter().map(|(_, addr)| addr).collect()
    }

    /// The `_identity_<n>` HD index that minted `address`, if it is one.
    pub fn hd_index_of(&self, address: &str) -> Option<u64> {
        self.xites.iter().find_map(|(key, s)| {
            if s.auth_address != address {
                return None;
            }
            key.strip_prefix("_identity_")?.parse::<u64>().ok()
        })
    }

    /// The private key (WIF) for `address`: the master key, a xite/identity
    /// series key, or a linked identity's key. `None` if this user doesn't
    /// control it.
    pub fn privatekey_for(&self, address: &str) -> Option<String> {
        if address == self.master_address {
            return Some(self.master_seed.clone());
        }
        if let Some(s) = self.xites.values().find(|s| s.auth_address == address) {
            return Some(s.auth_privatekey.clone());
        }
        self.identity(address).map(|i| i.auth_privatekey.clone())
    }

    /// Generate a fresh standalone identity address from a dedicated index
    /// range, stored so its private key can be found later (for linking).
    /// Returns `(address, privatekey)`. Mirrors `generateNewIdentityAddress`.
    pub fn generate_new_identity_address(&mut self) -> Result<(String, String), String> {
        let index = self
            .settings
            .get("next_identity_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(IDENTITY_INDEX_START);
        let privatekey = epix_crypt::hd_privatekey(&self.master_seed, index)?;
        let address = epix_crypt::privatekey_to_address(&privatekey)?;
        // Store under a synthetic key so the link flow can find the private key.
        if !self.xites.values().any(|s| s.auth_address == address) {
            self.xites.insert(
                format!("_identity_{index}"),
                XiteAuth {
                    auth_address: address.clone(),
                    auth_privatekey: privatekey.clone(),
                    ..Default::default()
                },
            );
        }
        self.settings.insert("next_identity_index".to_string(), Value::from(index + 1));
        Ok((address, privatekey))
    }

    // --- Schema migration ---------------------------------------------------

    /// Upgrade a schema-1 user in place: the `xid.epix` cert slot becomes a
    /// linked identity (and the default when a xite had it selected), every
    /// per-xite `cert` domain is dropped, and dangling references are cleared.
    /// One-way and idempotent. Returns whether anything changed.
    pub fn migrate_legacy(&mut self) -> bool {
        let mut changed = false;

        // 1. xID certs -> identities.
        let xid_domains: Vec<String> = self
            .legacy_certs
            .iter()
            .filter(|(domain, cert)| domain.as_str() == XID_CERT_DOMAIN || cert.auth_type == "xid")
            .map(|(domain, _)| domain.clone())
            .collect();
        let mut migrated_default: Option<String> = None;
        for domain in &xid_domains {
            let Some(cert) = self.legacy_certs.get(domain).cloned() else { continue };
            if cert.auth_user_name.trim().is_empty() {
                // No name means no directory; leave the slot alone.
                continue;
            }
            if self.identity(&cert.auth_address).is_none() {
                let hd_index = self.hd_index_of(&cert.auth_address);
                self.identities.push(Identity {
                    auth_address: cert.auth_address.clone(),
                    auth_privatekey: cert.auth_privatekey.clone(),
                    name: cert.auth_user_name.trim().to_lowercase(),
                    tld: XID_TLD.to_string(),
                    cert_sign: cert.cert_sign.clone(),
                    linked_at: None,
                    hd_index,
                });
            }
            // A xite that had this cert selected made it the active identity.
            let selected_here = self
                .xites
                .iter()
                .any(|(addr, x)| !addr.starts_with("_identity_") && x.cert.as_deref() == Some(domain));
            if selected_here && migrated_default.is_none() {
                migrated_default = Some(cert.auth_address.clone());
            }
            self.legacy_certs.remove(domain);
            changed = true;
        }

        // 2. Default identity.
        if self.default_identity.is_none() {
            let candidate = migrated_default.or_else(|| {
                (self.identities.len() == 1).then(|| self.identities[0].auth_address.clone())
            });
            if candidate.is_some() {
                self.default_identity = candidate;
                changed = true;
            }
        }

        // 3. Drop the schema-1 per-xite cert domains.
        for xite in self.xites.values_mut() {
            if xite.cert.is_some() {
                xite.cert = None;
                changed = true;
            }
        }

        // 4. Dangling references.
        if let Some(addr) = self.default_identity.clone() {
            if self.identity(&addr).is_none() {
                self.default_identity = None;
                changed = true;
            }
        }
        let held: Vec<String> = self.identities.iter().map(|i| i.auth_address.clone()).collect();
        for xite in self.xites.values_mut() {
            if let Some(addr) = xite.identity.as_deref() {
                if !addr.is_empty() && !held.iter().any(|h| h == addr) {
                    xite.identity = None;
                    changed = true;
                }
            }
        }
        changed
    }

    // --- File IO (EpixNet-compatible users.json) ----------------------------

    /// This user as a single `users.json` entry object.
    fn to_file_entry(&self) -> Value {
        let mut entry = serde_json::json!({
            "schema_version": USERS_SCHEMA_VERSION,
            "master_seed": self.master_seed,
            "xites": self.xites,
            "identities": self.identities,
            "certs": self.legacy_certs,
            "settings": self.settings,
            "follows": self.follows,
        });
        if let Some(addr) = &self.default_identity {
            entry["default_identity"] = Value::from(addr.clone());
        }
        entry
    }

    /// Build a user from a `users.json` entry (its master address + the object).
    /// Returns the user and whether the schema migration changed anything.
    fn from_file_entry(master_address: &str, entry: &Value) -> Option<(Self, bool)> {
        let master_seed = entry.get("master_seed")?.as_str()?.to_string();
        // Written as `xites`; `sites` is the legacy name (older builds, and
        // Python EpixNet). Read either - the per-xite auth keys and certs in
        // here are not reproducible, so dropping them would lose identities.
        let xites_entry = entry.get("xites").or_else(|| entry.get("sites"));
        let xites = xites_entry
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let identities = entry
            .get("identities")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let default_identity = entry
            .get("default_identity")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let legacy_certs = entry
            .get("certs")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let settings = entry
            .get("settings")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        let mut follows: HashMap<String, Value> = entry
            .get("follows")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        // Migration: Python EpixNet stored Newsfeed follows per-xite
        // (`xites.<addr>.follow`), which the typed XiteAuth parse drops. Merge
        // them into our top-level map (ours wins on conflict) so a data dir
        // copied from the Python client keeps its dashboard feed.
        if let Some(xites_obj) = xites_entry.and_then(|v| v.as_object()) {
            for (addr, xite_data) in xites_obj {
                if let Some(f) = xite_data.get("follow") {
                    if f.is_object() && !follows.contains_key(addr) {
                        follows.insert(addr.clone(), f.clone());
                    }
                }
            }
        }
        let mut user = Self {
            master_seed,
            master_address: master_address.to_string(),
            xites,
            identities,
            default_identity,
            legacy_certs,
            settings,
            follows,
        };
        let changed = user.migrate_legacy();
        Some((user, changed))
    }

    /// Load the identity from a `users.json` file, or generate + save one if the
    /// file is absent or holds no usable identity. Takes the first entry (this
    /// node runs one identity; Multiuser switches among several by master seed).
    /// A schema-1 entry is migrated and written back once.
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(Value::Object(users)) = serde_json::from_slice::<Value>(&bytes) {
                for (master_address, entry) in &users {
                    if let Some((user, migrated)) = Self::from_file_entry(master_address, entry) {
                        // A seed-derived master address must match its key, or
                        // the file is corrupt for that entry - skip it.
                        if epix_crypt::privatekey_to_address(&user.master_seed).as_deref()
                            == Ok(master_address)
                        {
                            if migrated {
                                user.save(path)?;
                            }
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
        let mut users: Map<String, Value> = match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(Value::Object(users)) => users,
                Ok(_) => return Err(format!("read {}: users file is not an object", path.display())),
                Err(error) => return Err(format!("parse {}: {error}", path.display())),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Map::new(),
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        };
        users.insert(self.master_address.clone(), self.to_file_entry());
        let bytes = serde_json::to_vec_pretty(&Value::Object(users))
            .map_err(|e| format!("serialize user: {e}"))?;
        let parent = path.parent().ok_or_else(|| {
            format!("write {}: destination has no parent", path.display())
        })?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| format!("create temporary {}: {e}", path.display()))?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|e| format!("write temporary {}: {e}", path.display()))?;
        let temporary = temporary.into_temp_path();
        epix_fs::replace_file_write_through(temporary.as_ref(), path)
            .map_err(|e| format!("durably replace {}: {e}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "5f5e100000000000000000000000000000000000000000000000000000000001";

    /// Mint an identity address and link it as `name`.
    fn link(u: &mut User, name: &str) -> String {
        let (addr, _pk) = u.generate_new_identity_address().unwrap();
        assert!(u.add_identity(name, &addr, "sig", None).unwrap());
        addr
    }

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
    fn derived_xite_key_is_deterministic_and_per_xite() {
        let mut u = User::from_seed(SEED).unwrap();
        let a1 = u.xite_data("talk.epix").unwrap().clone();
        let a2 = u.xite_data("blog.epix").unwrap().clone();
        assert!(a1.auth_address.starts_with("epix1"));
        assert!(a2.auth_address.starts_with("epix1"));
        assert_ne!(a1.auth_address, a2.auth_address, "different xite -> different key");
        assert_eq!(a1.identity, None, "a fresh xite inherits the default identity");

        let mut u2 = User::from_seed(SEED).unwrap();
        assert_eq!(u2.xite_data("talk.epix").unwrap().auth_address, a1.auth_address);
    }

    #[test]
    fn no_identity_means_read_only() {
        let mut u = User::generate();
        u.xite_data("talk.epix").unwrap();
        assert_eq!(u.auth_address("talk.epix").unwrap_err(), XID_REQUIRED);
        assert_eq!(u.auth_privatekey("talk.epix").unwrap_err(), XID_REQUIRED);
        assert_eq!(u.cert_user_id("talk.epix"), None);
        assert_eq!(u.user_directory("talk.epix"), None);
        assert!(u.identity_for("talk.epix").is_none());
        assert_eq!(u.identity_scope("talk.epix"), IdentityScope::Inherit);
        assert!(u.identity_list("talk.epix").is_empty());
    }

    #[test]
    fn add_and_select_identity() {
        let mut u = User::generate();
        let alice = link(&mut u, "alice");
        // The first identity becomes the default and applies to every xite.
        assert_eq!(u.default_identity.as_deref(), Some(alice.as_str()));
        assert_eq!(u.auth_address("talk.epix").unwrap(), alice);
        assert_eq!(u.auth_address("blog.epix").unwrap(), alice);
        assert_eq!(u.cert_user_id("talk.epix").as_deref(), Some("alice@xid.epix"));
        assert_eq!(u.user_directory("talk.epix").as_deref(), Some("alice.epix"));
        assert_eq!(u.auth_privatekey("talk.epix").unwrap(), u.privatekey_for(&alice).unwrap());

        // Re-adding updates in place and does not duplicate.
        assert!(!u.add_identity("Alice.epix", &alice, "sig2", None).unwrap());
        assert_eq!(u.identities().len(), 1);
        assert_eq!(u.identity(&alice).unwrap().cert_sign, "sig2");
        assert_eq!(u.identity(&alice).unwrap().name, "alice");
        assert!(u.identity(&alice).unwrap().hd_index.is_some(), "minted index recorded");

        // A second identity does not change the default.
        let bob = link(&mut u, "bob");
        assert_eq!(u.default_identity.as_deref(), Some(alice.as_str()));
        assert_eq!(u.identities().len(), 2);
        assert_eq!(u.identity_by_name("bob.epix").unwrap().auth_address, bob);

        // Linking needs a held key.
        assert!(u.add_identity("carol", "epix1nobody", "sig", None).is_err());
        assert!(u.add_identity("", &bob, "sig", None).is_err());
    }

    #[test]
    fn per_xite_override_and_explicit_none() {
        let mut u = User::generate();
        let alice = link(&mut u, "alice");
        let bob = link(&mut u, "bob");

        // Talk uses bob, everything else keeps the default (alice).
        assert!(u.select_identity("talk.epix", Some(&bob)).unwrap());
        assert_eq!(u.identity_scope("talk.epix"), IdentityScope::Xite);
        assert_eq!(u.auth_address("talk.epix").unwrap(), bob);
        assert_eq!(u.auth_address("blog.epix").unwrap(), alice);
        assert!(!u.select_identity("talk.epix", Some(&bob)).unwrap(), "no change");

        // Explicit none browses anonymously despite the default.
        assert!(u.select_identity("wiki.epix", Some("")).unwrap());
        assert_eq!(u.identity_scope("wiki.epix"), IdentityScope::None);
        assert_eq!(u.auth_address("wiki.epix").unwrap_err(), XID_REQUIRED);
        assert_eq!(u.user_directory("wiki.epix"), None);

        // Back to inheriting.
        assert!(u.select_identity("wiki.epix", None).unwrap());
        assert_eq!(u.identity_scope("wiki.epix"), IdentityScope::Inherit);
        assert_eq!(u.auth_address("wiki.epix").unwrap(), alice);

        // Unknown identities are refused.
        assert!(u.select_identity("talk.epix", Some("epix1nobody")).is_err());
        assert!(u.set_default_identity(Some("epix1nobody")).is_err());

        // Changing the default moves every inheriting xite, not the override.
        assert!(u.set_default_identity(Some(&bob)).unwrap());
        assert_eq!(u.auth_address("blog.epix").unwrap(), bob);
        assert_eq!(u.auth_address("talk.epix").unwrap(), bob);
        assert!(u.set_default_identity(None).unwrap());
        assert_eq!(u.auth_address("blog.epix").unwrap_err(), XID_REQUIRED);
        assert_eq!(u.auth_address("talk.epix").unwrap(), bob, "override survives");
    }

    #[test]
    fn identity_list_marks_selected_and_default() {
        let mut u = User::generate();
        let alice = link(&mut u, "alice");
        let bob = link(&mut u, "bob");
        u.select_identity("talk.epix", Some(&bob)).unwrap();

        let list = u.identity_list("talk.epix");
        assert_eq!(list.len(), 2);
        let row = |addr: &str| list.iter().find(|r| r["auth_address"] == addr).unwrap().clone();
        assert_eq!(row(&alice)["selected"], false);
        assert_eq!(row(&alice)["default"], true);
        assert_eq!(row(&bob)["selected"], true);
        assert_eq!(row(&bob)["default"], false);
        assert_eq!(row(&bob)["xid"], "bob.epix");
        assert_eq!(row(&bob)["cert_user_id"], "bob@xid.epix");
        assert_eq!(row(&bob)["directory"], "bob.epix");

        // On an inheriting xite the default is the selected one.
        let list = u.identity_list("blog.epix");
        assert_eq!(list.iter().find(|r| r["auth_address"] == alice).unwrap()["selected"], true);
    }

    #[test]
    fn remove_identity_clears_default_and_overrides() {
        let mut u = User::generate();
        let alice = link(&mut u, "alice");
        let bob = link(&mut u, "bob");
        u.select_identity("talk.epix", Some(&bob)).unwrap();
        u.set_default_identity(Some(&bob)).unwrap();

        assert!(u.remove_identity(&bob));
        assert!(!u.remove_identity(&bob), "already gone");
        assert_eq!(u.identities().len(), 1);
        assert_eq!(u.default_identity, None, "default cleared, not reassigned");
        assert_eq!(u.identity_scope("talk.epix"), IdentityScope::Inherit, "override cleared");
        assert_eq!(u.auth_address("talk.epix").unwrap_err(), XID_REQUIRED);
        // The minted key stays, so bob can be re-linked.
        assert!(u.privatekey_for(&bob).is_some());
        assert_eq!(u.unlinked_identity_addresses(), vec![bob.clone()]);
        assert!(u.add_identity("bob", &bob, "sig", None).unwrap());
        let _ = alice;
    }

    #[test]
    fn encrypt_key_shifts_when_an_identity_is_selected() {
        // Schema 1 shifted the derivation index by the `xid.epix` domain's auth
        // index whenever the xID cert was selected. The same shift applies
        // whenever the xite has an identity, so legacy mail still decrypts.
        let mut u = User::from_seed(SEED).unwrap();
        u.xite_data("talk.epix").unwrap();
        let plain = u.encrypt_privatekey("talk.epix", 0).unwrap();
        let expected_plain =
            epix_crypt::hd_privatekey(SEED, User::address_auth_index("talk.epix") + 1000).unwrap();
        assert_eq!(plain, expected_plain);

        link(&mut u, "alice");
        let certified = u.encrypt_privatekey("talk.epix", 0).unwrap();
        let expected_certified = epix_crypt::hd_privatekey(
            SEED,
            User::address_auth_index("talk.epix") + 1000 + User::address_auth_index("xid.epix"),
        )
        .unwrap();
        assert_eq!(certified, expected_certified);
        assert_ne!(plain, certified);

        // Two identities share the one legacy encryption key (Python parity).
        let bob = link(&mut u, "bob");
        u.select_identity("talk.epix", Some(&bob)).unwrap();
        assert_eq!(u.encrypt_privatekey("talk.epix", 0).unwrap(), certified);
    }

    #[test]
    fn new_identity_uses_dedicated_index_range() {
        let mut u = User::generate();
        let (addr, _pk) = u.generate_new_identity_address().unwrap();
        assert!(addr.starts_with("epix1"));
        // The index advanced.
        assert_eq!(u.settings["next_identity_index"], 100_000_002);
        // Stored so the link flow can bind to it.
        assert!(u.xites.values().any(|s| s.auth_address == addr));
        assert_eq!(u.hd_index_of(&addr), Some(100_000_001));
        assert_eq!(u.unlinked_identity_addresses(), vec![addr]);
    }

    #[test]
    fn identity_addresses_are_ordered_and_exclude_xite_auths() {
        let mut u = User::generate();
        // A xite-derived auth key (not an identity).
        u.xite_data("talk.epix").unwrap();
        let xite_auth = u.xites["talk.epix"].auth_address.clone();
        // Two standalone identities, minted in order.
        let (id1, pk1) = u.generate_new_identity_address().unwrap();
        let (id2, _pk2) = u.generate_new_identity_address().unwrap();

        let ids = u.identity_addresses();
        assert_eq!(ids, vec![id1.clone(), id2.clone()], "identity order by index");
        assert!(!ids.contains(&xite_auth), "xite auth is not an identity");

        // privatekey_for finds identity keys, the xite auth key, and master.
        assert_eq!(u.privatekey_for(&id1).as_deref(), Some(pk1.as_str()));
        assert_eq!(
            u.privatekey_for(&xite_auth).as_deref(),
            Some(u.xites["talk.epix"].auth_privatekey.as_str())
        );
        assert_eq!(u.privatekey_for(&u.master_address).as_deref(), Some(u.master_seed.as_str()));
        assert_eq!(u.privatekey_for("epix1nope"), None);

        // Linking one leaves the other as the "New" candidate.
        u.add_identity("alice", &id1, "sig", None).unwrap();
        assert_eq!(u.unlinked_identity_addresses(), vec![id2]);
    }

    #[test]
    fn users_json_is_python_keyed_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.json");
        let mut u = User::generate();
        u.xite_data("talk.epix").unwrap();
        let alice = link(&mut u, "alice");
        let bob = link(&mut u, "bob");
        u.select_identity("talk.epix", Some(&bob)).unwrap();
        u.select_identity("wiki.epix", Some("")).unwrap();
        u.save(&path).unwrap();

        // The file is keyed by master address, with identities at the top level.
        let raw: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let entry = &raw[&u.master_address];
        assert_eq!(entry["schema_version"], 2);
        assert_eq!(entry["master_seed"], u.master_seed);
        assert_eq!(entry["identities"][0]["name"], "alice");
        assert_eq!(entry["identities"][1]["name"], "bob");
        assert_eq!(entry["default_identity"], alice);
        assert_eq!(entry["xites"]["talk.epix"]["identity"], bob);
        assert_eq!(entry["xites"]["wiki.epix"]["identity"], "");
        assert!(entry["xites"]["blog.epix"].is_null());
        assert!(entry["certs"].as_object().unwrap().is_empty(), "no legacy cert slot written");
        assert!(entry["xites"]["talk.epix"].get("cert").is_none(), "no per-xite cert written");

        let loaded = User::load_or_create(&path).unwrap();
        assert_eq!(loaded.master_seed, u.master_seed);
        assert_eq!(loaded.cert_user_id("talk.epix").as_deref(), Some("bob@xid.epix"));
        assert_eq!(loaded.cert_user_id("blog.epix").as_deref(), Some("alice@xid.epix"));
        assert_eq!(loaded.cert_user_id("wiki.epix"), None);
        assert_eq!(loaded.default_identity.as_deref(), Some(alice.as_str()));
    }

    #[test]
    fn legacy_users_json_migrates_certs_and_cert_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.json");
        // A schema-1 file as written by an older node: one minted identity
        // address, the single xid.epix cert bound to it, selected on every
        // xite, plus a non-xID provider cert that must survive untouched.
        let mut seed_user = User::from_seed(SEED).unwrap();
        let (linked, linked_key) = seed_user.generate_new_identity_address().unwrap();
        seed_user.xite_data("talk.epix").unwrap();
        let talk = seed_user.xites["talk.epix"].clone();
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                seed_user.master_address.clone(): {
                    "master_seed": SEED,
                    "sites": {
                        "talk.epix": {
                            "auth_address": talk.auth_address, "auth_privatekey": talk.auth_privatekey,
                            "cert": "xid.epix"
                        },
                        "blog.epix": {
                            "auth_address": "epix1blog", "auth_privatekey": "k", "cert": "xid.epix"
                        },
                        "_identity_100000001": {
                            "auth_address": linked, "auth_privatekey": linked_key
                        }
                    },
                    "certs": {
                        "xid.epix": {
                            "auth_address": linked, "auth_privatekey": linked_key,
                            "auth_type": "xid", "auth_user_name": "Facts", "cert_sign": "legacy-sign"
                        },
                        "certs.epix": {
                            "auth_address": talk.auth_address, "auth_privatekey": talk.auth_privatekey,
                            "auth_type": "web", "auth_user_name": "tester", "cert_sign": "web-sign"
                        }
                    },
                    "settings": { "next_identity_index": 100000002 }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let loaded = User::load_or_create(&path).unwrap();
        assert_eq!(loaded.identities().len(), 1);
        let id = &loaded.identities()[0];
        assert_eq!(id.name, "facts", "name lowercased");
        assert_eq!(id.auth_address, linked);
        assert_eq!(id.auth_privatekey, linked_key);
        assert_eq!(id.cert_sign, "legacy-sign");
        assert_eq!(id.hd_index, Some(100_000_001));
        assert_eq!(loaded.default_identity.as_deref(), Some(linked.as_str()));
        // Every xite that had the cert selected now inherits the default.
        assert_eq!(loaded.identity_scope("talk.epix"), IdentityScope::Inherit);
        assert_eq!(loaded.auth_address("talk.epix").unwrap(), linked);
        assert_eq!(loaded.user_directory("blog.epix").as_deref(), Some("facts.epix"));
        assert!(loaded.xites["talk.epix"].cert.is_none());
        // The non-xID cert is carried through.
        assert_eq!(loaded.legacy_certs["certs.epix"].auth_user_name, "tester");
        assert!(!loaded.legacy_certs.contains_key("xid.epix"));

        // The upgrade was written back once and a second load is a no-op.
        let raw: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let entry = &raw[&loaded.master_address];
        assert_eq!(entry["schema_version"], 2);
        assert!(entry["certs"].get("xid.epix").is_none());
        assert!(entry["certs"].get("certs.epix").is_some());
        assert!(entry["xites"]["talk.epix"].get("cert").is_none());
        assert_eq!(entry["settings"]["next_identity_index"], 100000002);
        let mut again = User::load_or_create(&path).unwrap();
        assert!(!again.migrate_legacy(), "idempotent");
        assert_eq!(again.identities().len(), 1);

        // Removing the migrated identity and reloading stays removed (no
        // compat slot is ever written back).
        again.remove_identity(&linked);
        again.save(&path).unwrap();
        let third = User::load_or_create(&path).unwrap();
        assert!(third.identities().is_empty());
        assert_eq!(third.default_identity, None);
    }

    #[test]
    fn user_struct_round_trips_through_serde() {
        // The multiuser store serializes `User` with the derive directly.
        let mut u = User::generate();
        let alice = link(&mut u, "alice");
        u.select_identity("talk.epix", Some("")).unwrap();
        let json = serde_json::to_value(&u).unwrap();
        assert_eq!(json["identities"][0]["auth_address"], alice);
        assert_eq!(json["default_identity"], alice);
        assert!(json["certs"].is_object());
        let back: User = serde_json::from_value(json).unwrap();
        assert_eq!(back.identities(), u.identities());
        assert_eq!(back.identity_scope("talk.epix"), IdentityScope::None);
        // Older stores without the new fields still parse.
        let old: User = serde_json::from_value(serde_json::json!({
            "master_seed": u.master_seed, "master_address": u.master_address,
            "xites": {}, "certs": {}, "settings": {}, "follows": {}
        }))
        .unwrap();
        assert!(old.identities().is_empty());
    }

    #[test]
    fn python_per_xite_follows_migrate_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.json");
        // A Python-style users.json: follows live inside each xite entry, and
        // one address also has a Rust-style top-level follow that must win.
        let seed_user = User::generate();
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                seed_user.master_address.clone(): {
                    "master_seed": seed_user.master_seed,
                    "sites": {
                        "epix1talk": {
                            "auth_address": "a", "auth_privatekey": "k",
                            "follow": { "Topics": ["SELECT 1", ""] }
                        },
                        "epix1mail": {
                            "auth_address": "b", "auth_privatekey": "k",
                            "follow": { "Old mail": ["SELECT 2", ""] }
                        }
                    },
                    "certs": {}, "settings": {},
                    "follows": { "epix1mail": { "New conversations": ["SELECT 3", ""] } }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let loaded = User::load_or_create(&path).unwrap();
        // Python-only follow migrated; the Rust-style entry wins its conflict.
        assert!(loaded.follows["epix1talk"].get("Topics").is_some(), "python follow migrated");
        assert!(
            loaded.follows["epix1mail"].get("New conversations").is_some(),
            "rust follow kept over the python one"
        );
        assert!(loaded.follows["epix1mail"].get("Old mail").is_none());
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
        u.xite_data("talk.epix").unwrap();
        u.save(&path).unwrap();

        // Both identities are present after save.
        let raw: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(raw.get(&other.master_address).is_some(), "other user preserved");
        assert!(raw.get(&u.master_address).is_some(), "our user saved");
    }
}
