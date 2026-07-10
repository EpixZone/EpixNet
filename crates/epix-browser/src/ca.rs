//! A per-install local certificate authority for `*.epix` secure origins.
//!
//! On first run we generate a CA key, persisted under the data dir so it is
//! stable across launches. Firefox is told to trust this CA (see the cert-trust
//! injection in `main`, re-run each launch and idempotent by nickname). The TLS
//! proxy then mints a leaf certificate for each `*.epix` host on demand, signed
//! by the CA, so Firefox sees a valid `https://dashboard.epix/` - a real secure
//! context (service workers, `crypto.subtle`), no warning.
//!
//! rcgen can generate but not re-parse certs, so we persist only the CA key and
//! regenerate the CA cert from it each launch (same key + subject, so any leaf
//! we sign validates against the trusted copy regardless of serial).

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, Issuer, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// The local CA: the key (persisted) plus the regenerated CA cert used to sign
/// per-host leaf certs and to inject into Firefox's trust.
pub struct LocalCa {
    ca_key: KeyPair,
    ca_cert: Certificate,
}

impl LocalCa {
    /// Load the CA key from `dir/ca-key.pem` (generating + persisting it on
    /// first run) and regenerate the CA cert from it.
    pub fn load_or_create(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("ca dir: {e}"))?;
        let key_path = dir.join("ca-key.pem");

        let ca_key = match std::fs::read_to_string(&key_path) {
            Ok(pem) => KeyPair::from_pem(&pem).map_err(|e| format!("parse ca key: {e}"))?,
            Err(_) => {
                let key = KeyPair::generate().map_err(|e| format!("ca key: {e}"))?;
                std::fs::write(&key_path, key.serialize_pem())
                    .map_err(|e| format!("write ca key: {e}"))?;
                key
            }
        };
        let ca_cert = Self::ca_params()?
            .self_signed(&ca_key)
            .map_err(|e| format!("ca self-sign: {e}"))?;
        // Persist the cert too (handy for humans / other tools).
        let _ = std::fs::write(dir.join("ca-cert.pem"), ca_cert.pem());
        Ok(Self { ca_key, ca_cert })
    }

    fn ca_params() -> Result<CertificateParams, String> {
        let mut params =
            CertificateParams::new(Vec::new()).map_err(|e| format!("ca params: {e}"))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, "Epix Local CA");
        params.distinguished_name.push(DnType::OrganizationName, "EpixNet");
        Ok(params)
    }

    /// The CA certificate as PEM (what we install into Firefox's trust store).
    pub fn cert_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// Mint a leaf certificate for `host`, signed by this CA.
    fn leaf_for(&self, host: &str) -> Result<CertifiedKey, String> {
        let leaf_key = KeyPair::generate().map_err(|e| format!("leaf key: {e}"))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("leaf params: {e}"))?;
        params.distinguished_name.push(DnType::CommonName, host);
        // rcgen 0.14 signs against an Issuer (CA params + key) rather than the
        // CA cert + key directly. Rebuild it from the same deterministic params.
        let ca_params = Self::ca_params()?;
        let issuer = Issuer::from_params(&ca_params, &self.ca_key);
        let leaf = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| format!("sign leaf: {e}"))?;

        let leaf_der = leaf.der().clone();
        let ca_der: CertificateDer<'static> = self.ca_cert.der().clone();
        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| format!("leaf key der: {e}"))?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| format!("signing key: {e}"))?;
        // Send the leaf + our CA so Firefox builds the chain to its trusted root.
        Ok(CertifiedKey::new(vec![leaf_der, ca_der], signing_key))
    }
}

/// A rustls cert resolver that mints (and caches) a leaf per SNI host on the
/// fly, so any `*.epix` host gets a valid cert without pre-provisioning.
#[derive(Clone)]
pub struct EpixCertResolver {
    ca: Arc<LocalCa>,
    cache: Arc<Mutex<HashMap<String, Arc<CertifiedKey>>>>,
}

impl EpixCertResolver {
    pub fn new(ca: Arc<LocalCa>) -> Self {
        Self { ca, cache: Arc::new(Mutex::new(HashMap::new())) }
    }

    fn cert_for(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(k) = self.cache.lock().unwrap().get(host) {
            return Some(k.clone());
        }
        let key = Arc::new(self.ca.leaf_for(host).ok()?);
        self.cache.lock().unwrap().insert(host.to_string(), key.clone());
        Some(key)
    }
}

impl std::fmt::Debug for EpixCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpixCertResolver")
    }
}

impl ResolvesServerCert for EpixCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let host = client_hello.server_name().unwrap_or("epix").to_string();
        self.cert_for(&host)
    }
}
