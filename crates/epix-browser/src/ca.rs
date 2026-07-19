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

use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, Issuer, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// The local CA: the key and the CA cert, both persisted and reused unchanged
/// across launches, used to sign per-host leaf certs and to inject into
/// Firefox's trust.
pub struct LocalCa {
    ca_key: KeyPair,
    // The CA cert, generated once and reused (persisted as PEM). Its bytes never
    // change across launches - see load_or_create for why that matters.
    ca_cert_pem: String,
    ca_cert_der: CertificateDer<'static>,
}

impl LocalCa {
    /// Load the CA key from `dir/ca-key.pem` and the CA cert from
    /// `dir/ca-cert.pem`, generating and persisting each once on first run and
    /// reusing the same bytes forever after.
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

        // Generate the CA cert ONCE, then reuse the persisted bytes. Regenerating
        // it each launch minted a fresh serial and a fresh (randomized) ECDSA
        // signature - so a different fingerprint every run - which forced
        // certutil to re-sync Firefox's cert9.db on every launch. If that sync
        // raced with Firefox reading the DB (or an old Firefox lingered), Firefox
        // trusted a different CA cert than the proxy served and showed
        // SEC_ERROR_UNKNOWN_ISSUER ("Potential Security Risk Ahead"). A stable
        // cert is added to the trust store once and can never diverge from what
        // the proxy presents.
        let cert_path = dir.join("ca-cert.pem");
        let ca_cert_pem = match std::fs::read_to_string(&cert_path) {
            Ok(pem) if pem.contains("BEGIN CERTIFICATE") => pem,
            _ => {
                let cert = Self::ca_params()?
                    .self_signed(&ca_key)
                    .map_err(|e| format!("ca self-sign: {e}"))?;
                let pem = cert.pem();
                std::fs::write(&cert_path, &pem).map_err(|e| format!("write ca cert: {e}"))?;
                pem
            }
        };
        let ca_cert_der = pem_to_der(&ca_cert_pem)?;
        Ok(Self { ca_key, ca_cert_pem, ca_cert_der })
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
        self.ca_cert_pem.clone()
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
        let ca_der: CertificateDer<'static> = self.ca_cert_der.clone();
        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| format!("leaf key der: {e}"))?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| format!("signing key: {e}"))?;
        // Send the leaf + our CA so Firefox builds the chain to its trusted root.
        Ok(CertifiedKey::new(vec![leaf_der, ca_der], signing_key))
    }
}

/// Decode a single PEM certificate block into DER (rcgen emits PEM but can't
/// re-parse it, so we strip the armor and base64-decode the body ourselves).
fn pem_to_der(pem: &str) -> Result<CertificateDer<'static>, String> {
    let body: String = pem.lines().filter(|l| !l.contains("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| format!("decode ca cert: {e}"))?;
    Ok(CertificateDer::from(der))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CA cert must be byte-identical across loads. The previous code
    /// regenerated it each launch (new serial + randomized ECDSA signature), so
    /// its fingerprint changed every run and forced certutil to re-sync Firefox's
    /// trust store - a race that produced SEC_ERROR_UNKNOWN_ISSUER.
    #[test]
    fn ca_cert_is_stable_across_loads() {
        // Securely-created unique temp dir (auto-removed on drop).
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();

        let first = LocalCa::load_or_create(dir).expect("first load");
        let second = LocalCa::load_or_create(dir).expect("second load reuses persisted cert");

        assert_eq!(first.cert_pem(), second.cert_pem(), "CA PEM changed across loads");
        assert_eq!(first.ca_cert_der, second.ca_cert_der, "CA DER changed across loads");
        // The reused DER must match what we persisted on disk.
        let on_disk = std::fs::read_to_string(dir.join("ca-cert.pem")).unwrap();
        assert_eq!(pem_to_der(&on_disk).unwrap(), second.ca_cert_der);
        // A freshly minted leaf still chains to the reused CA (issuer name + key).
        let leaf = second.leaf_for("dashboard.epix").expect("leaf mint");
        assert_eq!(leaf.cert.len(), 2, "leaf chain should be [leaf, ca]");
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
