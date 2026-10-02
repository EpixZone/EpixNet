//! Grants, checkpoints and the two-phase activation loader.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsFd as _;
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use evx_api::grant::ActivationContext;
use evx_api::Capability;
use serde::{Deserialize, Serialize};

use crate::capture::{self, CaptureFn};
use crate::envelope::{self, field, Object};
use crate::{digest, AuthenticationError, MAX_FILES, MAX_TOTAL};

const KIND: &str = "evx.activation.v1";
const BODY_KEYS: &[&str] = &[
    "kind",
    "xite",
    "publisher",
    "version",
    "runtime_profile",
    "entry",
    "artifact_format",
    "files",
    "capabilities",
];
/// Most capabilities one activation may declare.
const MAX_CAPABILITIES: usize = 64;
const WASM_MAGIC: &[u8] = b"\0asm\x01\0\0\0";

/// Host-issued authority for one xite: who may publish code for it, which
/// capabilities and runtime profiles that code may declare, and whether it
/// may run at all. An accepted code update never replaces its grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XiteGrant {
    /// The xite this grant covers.
    pub xite: String,
    /// The publisher whose signatures activate code for the xite.
    pub publisher: String,
    /// Raw Ed25519 public key of the publisher.
    pub public_key: [u8; 32],
    /// Capabilities an activation may declare; declarations must be a subset.
    pub capabilities: BTreeSet<Capability>,
    /// Runtime profiles an activation may select.
    pub runtime_profiles: BTreeSet<String>,
    /// Authority generation; changes whenever the authority changes.
    pub generation: u64,
    /// Whether the xite may execute at all.
    pub enabled: bool,
}

impl XiteGrant {
    /// Build an enabled generation-1 grant, validating the identifiers and
    /// that `public_key` is a well-formed Ed25519 key.
    pub fn new(
        xite: impl Into<String>,
        publisher: impl Into<String>,
        public_key: [u8; 32],
        capabilities: BTreeSet<Capability>,
        runtime_profiles: BTreeSet<String>,
    ) -> Result<Self, AuthenticationError> {
        let xite = xite.into();
        let publisher = publisher.into();
        for value in [&xite, &publisher] {
            evx_api::validate_identifier(value)
                .map_err(|_| AuthenticationError::new("invalid fixture identifier"))?;
        }
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| AuthenticationError::new("invalid Ed25519 public key"))?;
        Ok(XiteGrant {
            xite,
            publisher,
            public_key,
            capabilities,
            runtime_profiles,
            generation: 1,
            enabled: true,
        })
    }

    /// Set the authority generation; must be in `1..=2**63-1`.
    pub fn with_generation(mut self, generation: u64) -> Result<Self, AuthenticationError> {
        self.generation = envelope::positive_u64(generation)?;
        Ok(self)
    }

    /// Enable or disable execution.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// The version floor for one xite: the highest admitted version and the
/// manifest digest admitted at that version. The host persists it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCheckpoint {
    /// Highest admitted version, or 0 when nothing has been admitted.
    pub version: u64,
    /// Manifest digest admitted at `version`, if any.
    pub manifest_digest: Option<String>,
}

impl ActivationCheckpoint {
    /// Build a checkpoint from persisted values.
    pub fn new(version: u64, manifest_digest: Option<String>) -> Self {
        ActivationCheckpoint {
            version,
            manifest_digest,
        }
    }

    /// Whether an activation at `version` with `manifest_digest` is neither a
    /// rollback nor a conflicting manifest at the current version.
    fn admits(&self, version: u64, manifest_digest: &str) -> bool {
        if version < self.version {
            return false;
        }
        version != self.version || self.manifest_digest.as_deref() == Some(manifest_digest)
    }
}

fn rollback() -> AuthenticationError {
    AuthenticationError::new("activation rollback or version conflict")
}

/// The closed set of artifact encodings an activation may declare. Native or
/// engine-serialized caches are never accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactFormat {
    /// WebAssembly text; every captured file must start with `(module`.
    Wat,
    /// Core WebAssembly binary; every captured file must carry the
    /// `\0asm` version-1 magic.
    WasmCoreV1,
}

impl ArtifactFormat {
    /// The name used in signed bodies.
    pub fn name(self) -> &'static str {
        match self {
            ArtifactFormat::Wat => "wat",
            ArtifactFormat::WasmCoreV1 => "wasm-core-v1",
        }
    }

    /// Parse a declared format name; anything else is unsupported.
    pub fn parse(name: &str) -> Option<ArtifactFormat> {
        match name {
            "wat" => Some(ArtifactFormat::Wat),
            "wasm-core-v1" => Some(ArtifactFormat::WasmCoreV1),
            _ => None,
        }
    }

    fn check(self, data: &[u8]) -> Result<(), AuthenticationError> {
        match self {
            ArtifactFormat::WasmCoreV1 => {
                if !data.starts_with(WASM_MAGIC) {
                    return Err(AuthenticationError::new("not a core Wasm artifact"));
                }
            }
            ArtifactFormat::Wat => {
                let text = std::str::from_utf8(data)
                    .map_err(|_| AuthenticationError::new("invalid WAT encoding"))?;
                if !text.trim_start().starts_with("(module") {
                    return Err(AuthenticationError::new("not a fixture WAT module"));
                }
            }
        }
        Ok(())
    }
}

/// An admitted activation: the signed manifest and every captured file,
/// immutable for the lifetime of the value. There is no key material here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenActivation {
    xite: String,
    publisher: String,
    grant_generation: u64,
    version: u64,
    runtime_profile: String,
    artifact_format: ArtifactFormat,
    capabilities: BTreeSet<Capability>,
    manifest_digest: String,
    manifest_bytes: Vec<u8>,
    entry: String,
    files: BTreeMap<String, Vec<u8>>,
}

impl FrozenActivation {
    /// The xite named by the grant and the signed body.
    pub fn xite(&self) -> &str {
        &self.xite
    }

    /// The publisher named by the grant and the signed body.
    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    /// Generation of the grant the activation was verified under.
    pub fn grant_generation(&self) -> u64 {
        self.grant_generation
    }

    /// Signed version.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Signed runtime profile, already checked against the grant.
    pub fn runtime_profile(&self) -> &str {
        &self.runtime_profile
    }

    /// Signed artifact format.
    pub fn artifact_format(&self) -> ArtifactFormat {
        self.artifact_format
    }

    /// Declared capabilities, already checked to be within the grant.
    pub fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }

    /// SHA-256 of the canonical signed body.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// The canonical signed body bytes.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Relative path of the entry artifact within the closure.
    pub fn entry(&self) -> &str {
        &self.entry
    }

    /// Relative paths of every captured file, in sorted order.
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// The captured bytes of the entry artifact.
    pub fn entry_bytes(&self) -> &[u8] {
        self.files.get(&self.entry).map_or(&[], Vec::as_slice)
    }

    /// The captured bytes of one file in the signed closure.
    pub fn artifact_bytes(&self, path: &str) -> Result<&[u8], AuthenticationError> {
        self.files
            .get(path)
            .map(Vec::as_slice)
            .ok_or_else(|| AuthenticationError::new("artifact absent from captured closure"))
    }

    /// The context a host pins for the invocation: the activation's identity,
    /// profile and capabilities under the grant generation and publisher key
    /// the host verified against.
    pub fn context(&self, grant_generation: u64, public_key: [u8; 32]) -> ActivationContext {
        ActivationContext {
            xite: self.xite.clone(),
            generation: grant_generation,
            publisher: self.publisher.clone(),
            public_key: Some(public_key),
            runtime_profile: self.runtime_profile.clone(),
            capabilities: self.capabilities.clone(),
        }
    }
}

/// A verified and captured activation that has not been admitted.
///
/// Everything a host needs for its binding checks is readable here; the
/// captured bytes become available only through [`ActivationLoader::admit`].
/// Dropping a pending activation leaves the loader's checkpoint untouched.
#[derive(Debug)]
pub struct PendingActivation {
    activation: FrozenActivation,
}

impl PendingActivation {
    /// The xite named by the grant and the signed body.
    pub fn xite(&self) -> &str {
        self.activation.xite()
    }

    /// The publisher named by the grant and the signed body.
    pub fn publisher(&self) -> &str {
        self.activation.publisher()
    }

    /// Generation of the grant the activation was verified under.
    pub fn grant_generation(&self) -> u64 {
        self.activation.grant_generation()
    }

    /// Signed version.
    pub fn version(&self) -> u64 {
        self.activation.version()
    }

    /// Signed runtime profile.
    pub fn runtime_profile(&self) -> &str {
        self.activation.runtime_profile()
    }

    /// Signed artifact format.
    pub fn artifact_format(&self) -> ArtifactFormat {
        self.activation.artifact_format()
    }

    /// Declared capabilities.
    pub fn capabilities(&self) -> &BTreeSet<Capability> {
        self.activation.capabilities()
    }

    /// SHA-256 of the canonical signed body.
    pub fn manifest_digest(&self) -> &str {
        self.activation.manifest_digest()
    }

    /// The context a host compares with its current grant before admitting.
    pub fn context(&self, grant_generation: u64, public_key: [u8; 32]) -> ActivationContext {
        self.activation.context(grant_generation, public_key)
    }

    /// Captured entry bytes, so a host can compile before admitting and keep
    /// the version floor unchanged when compilation is refused. The bytes are
    /// the ones verified against the signed digest; nothing is reopened.
    pub fn entry_bytes(&self) -> &[u8] {
        self.activation.entry_bytes()
    }
}

/// Serial host loader for one xite grant.
///
/// The grant is fixed for the loader's lifetime; a host that changes
/// authority builds a new loader (restoring the persisted checkpoint).
#[derive(Debug)]
pub struct ActivationLoader {
    grant: XiteGrant,
    checkpoint: ActivationCheckpoint,
}

impl ActivationLoader {
    /// A loader with no admitted version.
    pub fn new(grant: XiteGrant) -> Self {
        ActivationLoader {
            grant,
            checkpoint: ActivationCheckpoint::default(),
        }
    }

    /// A loader restored from a persisted checkpoint.
    pub fn with_checkpoint(grant: XiteGrant, checkpoint: ActivationCheckpoint) -> Self {
        ActivationLoader { grant, checkpoint }
    }

    /// The grant every verification runs under.
    pub fn grant(&self) -> &XiteGrant {
        &self.grant
    }

    /// The current version floor.
    pub fn checkpoint(&self) -> &ActivationCheckpoint {
        &self.checkpoint
    }

    /// Phase one: authenticate `envelope`, validate every declaration against
    /// the grant, check the version against the checkpoint and capture the
    /// signed closure beneath `artifact_root`. Nothing is mutated.
    pub fn verify(
        &self,
        envelope: &[u8],
        artifact_root: &Path,
    ) -> Result<PendingActivation, AuthenticationError> {
        self.verify_with(envelope, artifact_root, &mut capture::capture_file)
    }

    /// Phase two: re-check the checkpoint, which another admission may have
    /// advanced since `pending` was verified, then advance it and release the
    /// captured activation.
    pub fn admit(
        &mut self,
        pending: PendingActivation,
    ) -> Result<FrozenActivation, AuthenticationError> {
        let activation = pending.activation;
        if !self.grant.enabled {
            return Err(AuthenticationError::new("xite execution is not enabled"));
        }
        if activation.xite != self.grant.xite
            || activation.publisher != self.grant.publisher
            || activation.grant_generation != self.grant.generation
        {
            return Err(AuthenticationError::new(
                "pending activation was not verified under this grant",
            ));
        }
        if !self
            .checkpoint
            .admits(activation.version, &activation.manifest_digest)
        {
            return Err(rollback());
        }
        self.checkpoint =
            ActivationCheckpoint::new(activation.version, Some(activation.manifest_digest.clone()));
        Ok(activation)
    }

    pub(crate) fn verify_with(
        &self,
        envelope: &[u8],
        artifact_root: &Path,
        capture: &mut CaptureFn<'_>,
    ) -> Result<PendingActivation, AuthenticationError> {
        let grant = &self.grant;
        if !grant.enabled {
            return Err(AuthenticationError::new("xite execution is not enabled"));
        }
        let signed = envelope::verify_envelope(envelope, &grant.public_key)?;
        let body = &signed.body;
        envelope::shape(body, BODY_KEYS)?;
        if field(body, "kind").as_str() != Some(KIND)
            || field(body, "xite").as_str() != Some(grant.xite.as_str())
            || field(body, "publisher").as_str() != Some(grant.publisher.as_str())
        {
            return Err(AuthenticationError::new("activation identity mismatch"));
        }
        let version = envelope::positive(field(body, "version"))?;
        let manifest_digest = digest(&signed.bytes);
        if !self.checkpoint.admits(version, &manifest_digest) {
            return Err(rollback());
        }
        let profile = envelope::identifier(field(body, "runtime_profile"))?;
        if !grant.runtime_profiles.contains(profile) {
            return Err(AuthenticationError::new("runtime profile outside grant"));
        }
        let capabilities = declared_capabilities(body, grant)?;
        let artifact_format = field(body, "artifact_format")
            .as_str()
            .and_then(ArtifactFormat::parse)
            .ok_or_else(|| {
                AuthenticationError::new(
                    "unsupported artifact format; native caches are not accepted",
                )
            })?;
        let expected = signed_closure(body)?;
        let entry = field(body, "entry")
            .as_str()
            .filter(|entry| expected.contains_key(*entry))
            .ok_or_else(|| AuthenticationError::new("entry absent from signed closure"))?;

        let root = capture::open_root(artifact_root)?;
        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for (path, expected_digest) in &expected {
            let data = capture(root.as_fd(), path)?;
            total = total.saturating_add(data.len());
            if total > MAX_TOTAL || digest(&data) != *expected_digest {
                return Err(AuthenticationError::new(
                    "artifact digest or aggregate size mismatch",
                ));
            }
            artifact_format.check(&data)?;
            files.insert(path.clone(), data);
        }
        drop(root);

        Ok(PendingActivation {
            activation: FrozenActivation {
                xite: grant.xite.clone(),
                publisher: grant.publisher.clone(),
                grant_generation: grant.generation,
                version,
                runtime_profile: profile.to_string(),
                artifact_format,
                capabilities,
                manifest_digest,
                manifest_bytes: signed.bytes,
                entry: entry.to_string(),
                files,
            },
        })
    }
}

/// The declared capability list: at most 64 well-formed, distinct, known
/// capability names, all within the grant.
fn declared_capabilities(
    body: &Object,
    grant: &XiteGrant,
) -> Result<BTreeSet<Capability>, AuthenticationError> {
    let declared = field(body, "capabilities")
        .as_array()
        .filter(|list| list.len() <= MAX_CAPABILITIES)
        .ok_or_else(|| AuthenticationError::new("invalid capability declaration"))?;
    let exceeds = || AuthenticationError::new("capability declaration exceeds grant");
    let mut capabilities = BTreeSet::new();
    for item in declared {
        let name = envelope::identifier(item)?;
        let capability = Capability::parse(name).ok_or_else(exceeds)?;
        if !capabilities.insert(capability) {
            return Err(exceeds());
        }
    }
    if !capabilities.is_subset(&grant.capabilities) {
        return Err(exceeds());
    }
    Ok(capabilities)
}

/// The signed closure: 1 to [`MAX_FILES`] relative paths, each with a hex
/// SHA-256 digest, in sorted order.
fn signed_closure(body: &Object) -> Result<BTreeMap<String, String>, AuthenticationError> {
    let files = field(body, "files")
        .as_object()
        .filter(|files| (1..=MAX_FILES).contains(&files.len()))
        .ok_or_else(|| AuthenticationError::new("invalid artifact closure"))?;
    let mut expected = BTreeMap::new();
    for (path, value) in files {
        evx_api::validate_relative_path(path)
            .map_err(|_| AuthenticationError::new("artifact path outside allowed namespace"))?;
        let expected_digest = envelope::hex_digest(value)?;
        expected.insert(path.clone(), expected_digest.to_string());
    }
    Ok(expected)
}
