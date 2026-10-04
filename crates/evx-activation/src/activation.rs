//! Grants, checkpoints and the two-phase activation loader.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::{os::fd::AsFd as _, path::Path};

use ed25519_dalek::VerifyingKey;
use evx_api::grant::ActivationContext;
use evx_api::Capability;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use crate::capture::{self, CaptureFn};
use crate::envelope::{self, field, Object};
use crate::{digest, AuthenticationError, MAX_ARTIFACT, MAX_FILES, MAX_TOTAL};

/// Trusted artifact reader selected by the host, never by a xite.
///
/// The arguments are a validated signed relative name and the maximum number
/// of bytes permitted for that file. Implementations must restrict reads to
/// the host-selected xite source and bound I/O and allocation independently.
/// The loader rejects oversized returns and authenticates the exact bytes;
/// this callback does not itself provide filesystem containment.
pub type ArtifactReadFn<'a> = dyn FnMut(&str, usize) -> Result<Vec<u8>, AuthenticationError> + 'a;

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

/// Who may publish code for a xite, in the two forms the loader can check.
///
/// The envelope path trusts a raw Ed25519 key and verifies every envelope
/// against it inside [`ActivationLoader::verify`]. The content path trusts
/// the xite's root address: the owner's secp256k1 signature on `content.json`
/// is checked by the node (`epix_content::verify_signer`) before
/// [`ActivationLoader::verify_content`] is called, so the loader holds no key
/// for it and only records which address the caller vouched for. The enum is
/// closed on purpose: each activation path refuses a grant of the other kind
/// instead of guessing what its signature would have meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublisherAuthority {
    /// Raw Ed25519 public key; signed fixture envelopes verify against it.
    Ed25519([u8; 32]),
    /// The `epix1…` root address whose content signature the node verified.
    RootAddress(String),
}

/// Host-issued authority for one xite: who may publish code for it, which
/// capabilities and runtime profiles that code may declare, and whether it
/// may run at all. An accepted code update never replaces its grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XiteGrant {
    /// The xite this grant covers.
    pub xite: String,
    /// The publisher whose signatures activate code for the xite: a fixture
    /// publisher id under [`PublisherAuthority::Ed25519`], the root address
    /// itself under [`PublisherAuthority::RootAddress`].
    pub publisher: String,
    /// Raw Ed25519 public key of the publisher. Meaningful only when
    /// `authority` is [`PublisherAuthority::Ed25519`]; a root-address grant
    /// holds all zeros here, which no envelope can verify against, and hosts
    /// read [`XiteGrant::ed25519_public_key`] instead of this field.
    pub public_key: [u8; 32],
    /// Which signature the loader trusts for this grant.
    pub authority: PublisherAuthority,
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
            authority: PublisherAuthority::Ed25519(public_key),
            capabilities,
            runtime_profiles,
            generation: 1,
            enabled: true,
        })
    }

    /// Build an enabled generation-1 grant for content signed by the owner
    /// of `publisher`, an `epix1…` root address. `xite` is the xite's own
    /// address in the real deployment, but only its identifier grammar is
    /// checked so fixtures can name it freely; `publisher` must be a
    /// well-formed address because it is what the node's signature check
    /// was performed against, and a grant naming an impossible address can
    /// never correspond to a verified signer.
    pub fn for_root_address(
        xite: impl Into<String>,
        publisher: impl Into<String>,
        capabilities: BTreeSet<Capability>,
        runtime_profiles: BTreeSet<String>,
    ) -> Result<Self, AuthenticationError> {
        let xite = xite.into();
        let publisher = publisher.into();
        evx_api::validate_identifier(&xite)
            .map_err(|_| AuthenticationError::new("invalid fixture identifier"))?;
        if !epix_crypt::is_valid_address(&publisher) {
            return Err(AuthenticationError::new("invalid publisher root address"));
        }
        Ok(XiteGrant {
            xite,
            authority: PublisherAuthority::RootAddress(publisher.clone()),
            publisher,
            public_key: [0; 32],
            capabilities,
            runtime_profiles,
            generation: 1,
            enabled: true,
        })
    }

    /// The Ed25519 key envelopes verify against, or `None` for a
    /// root-address grant. This is what a host pins into an
    /// [`ActivationContext`] and compares with its broker grant, so the two
    /// authority forms are never confused with each other.
    pub fn ed25519_public_key(&self) -> Option<[u8; 32]> {
        match &self.authority {
            PublisherAuthority::Ed25519(key) => Some(*key),
            PublisherAuthority::RootAddress(_) => None,
        }
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
    declaration_digest: Option<String>,
    program: Option<String>,
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

    /// The canonical signed body bytes: the envelope body for an envelope
    /// activation, `epix_content::signed_data` for a content activation.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// SHA-256 of the canonical `evx` section of the signed `content.json`
    /// for a content activation, the digest a stored grant is pinned to;
    /// `None` for an envelope activation, which has no declaration.
    pub fn declaration_digest(&self) -> Option<&str> {
        self.declaration_digest.as_deref()
    }

    /// The declared program id a content activation was bound to; `None`
    /// for an envelope activation.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
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
        self.context_with(grant_generation, Some(public_key))
    }

    /// [`FrozenActivation::context`] under whichever authority `grant`
    /// carries: the Ed25519 key for an envelope grant, no key for a
    /// root-address grant, whose binding the broker checks by publisher
    /// address alone.
    pub fn grant_context(&self, grant: &XiteGrant) -> ActivationContext {
        self.context_with(grant.generation, grant.ed25519_public_key())
    }

    fn context_with(
        &self,
        grant_generation: u64,
        public_key: Option<[u8; 32]>,
    ) -> ActivationContext {
        ActivationContext {
            xite: self.xite.clone(),
            generation: grant_generation,
            publisher: self.publisher.clone(),
            public_key,
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
    verified_grant: XiteGrant,
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

    /// [`PendingActivation::context`] under `grant`'s own authority form.
    pub fn grant_context(&self, grant: &XiteGrant) -> ActivationContext {
        self.activation.grant_context(grant)
    }

    /// Declaration digest of a content activation; `None` for an envelope.
    pub fn declaration_digest(&self) -> Option<&str> {
        self.activation.declaration_digest()
    }

    /// Declared program id of a content activation; `None` for an envelope.
    pub fn program(&self) -> Option<&str> {
        self.activation.program()
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
    #[cfg(unix)]
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
        if pending.verified_grant != self.grant {
            return Err(AuthenticationError::new(
                "pending activation was not verified under this grant",
            ));
        }
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

    #[cfg(unix)]
    pub(crate) fn verify_with(
        &self,
        envelope: &[u8],
        artifact_root: &Path,
        capture: &mut CaptureFn<'_>,
    ) -> Result<PendingActivation, AuthenticationError> {
        // Do not touch the filesystem until the signed declaration has passed
        // identity, version, capability and closure validation.
        let mut root = None;
        self.verify_reader(envelope, &mut |path, _limit| {
            if root.is_none() {
                root = Some(capture::open_root(artifact_root)?);
            }
            capture(root.as_ref().expect("root opened above").as_fd(), path)
        })
    }

    /// Verify an envelope and capture exact signed bytes from a trusted source.
    ///
    /// Works without Unix filesystem APIs. Identity, signature, capability and
    /// version checks happen before the reader is called. The returned pending
    /// activation does not advance the checkpoint until [`Self::admit`].
    /// The host must choose and confine the reader; a validated relative name
    /// is not permission to access an arbitrary operating-system path.
    pub fn verify_reader(
        &self,
        envelope: &[u8],
        read: &mut ArtifactReadFn<'_>,
    ) -> Result<PendingActivation, AuthenticationError> {
        let grant = &self.grant;
        if !grant.enabled {
            return Err(AuthenticationError::new("xite execution is not enabled"));
        }
        // A root-address grant holds no Ed25519 key; its zeroed `public_key`
        // would fail every signature anyway, but refusing by authority kind
        // names the real reason instead of a spurious signature failure.
        let PublisherAuthority::Ed25519(trusted_key) = &grant.authority else {
            return Err(AuthenticationError::new(
                "envelope activation requires an Ed25519 grant",
            ));
        };
        let signed = envelope::verify_envelope(envelope, trusted_key)?;
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

        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for (path, expected_digest) in &expected {
            let remaining = MAX_ARTIFACT.min(MAX_TOTAL.saturating_sub(total));
            let data = read(path, remaining)?;
            if data.len() > remaining {
                return Err(AuthenticationError::new("artifact size limit"));
            }
            total = total.saturating_add(data.len());
            if total > MAX_TOTAL || digest(&data) != *expected_digest {
                return Err(AuthenticationError::new(
                    "artifact digest or aggregate size mismatch",
                ));
            }
            artifact_format.check(&data)?;
            files.insert(path.clone(), data);
        }
        Ok(PendingActivation {
            verified_grant: grant.clone(),
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
                declaration_digest: None,
                program: None,
                entry: entry.to_string(),
                files,
            },
        })
    }

    /// Mint a pending content activation from fields `crate::content` has
    /// verified. Lives here so the frozen fields stay private to this module
    /// and only the two verification paths can produce one.
    pub(crate) fn pending_content(&self, verified: VerifiedContent) -> PendingActivation {
        PendingActivation {
            verified_grant: self.grant.clone(),
            activation: FrozenActivation {
                xite: self.grant.xite.clone(),
                publisher: self.grant.publisher.clone(),
                grant_generation: self.grant.generation,
                version: verified.version,
                runtime_profile: verified.runtime_profile,
                artifact_format: ArtifactFormat::WasmCoreV1,
                capabilities: verified.capabilities,
                manifest_digest: verified.manifest_digest,
                manifest_bytes: verified.manifest_bytes,
                declaration_digest: Some(verified.declaration_digest),
                program: Some(verified.program),
                entry: verified.entry,
                files: verified.files,
            },
        }
    }

    /// Whether `version` with `manifest_digest` passes the version floor
    /// right now; shared by both verification paths.
    pub(crate) fn admits(&self, version: u64, manifest_digest: &str) -> bool {
        self.checkpoint.admits(version, manifest_digest)
    }
}

/// Everything the content path verified, handed to
/// [`ActivationLoader::pending_content`] in one piece.
pub(crate) struct VerifiedContent {
    pub(crate) version: u64,
    pub(crate) runtime_profile: String,
    pub(crate) capabilities: BTreeSet<Capability>,
    pub(crate) manifest_digest: String,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) declaration_digest: String,
    pub(crate) program: String,
    pub(crate) entry: String,
    pub(crate) files: BTreeMap<String, Vec<u8>>,
}

impl ArtifactFormat {
    /// The encoding check, for the content path.
    pub(crate) fn check_bytes(self, data: &[u8]) -> Result<(), AuthenticationError> {
        self.check(data)
    }
}

/// The error both paths report for a version below or conflicting with the
/// floor.
pub(crate) fn rollback_error() -> AuthenticationError {
    rollback()
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
