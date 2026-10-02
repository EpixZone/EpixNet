//! EVX host: authenticated activation bound to contained execution.
//!
//! [`run_activation`] and [`run_content_activation`] are the only paths by
//! which xite content reaches a worker. The first takes a signed fixture
//! envelope, the second the real authority chain: a root `content.json` the
//! node has verified against the xite owner's address, a program bound to
//! its manifest, and a reader for the stored files. Each verifies and
//! captures the closure, checks the activation against the broker's current
//! grant, compiles the captured entry bytes in a confined compiler process,
//! admits the activation (which is the only point the version floor
//! advances), and runs the artifact under the activation context so the
//! supervisor rechecks the same authority at every broker call and file
//! commit.
//!
//! Neither input selects a broker, workspace, runtime option or key, and a
//! denied binding check leaves the previous version runnable.

use std::collections::BTreeSet;
use std::path::Path;

use evx_activation::{
    ActivationLoader, AuthenticationError, BoundProgram, ContentReadFn, PendingActivation,
};
use evx_api::{Capability, RunResult};
use evx_supervisor::{compile_module, run_guest, Broker, Config, RunOptions};

/// Activation metadata attached to a result.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivationReport {
    pub xite: String,
    pub publisher: String,
    pub version: u64,
    pub grant_generation: u64,
    pub runtime_profile: String,
    pub artifact_format: String,
    pub manifest_digest: String,
    pub artifact_sha256: String,
    /// Digest of the signed `evx` section for a content activation; `None`
    /// for an envelope activation.
    pub declaration_digest: Option<String>,
    /// Declared program id for a content activation; `None` for an envelope.
    pub program: Option<String>,
}

/// Result of an authenticated run.
#[derive(Debug)]
pub struct ActivationOutcome {
    pub result: RunResult,
    pub activation: Option<ActivationReport>,
}

fn denied(reason: impl Into<String>) -> ActivationOutcome {
    ActivationOutcome {
        result: RunResult::denied(reason),
        activation: None,
    }
}

/// Check that the loader's grant and the broker's current grant describe the
/// same authority, optionally for a specific activation's declared needs.
///
/// The publisher key is compared through [`evx_activation::XiteGrant::ed25519_public_key`]
/// so a root-address grant binds to a broker grant with no key, and an
/// Ed25519 grant to one carrying exactly its key; a broker grant of the other
/// shape is a mismatch, never a match by omission.
fn check_binding(
    loader: &ActivationLoader,
    broker: &Broker,
    capabilities: Option<&BTreeSet<Capability>>,
    runtime_profile: Option<&str>,
) -> Result<(), AuthenticationError> {
    let grant = loader.grant();
    let current = broker.grant();
    if !grant.enabled || !current.enabled {
        return Err(AuthenticationError::new("execution grant is disabled"));
    }
    if current.xite != grant.xite || current.generation != grant.generation {
        return Err(AuthenticationError::new(
            "broker xite or grant generation mismatch",
        ));
    }
    if current.publisher.as_deref() != Some(grant.publisher.as_str())
        || current.publisher_public_key != grant.ed25519_public_key()
    {
        return Err(AuthenticationError::new(
            "broker publisher binding mismatch",
        ));
    }
    if let Some(caps) = capabilities {
        if !caps.is_subset(&current.capabilities) {
            return Err(AuthenticationError::new(
                "activation capabilities exceed current broker grant",
            ));
        }
    }
    if let Some(profile) = runtime_profile {
        if !current.runtime_profiles.contains(profile) {
            return Err(AuthenticationError::new(
                "activation runtime profile exceeds current broker grant",
            ));
        }
    }
    Ok(())
}

/// Verify, capture, compile, admit and run one signed activation.
pub fn run_activation(
    config: &Config,
    loader: &mut ActivationLoader,
    envelope: &[u8],
    artifact_root: &Path,
    broker: &Broker,
    options: RunOptions,
) -> ActivationOutcome {
    if let Err(e) = check_binding(loader, broker, None, None) {
        return denied(e.to_string());
    }
    let pending: PendingActivation = match loader.verify(envelope, artifact_root) {
        Ok(pending) => pending,
        Err(e) => return denied(e.to_string()),
    };
    bind_compile_admit_run(config, loader, pending, broker, options)
}

/// Verify, capture, compile, admit and run one program of a xite's signed
/// `content.json`.
///
/// `content` must already be verified by the caller as the root
/// `content.json` signed by the owner of the loader grant's root address
/// (see [`ActivationLoader::verify_content`]); `bound` is the program pinned
/// to that manifest and `read` yields the xite's stored files by
/// manifest-relative path. The closure is captured through `read` and
/// re-hashed against the manifest, so no artifact root is needed here: the
/// bytes the worker runs are exactly the bytes that matched.
pub fn run_content_activation(
    config: &Config,
    loader: &mut ActivationLoader,
    content: &serde_json::Value,
    bound: &BoundProgram,
    read: &mut ContentReadFn<'_>,
    broker: &Broker,
    options: RunOptions,
) -> ActivationOutcome {
    if let Err(e) = check_binding(loader, broker, None, None) {
        return denied(e.to_string());
    }
    let pending: PendingActivation = match loader.verify_content(content, bound, read) {
        Ok(pending) => pending,
        Err(e) => return denied(e.to_string()),
    };
    bind_compile_admit_run(config, loader, pending, broker, options)
}

/// The shared tail of both paths: bind the pending activation's request to
/// the broker's current grant, compile the captured entry, admit, run.
fn bind_compile_admit_run(
    config: &Config,
    loader: &mut ActivationLoader,
    pending: PendingActivation,
    broker: &Broker,
    options: RunOptions,
) -> ActivationOutcome {
    if let Err(e) = check_binding(
        loader,
        broker,
        Some(pending.capabilities()),
        Some(pending.runtime_profile()),
    ) {
        return denied(e.to_string());
    }
    // Compile the captured bytes before admission so a module the compiler
    // refuses does not advance the version floor either.
    let entry: Vec<u8> = match pending.artifact_format() {
        evx_activation::ArtifactFormat::Wat => {
            let text = match std::str::from_utf8(pending.entry_bytes()) {
                Ok(text) => text,
                Err(_) => return denied("invalid WAT encoding"),
            };
            match evx_runtime::text_to_binary(text) {
                Ok(bytes) => bytes,
                Err(e) => return denied(e.to_string()),
            }
        }
        evx_activation::ArtifactFormat::WasmCoreV1 => pending.entry_bytes().to_vec(),
    };
    let artifact = match compile_module(config, &entry) {
        Ok(artifact) => artifact,
        Err(e) => return denied(e.to_string()),
    };
    let grant = loader.grant().clone();
    let activation = match loader.admit(pending) {
        Ok(activation) => activation,
        Err(e) => return denied(e.to_string()),
    };
    let context = activation.grant_context(&grant);
    let report = ActivationReport {
        xite: activation.xite().to_string(),
        publisher: activation.publisher().to_string(),
        version: activation.version(),
        grant_generation: activation.grant_generation(),
        runtime_profile: activation.runtime_profile().to_string(),
        artifact_format: activation.artifact_format().name().to_string(),
        manifest_digest: activation.manifest_digest().to_string(),
        artifact_sha256: artifact.sha256.clone(),
        declaration_digest: activation.declaration_digest().map(str::to_string),
        program: activation.program().map(str::to_string),
    };
    let options = RunOptions {
        activation_context: Some(context),
        ..options
    };
    let result = run_guest(config, &artifact, broker, options);
    ActivationOutcome {
        result,
        activation: Some(report),
    }
}
