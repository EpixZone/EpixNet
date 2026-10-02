//! EVX host: authenticated activation bound to contained execution.
//!
//! [`run_activation`] is the only path by which signed xite content reaches a
//! worker. It verifies the envelope and captures the artifact closure, checks
//! the activation against the broker's current grant, compiles the captured
//! entry bytes in a confined compiler process, admits the activation (which is
//! the only point the version floor advances), and runs the artifact under the
//! activation context so the supervisor rechecks the same authority at every
//! broker call and file commit.
//!
//! The envelope never selects a broker, workspace, runtime option or key, and
//! a denied binding check leaves the previous version runnable.

use std::collections::BTreeSet;
use std::path::Path;

use evx_activation::{ActivationLoader, AuthenticationError, PendingActivation};
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
        || current.publisher_public_key != Some(grant.public_key)
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
    let public_key = loader.grant().public_key;
    let activation = match loader.admit(pending) {
        Ok(activation) => activation,
        Err(e) => return denied(e.to_string()),
    };
    let context = activation.context(activation.grant_generation(), public_key);
    let report = ActivationReport {
        xite: activation.xite().to_string(),
        publisher: activation.publisher().to_string(),
        version: activation.version(),
        grant_generation: activation.grant_generation(),
        runtime_profile: activation.runtime_profile().to_string(),
        artifact_format: activation.artifact_format().name().to_string(),
        manifest_digest: activation.manifest_digest().to_string(),
        artifact_sha256: artifact.sha256.clone(),
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
