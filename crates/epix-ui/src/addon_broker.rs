//! Authenticated transport for the packaged desktop browser's native addon UI.
//!
//! The launcher registers the real profile before Firefox starts. Requests can
//! choose neither profile paths nor sessions. This protocol is separate from
//! the wallet native-messaging host and is never exposed through EpixFrame.
use crate::{addons::*, data_relocation::ProtectedDirectory, AppState};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::result::Result;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
};

pub const PATH: &str = "/EpixNet-Internal/AddonBroker";
// Reconciliation sends the complete bounded engine inventory. Allow 2048
// entries with 255-byte IDs, 128-byte versions and JSON's worst-case sixfold
// escaping, plus hashes and field names. The native client uses the same cap.
pub const MAX_REQUEST_BYTES: usize = 6 * 1024 * 1024;
const MAX_MIRROR_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CLIENTS: usize = 16;
const MAX_NONCES: usize = 4096;
const CLOCK_WINDOW_MS: u64 = 60_000;
const REQUEST_DOMAIN: &[u8] = b"EpixNet addon broker request v1\0";
const RESPONSE_DOMAIN: &[u8] = b"EpixNet addon broker response v1\0";
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AddonBroker {
    state: Arc<AppState>,
    clients: Arc<Mutex<HashMap<String, Arc<Client>>>>,
}

/// Per-run authority passed only to the native browser process environment.
/// It is never stored in the profile, where file-access extensions could read
/// it, and deliberately has no Debug or Serialize implementation.
#[derive(Clone)]
pub struct AddonLaunchCredentials {
    profile_id: String,
    client_id: String,
    secret: String,
}

impl AddonLaunchCredentials {
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn configure_command(&self, command: &mut std::process::Command) {
        command.env("EPIX_ADDON_BROKER_CLIENT", &self.client_id);
        command.env("EPIX_ADDON_BROKER_SECRET", &self.secret);
    }
}

struct Client {
    profile_id: String,
    // Deliberately no Debug or Serialize implementation for live credentials.
    secret: String,
    directory: ProtectedDirectory,
    session_id: Mutex<String>,
    nonces: Mutex<HashMap<String, u64>>,
    // Verification can be cancelled during preparation and handoff. Other
    // mutations and the synchronous startup mirror commit are serialized.
    control: tokio::sync::Mutex<()>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileIdentity {
    protocol: u32,
    profile_id: String,
}

#[derive(Serialize)]
struct Credentials<'a> {
    protocol: u32,
    endpoint: String,
    profile_id: &'a str,
    client_id: &'a str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mirror {
    protocol: u32,
    profile_id: String,
    managed: Vec<AddonOwnership>,
    pending: Option<AddonSnapshot>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NativeConsent {
    protocol: u32,
    profile_id: String,
    operation_id: String,
    addon_id: String,
    version: String,
    archive_sha256: String,
}

impl NativeConsent {
    fn matches(&self, session: &AddonSession, pending: &AddonSnapshot) -> bool {
        self.protocol == 1
            && self.profile_id == session.profile_id
            && self.operation_id == pending.operation_id
            && pending.candidate.as_ref().is_some_and(|candidate| {
                self.addon_id == candidate.addon_id
                    && self.version == candidate.version
                    && self.archive_sha256 == candidate.archive_sha256
            })
    }
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Open {},
    Reconcile {
        inventory: AddonInventory,
    },
    Prepare {
        source_url: String,
        action: AddonAction,
    },
    Status {},
    Cancel {
        operation_id: Option<String>,
    },
    Stage {
        operation_id: String,
        archive_sha256: String,
    },
    Consent {
        operation_id: String,
        archive_sha256: String,
    },
    Report {
        operation_id: String,
        outcome: AddonEngineOutcome,
    },
    BeginUninstall {
        addon_id: String,
    },
}

fn error(code: AddonErrorCode, message: impl Into<String>) -> AddonError {
    AddonError::new(code, message)
}

impl AddonBroker {
    pub(crate) fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Only the native launcher may supply this path. The endpoint never
    /// accepts a path or a caller-selected profile identity.
    pub async fn register_profile(
        &self,
        profile: &Path,
        address: SocketAddr,
    ) -> Result<AddonLaunchCredentials, String> {
        self.register(profile, address)
            .await
            .map_err(|e| e.to_string())
    }

    async fn register(
        &self,
        profile: &Path,
        address: SocketAddr,
    ) -> Result<AddonLaunchCredentials, AddonError> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(error(
                AddonErrorCode::InvalidRequest,
                "Addon broker requires a bound loopback listener",
            ));
        }
        let directory = ProtectedDirectory::open_child(profile, "epix-addons")?;
        let old_mirror = directory
            .read("mirror.json", MAX_MIRROR_BYTES)?
            .map(|bytes| serde_json::from_slice::<Mirror>(&bytes))
            .transpose()
            .map_err(|_| {
                error(
                    AddonErrorCode::NeedsReconciliation,
                    "Invalid addon startup receipts",
                )
            })?;
        let identity = match directory.read("profile.json", 1024)? {
            Some(bytes) => serde_json::from_slice::<ProfileIdentity>(&bytes).map_err(|_| {
                error(
                    AddonErrorCode::NeedsReconciliation,
                    "Invalid addon profile identity",
                )
            })?,
            None => {
                if old_mirror.is_some() || directory.read("client.json", 4096)?.is_some() {
                    return Err(error(
                        AddonErrorCode::NeedsReconciliation,
                        "Addon profile identity is missing",
                    ));
                }
                let identity = ProfileIdentity {
                    protocol: 1,
                    profile_id: random_id()?,
                };
                directory.create_new("profile.json", &encode(&identity)?)?;
                identity
            }
        };
        if identity.protocol != 1 || !valid_id(&identity.profile_id) {
            return Err(error(
                AddonErrorCode::NeedsReconciliation,
                "Unsupported addon profile identity",
            ));
        }
        {
            let clients = self
                .clients
                .lock()
                .map_err(|_| error(AddonErrorCode::Io, "Addon broker lock failed"))?;
            if clients.len() >= MAX_CLIENTS
                || clients
                    .values()
                    .any(|c| c.profile_id == identity.profile_id)
            {
                return Err(error(
                    AddonErrorCode::Busy,
                    "Addon profile is already registered or client limit reached",
                ));
            }
        }
        let session = self
            .state
            .addon_open_session(&identity.profile_id, AddonEngine::Gecko)
            .await?;
        if let Some(old) = &old_mirror {
            validate_mirror_continuity(old, &session)?;
        } else if !session.managed.is_empty()
            || durable_pending(session.operation.as_ref()).is_some()
        {
            return Err(error(
                AddonErrorCode::NeedsReconciliation,
                "Enrolled profile is missing its startup receipts",
            ));
        }
        let client_id = random_id()?;
        let client = Arc::new(Client {
            profile_id: identity.profile_id.clone(),
            secret: random_id()?,
            directory,
            session_id: Mutex::new(session.session_id.clone()),
            nonces: Mutex::new(HashMap::new()),
            control: tokio::sync::Mutex::new(()),
        });
        write_mirror(&client, &session)?;
        let credentials = Credentials {
            protocol: 1,
            endpoint: format!("http://{address}{PATH}"),
            profile_id: &client.profile_id,
            client_id: &client_id,
        };
        client
            .directory
            .write("client.json", &encode(&credentials)?)?;
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| error(AddonErrorCode::Io, "Addon broker lock failed"))?;
        // Registration is launcher-owned and normally serial. Fail closed if
        // another native registration raced it, rather than replacing a client.
        if clients.len() >= MAX_CLIENTS
            || clients.values().any(|c| c.profile_id == client.profile_id)
        {
            return Err(error(
                AddonErrorCode::Busy,
                "Addon profile registration changed",
            ));
        }
        let credentials = AddonLaunchCredentials {
            profile_id: identity.profile_id,
            client_id: client_id.clone(),
            secret: client.secret.clone(),
        };
        clients.insert(client_id, client);
        Ok(credentials)
    }

    fn authenticate(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now: u64,
    ) -> Option<(Arc<Client>, Auth)> {
        // Chrome-origin calls omit Origin. Page requests, including opaque
        // origins, are refused in addition to MAC authentication and CORS.
        if headers.contains_key("origin") || body.len() > MAX_REQUEST_BYTES {
            return None;
        }
        let auth = Auth::read(headers)?;
        if now.abs_diff(auth.time) > CLOCK_WINDOW_MS {
            return None;
        }
        let client = self.clients.lock().ok()?.get(&auth.client_id)?.clone();
        let mac = authenticator(&client.secret, REQUEST_DOMAIN, &auth, None, body)?;
        if mac.verify_slice(&hex::decode(&auth.mac).ok()?).is_err() {
            return None;
        }
        let mut nonces = client.nonces.lock().ok()?;
        nonces.retain(|_, received| now.saturating_sub(*received) <= 2 * CLOCK_WINDOW_MS);
        if nonces.contains_key(&auth.nonce) || nonces.len() >= MAX_NONCES {
            return None;
        }
        nonces.insert(auth.nonce.clone(), now);
        drop(nonces);
        Some((client, auth))
    }

    async fn dispatch(
        &self,
        client: &Client,
        request: Request,
    ) -> Result<serde_json::Value, AddonError> {
        if let Request::Prepare { source_url, action } = request {
            let session_id = session_id(client)?;
            let result = self
                .state
                .addon_prepare(AddonPrepareRequest {
                    session_id: session_id.clone(),
                    source_url,
                    action,
                })
                .await;
            let _control = client.control.lock().await;
            let current = self.state.addon_status(&session_id).await?;
            write_mirror(client, &current)?;
            return result.and_then(to_value);
        }
        if let Request::Stage {
            operation_id,
            archive_sha256,
        } = request
        {
            let current_id = session_id(client)?;
            // Authority verification may wait on a manifest mutation. Do not
            // hold the transport lock that Cancel needs to interrupt it.
            let result = self
                .state
                .addon_stage(&current_id, &operation_id, &archive_sha256)
                .await;
            let _control = client.control.lock().await;
            let current = self.state.addon_status(&current_id).await?;
            write_mirror(client, &current)?;
            let staged = result?;
            // Cancel may have won the lock after the core made the handoff.
            // Never return its path after that operation was replaced/closed.
            if !current.operation.as_ref().is_some_and(|operation| {
                operation.phase == AddonPhase::HandedOff
                    && operation.operation_id == operation_id
                    && operation.candidate.as_ref() == Some(&staged.candidate)
            }) {
                return Err(error(
                    AddonErrorCode::Cancelled,
                    "Addon handoff was cancelled",
                ));
            }
            if staged.candidate.expires_at_ms <= now_ms() {
                return Err(error(AddonErrorCode::Expired, "Addon handoff expired"));
            }
            return to_value(staged);
        }
        let _control = client.control.lock().await;
        let mut current_id = session_id(client)?;
        let result = match request {
            Request::Open {} => {
                let session = self
                    .state
                    .addon_open_session(&client.profile_id, AddonEngine::Gecko)
                    .await?;
                current_id = session.session_id.clone();
                *client
                    .session_id
                    .lock()
                    .map_err(|_| error(AddonErrorCode::Io, "Addon session lock failed"))? =
                    current_id.clone();
                to_value(session)
            }
            Request::Reconcile { inventory } => self
                .state
                .addon_reconcile(&current_id, inventory)
                .await
                .and_then(to_value),
            Request::Status {} => self
                .state
                .addon_status(&current_id)
                .await
                .and_then(to_value),
            Request::Cancel { operation_id } => self
                .state
                .addon_cancel(&current_id, operation_id.as_deref())
                .await
                .and_then(to_value),
            Request::Consent {
                operation_id,
                archive_sha256,
            } => {
                let session = self.state.addon_status(&current_id).await?;
                let consent = consent_for(&session, &operation_id, &archive_sha256, now_ms())?;
                if let Some(previous) = read_consent(client)? {
                    if previous != consent {
                        return Err(error(
                            AddonErrorCode::NeedsReconciliation,
                            "A different native approval is still pending",
                        ));
                    }
                }
                client
                    .directory
                    .write("native-consent.json", &encode(&consent)?)?;
                to_value(consent)
            }
            Request::Report {
                operation_id,
                outcome,
            } => self
                .state
                .addon_report(&current_id, &operation_id, outcome)
                .await
                .and_then(to_value),
            Request::BeginUninstall { addon_id } => self
                .state
                .addon_begin_uninstall(&current_id, &addon_id)
                .await
                .and_then(to_value),
            Request::Prepare { .. } | Request::Stage { .. } => unreachable!(),
        };
        // Persist before returning a path or acknowledging a state change.
        // On failure the engine receives no handoff, while the core retains
        // its pending receipt for explicit reconciliation.
        let current = self.state.addon_status(&current_id).await?;
        write_mirror(client, &current)?;
        result
    }
}

fn session_id(client: &Client) -> Result<String, AddonError> {
    client
        .session_id
        .lock()
        .map(|s| s.clone())
        .map_err(|_| error(AddonErrorCode::Io, "Addon session lock failed"))
}

fn durable_pending(operation: Option<&AddonSnapshot>) -> Option<&AddonSnapshot> {
    operation.filter(|o| {
        matches!(
            o.phase,
            AddonPhase::HandedOff
                | AddonPhase::Staged
                | AddonPhase::NeedsReconciliation
                | AddonPhase::Uninstalling
        )
    })
}

fn consent_for(
    session: &AddonSession,
    operation_id: &str,
    archive_sha256: &str,
    now: u64,
) -> Result<NativeConsent, AddonError> {
    let pending = session
        .operation
        .as_ref()
        .filter(|operation| {
            operation.phase == AddonPhase::HandedOff && operation.operation_id == operation_id
        })
        .ok_or_else(|| {
            error(
                AddonErrorCode::InvalidRequest,
                "Native approval requires the current engine handoff",
            )
        })?;
    let candidate = pending
        .candidate
        .as_ref()
        .filter(|candidate| {
            candidate.archive_sha256 == archive_sha256 && candidate.operation_id == operation_id
        })
        .ok_or_else(|| {
            error(
                AddonErrorCode::InvalidRequest,
                "Native approval does not match the verified package",
            )
        })?;
    if candidate.expires_at_ms <= now {
        return Err(error(
            AddonErrorCode::Expired,
            "Review the package again before approving",
        ));
    }
    Ok(NativeConsent {
        protocol: 1,
        profile_id: session.profile_id.clone(),
        operation_id: operation_id.to_owned(),
        addon_id: candidate.addon_id.clone(),
        version: candidate.version.clone(),
        archive_sha256: candidate.archive_sha256.clone(),
    })
}

fn read_consent(client: &Client) -> Result<Option<NativeConsent>, AddonError> {
    client
        .directory
        .read("native-consent.json", 4096)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|_| {
                error(
                    AddonErrorCode::NeedsReconciliation,
                    "Native approval receipt is invalid",
                )
            })
        })
        .transpose()
}

fn write_mirror(client: &Client, session: &AddonSession) -> Result<(), AddonError> {
    if session.profile_id != client.profile_id || session.engine != AddonEngine::Gecko {
        return Err(error(
            AddonErrorCode::NeedsReconciliation,
            "Addon session changed profile",
        ));
    }
    let mirror = Mirror {
        protocol: 1,
        profile_id: session.profile_id.clone(),
        managed: session.managed.clone(),
        pending: durable_pending(session.operation.as_ref()).cloned(),
    };
    let bytes = encode(&mirror)?;
    if bytes.len() as u64 > MAX_MIRROR_BYTES {
        return Err(error(
            AddonErrorCode::LimitExceeded,
            "Addon startup receipts exceed limit",
        ));
    }
    client.directory.write("mirror.json", &bytes)?;
    if let Some(consent) = read_consent(client)? {
        match durable_pending(session.operation.as_ref())
            .filter(|operation| operation.candidate.is_some())
        {
            Some(pending) if consent.matches(session, pending) => {}
            Some(_) => {
                return Err(error(
                    AddonErrorCode::NeedsReconciliation,
                    "Native approval and pending package disagree",
                ))
            }
            // A committed installation is protected by its durable ownership
            // receipt. Confirmed absence/cancellation needs no approval marker.
            None => client.directory.remove("native-consent.json")?,
        }
    }
    Ok(())
}

fn validate_mirror_continuity(old: &Mirror, current: &AddonSession) -> Result<(), AddonError> {
    if old.protocol != 1 || old.profile_id != current.profile_id {
        return Err(error(
            AddonErrorCode::NeedsReconciliation,
            "Addon startup receipts belong to a different profile",
        ));
    }
    // A prior reply may have been lost after the core committed. Only the
    // exact already-approved candidate can explain an ownership difference.
    let candidate = old
        .pending
        .as_ref()
        .and_then(|p| p.candidate.as_ref())
        .map(AddonOwnership::from);
    let unchanged = old.managed.iter().all(|o| current.managed.contains(o))
        && current.managed.iter().all(|o| old.managed.contains(o));
    let promoted = candidate.as_ref().is_some_and(|approved| {
        current.managed.contains(approved)
            && old
                .managed
                .iter()
                .filter(|o| o.addon_id != approved.addon_id)
                .all(|o| current.managed.contains(o))
            && current
                .managed
                .iter()
                .filter(|o| o.addon_id != approved.addon_id)
                .all(|o| old.managed.contains(o))
    });
    let uninstalled = old
        .pending
        .as_ref()
        .filter(|p| {
            matches!(
                p.phase,
                AddonPhase::Uninstalling | AddonPhase::NeedsReconciliation
            ) && p.candidate.is_none()
        })
        .and_then(|p| p.uninstall_id.as_ref())
        .is_some_and(|id| {
            !current.managed.iter().any(|o| &o.addon_id == id)
                && old
                    .managed
                    .iter()
                    .filter(|o| &o.addon_id != id)
                    .all(|o| current.managed.contains(o))
                && current.managed.iter().all(|o| old.managed.contains(o))
        });
    if !unchanged && !promoted && !uninstalled {
        return Err(error(
            AddonErrorCode::NeedsReconciliation,
            "Core and browser addon receipts disagree",
        ));
    }
    if let Some(pending) = &old.pending {
        let retained = durable_pending(current.operation.as_ref()).is_some_and(|p| {
            p.operation_id == pending.operation_id
                && p.candidate == pending.candidate
                && p.uninstall_id == pending.uninstall_id
        });
        // The core may have durably reconciled an absent/unchanged engine
        // before the previous broker could replace its mirror. Only that
        // exact terminal receipt explains cancellation without ownership
        // changes. A missing core pending record alone proves nothing.
        let cancelled = unchanged
            && durable_pending(Some(pending)).is_some()
            && current.operation.as_ref().is_some_and(|completed| {
                completed.phase == AddonPhase::Cancelled
                    && completed.operation_id == pending.operation_id
                    && completed.candidate == pending.candidate
                    && completed.uninstall_id == pending.uninstall_id
            });
        if !retained && !promoted && !uninstalled && !cancelled {
            return Err(error(
                AddonErrorCode::NeedsReconciliation,
                "Pending browser outcome requires reconciliation",
            ));
        }
    }
    Ok(())
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, AddonError> {
    serde_json::to_vec(value).map_err(|_| error(AddonErrorCode::Io, "Cannot encode addon state"))
}
fn to_value(value: impl Serialize) -> Result<serde_json::Value, AddonError> {
    serde_json::to_value(value).map_err(|_| error(AddonErrorCode::Io, "Cannot encode addon state"))
}

struct Auth {
    client_id: String,
    nonce: String,
    timestamp: String,
    time: u64,
    mac: String,
}
impl Auth {
    fn read(headers: &HeaderMap) -> Option<Self> {
        fn one(headers: &HeaderMap, name: &str) -> Option<String> {
            let mut values = headers.get_all(name).iter();
            let value = values.next()?.to_str().ok()?;
            if values.next().is_some() {
                return None;
            }
            Some(value.to_owned())
        }
        let client_id = one(headers, "x-epix-addon-client")?;
        let nonce = one(headers, "x-epix-addon-nonce")?;
        let timestamp = one(headers, "x-epix-addon-time")?;
        let mac = one(headers, "x-epix-addon-mac")?;
        if !valid_id(&client_id) || !valid_id(&nonce) || !valid_id(&mac) || timestamp.len() > 20 {
            return None;
        }
        let time: u64 = timestamp.parse().ok()?;
        if time.to_string() != timestamp {
            return None;
        }
        Some(Self {
            client_id,
            nonce,
            timestamp,
            time,
            mac,
        })
    }
}

fn authenticator(
    secret: &str,
    domain: &[u8],
    auth: &Auth,
    status: Option<u16>,
    body: &[u8],
) -> Option<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(domain);
    fn field(mac: &mut HmacSha256, bytes: &[u8]) {
        mac.update(&(bytes.len() as u64).to_be_bytes());
        mac.update(bytes);
    }
    field(&mut mac, auth.client_id.as_bytes());
    field(&mut mac, auth.nonce.as_bytes());
    field(&mut mac, auth.timestamp.as_bytes());
    if let Some(status) = status {
        mac.update(&status.to_be_bytes());
    }
    field(&mut mac, body);
    Some(mac)
}

pub(crate) async fn serve(
    State(ctx): State<crate::Ctx>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "Native addon authentication failed").into_response();
    }
    let Some((client, auth)) = ctx.addon_broker.authenticate(&headers, &body, now_ms()) else {
        return (StatusCode::FORBIDDEN, "Native addon authentication failed").into_response();
    };
    let result = match serde_json::from_slice::<Request>(&body) {
        Ok(request) => ctx.addon_broker.dispatch(&client, request).await,
        Err(_) => Err(error(
            AddonErrorCode::InvalidRequest,
            "Invalid native addon request",
        )),
    };
    let (status, value) = match result {
        Ok(result) => (
            StatusCode::OK,
            serde_json::json!({"ok": true, "result": result}),
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": error}),
        ),
    };
    let Ok(bytes) = serde_json::to_vec(&value) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Some(mac) = authenticator(
        &client.secret,
        RESPONSE_DOMAIN,
        &auth,
        Some(status.as_u16()),
        &bytes,
    ) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mac = hex::encode(mac.finalize().into_bytes());
    (
        status,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
            ("x-epix-addon-mac", mac.as_str()),
        ],
        bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_interrupts_handoff_waiting_for_signed_authority() {
        use epix_xite::XiteStorage;
        use std::io::{Cursor, Write};
        use std::time::Duration;

        let root = tempfile::tempdir().unwrap();
        let profile = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("private")).unwrap();
        let state = AppState::with_data_dir("test", root.path());
        let key = epix_crypt::new_private_key();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let storage = XiteStorage::new(root.path().join("data").join(&address));
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        archive
            .start_file("manifest.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(br#"{"manifest_version":2,"name":"Cancellation fixture","version":"1.0","browser_specific_settings":{"gecko":{"id":"cancel@example.test"}}}"#).unwrap();
        let bytes = archive.finish().unwrap().into_inner();
        storage.write("extension.xpi", &bytes).unwrap();
        let mut content = serde_json::json!({"address":address,"inner_path":"content.json","modified":1,"files":{"extension.xpi":{"size":bytes.len(),"b3":blake3::hash(&bytes).to_hex().to_string(),"sha512":XiteStorage::hash_bytes(&bytes)}}});
        epix_content::sign(&mut content, &key).unwrap();
        storage
            .write(
                "content.json",
                epix_content::dumps_content(&content).as_bytes(),
            )
            .unwrap();
        state
            .add_xite(
                &address,
                crate::XiteEntry {
                    storage,
                    content: Some(content),
                },
            )
            .await;
        let broker = AddonBroker::new(state.clone());
        let launch = broker
            .register_profile(profile.path(), "127.0.0.1:43110".parse().unwrap())
            .await
            .unwrap();
        let client = broker
            .clients
            .lock()
            .unwrap()
            .get(&launch.client_id)
            .unwrap()
            .clone();
        broker
            .dispatch(
                &client,
                Request::Reconcile {
                    inventory: AddonInventory {
                        addons: vec![],
                        has_pending_installs: false,
                    },
                },
            )
            .await
            .unwrap();
        let candidate: AddonCandidate = serde_json::from_value(
            broker
                .dispatch(
                    &client,
                    Request::Prepare {
                        source_url: format!("https://{address}.epix/extension.xpi"),
                        action: AddonAction::Install,
                    },
                )
                .await
                .unwrap(),
        )
        .unwrap();
        let authority = state.addon_hold_authority_for_test(&address).await;
        let operation = candidate.operation_id.clone();
        let stage_broker = broker.clone();
        let stage_client = client.clone();
        let mut stage = tokio::spawn(async move {
            stage_broker
                .dispatch(
                    &stage_client,
                    Request::Stage {
                        operation_id: candidate.operation_id,
                        archive_sha256: candidate.archive_sha256,
                    },
                )
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut stage)
                .await
                .is_err(),
            "handoff must wait for the held authority lock"
        );
        let cancelled = tokio::time::timeout(
            Duration::from_secs(1),
            broker.dispatch(
                &client,
                Request::Cancel {
                    operation_id: Some(operation),
                },
            ),
        )
        .await
        .expect("Cancel must reach the core while Stage waits for authority")
        .unwrap();
        let cancelled: AddonSnapshot = serde_json::from_value(cancelled).unwrap();
        assert_eq!(cancelled.phase, AddonPhase::Cancelled);
        let result = tokio::time::timeout(Duration::from_secs(1), &mut stage)
            .await
            .expect("cancelled handoff must finish without releasing authority")
            .unwrap();
        assert_eq!(result.unwrap_err().code, AddonErrorCode::Cancelled);
        let mirror: Mirror = serde_json::from_slice(
            &client
                .directory
                .read("mirror.json", MAX_MIRROR_BYTES)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(mirror.pending.is_none());
        assert!(read_consent(&client).unwrap().is_none());
        drop(authority);
    }

    fn handed_off_session() -> AddonSession {
        let candidate = AddonCandidate {
            operation_id: "33".repeat(32),
            source_url: "https://test.epix/addon.xpi".into(),
            publisher: "test".into(),
            inner_path: "addon.xpi".into(),
            governing_manifest: "content.json".into(),
            archive_sha256: "44".repeat(32),
            byte_length: 100,
            addon_id: "addon@example.invalid".into(),
            version: "1.0".into(),
            name: "Fixture".into(),
            manifest_version: 2,
            required_permissions: vec![],
            optional_permissions: vec![],
            host_permissions: vec![],
            optional_host_permissions: vec![],
            expires_at_ms: 1_000_000,
            engine: AddonEngine::Gecko,
        };
        AddonSession {
            session_id: "55".repeat(32),
            profile_id: "11".repeat(32),
            engine: AddonEngine::Gecko,
            needs_reconciliation: true,
            managed: vec![],
            operation: Some(AddonSnapshot {
                operation_id: candidate.operation_id.clone(),
                phase: AddonPhase::HandedOff,
                candidate: Some(candidate),
                message: None,
                uninstall_id: None,
            }),
        }
    }

    #[test]
    fn native_consent_requires_exact_live_handoff_and_survives_uncertainty() {
        let dir = tempfile::tempdir().unwrap();
        let client = test_client(dir.path());
        let mut session = handed_off_session();
        let operation = "33".repeat(32);
        let hash = "44".repeat(32);
        assert!(consent_for(&session, &operation, &"66".repeat(32), 1).is_err());
        assert!(consent_for(&session, &"66".repeat(32), &hash, 1).is_err());
        assert!(consent_for(&session, &operation, &hash, 1_000_000).is_err());
        session.operation.as_mut().unwrap().phase = AddonPhase::Ready;
        assert!(consent_for(&session, &operation, &hash, 1).is_err());
        session.operation.as_mut().unwrap().phase = AddonPhase::HandedOff;
        // Staging does not itself create a native Allow receipt.
        write_mirror(&client, &session).unwrap();
        assert!(read_consent(&client).unwrap().is_none());
        let consent = consent_for(&session, &operation, &hash, 1).unwrap();
        client
            .directory
            .write("native-consent.json", &encode(&consent).unwrap())
            .unwrap();
        session.operation.as_mut().unwrap().phase = AddonPhase::NeedsReconciliation;
        write_mirror(&client, &session).unwrap();
        assert!(read_consent(&client)
            .unwrap()
            .unwrap()
            .matches(&session, session.operation.as_ref().unwrap()));
        session.operation.as_mut().unwrap().phase = AddonPhase::Cancelled;
        write_mirror(&client, &session).unwrap();
        assert!(read_consent(&client).unwrap().is_none());
    }

    #[test]
    fn lost_uninstall_reply_recovers_only_the_exact_recorded_target() {
        let owner = AddonOwnership {
            addon_id: "addon@example.invalid".into(),
            version: "1.0".into(),
            archive_sha256: "11".repeat(32),
            publisher: "test".into(),
            inner_path: "addon.xpi".into(),
            source_url: "https://test.epix/addon.xpi".into(),
            engine: AddonEngine::Gecko,
        };
        let mut old = Mirror {
            protocol: 1,
            profile_id: "22".repeat(32),
            managed: vec![owner.clone()],
            pending: Some(AddonSnapshot {
                operation_id: "33".repeat(32),
                phase: AddonPhase::NeedsReconciliation,
                candidate: None,
                message: None,
                uninstall_id: Some(owner.addon_id.clone()),
            }),
        };
        let current = AddonSession {
            session_id: "44".repeat(32),
            profile_id: old.profile_id.clone(),
            engine: AddonEngine::Gecko,
            needs_reconciliation: true,
            managed: vec![],
            operation: None,
        };
        validate_mirror_continuity(&old, &current).unwrap();
        old.pending.as_mut().unwrap().uninstall_id = Some("other@example.invalid".into());
        assert!(validate_mirror_continuity(&old, &current).is_err());
        old.pending = None;
        assert!(validate_mirror_continuity(&old, &current).is_err());
    }

    #[test]
    fn lost_cancelled_reconciliation_reply_requires_exact_durable_completion() {
        let mut current = handed_off_session();
        let old = Mirror {
            protocol: 1,
            profile_id: current.profile_id.clone(),
            managed: current.managed.clone(),
            pending: current.operation.clone(),
        };
        current.operation.as_mut().unwrap().phase = AddonPhase::Cancelled;
        validate_mirror_continuity(&old, &current).unwrap();
        let completed = current.operation.clone();
        current.operation = None;
        assert!(validate_mirror_continuity(&old, &current).is_err());
        current.operation = completed.clone();
        current.operation.as_mut().unwrap().operation_id = "66".repeat(32);
        assert!(validate_mirror_continuity(&old, &current).is_err());
        current.operation = completed.clone();
        current
            .operation
            .as_mut()
            .unwrap()
            .candidate
            .as_mut()
            .unwrap()
            .archive_sha256 = "77".repeat(32);
        assert!(validate_mirror_continuity(&old, &current).is_err());
        current.operation = completed.clone();
        current.operation.as_mut().unwrap().uninstall_id = Some("other@example.invalid".into());
        assert!(validate_mirror_continuity(&old, &current).is_err());
        current.operation = completed;
        current.operation.as_mut().unwrap().phase = AddonPhase::Installed;
        assert!(validate_mirror_continuity(&old, &current).is_err());
    }

    #[tokio::test]
    async fn http_endpoint_authenticates_both_directions_and_rejects_replay() {
        use axum::{body::Body, http::Request as HttpRequest};
        use tower::ServiceExt;
        let root = tempfile::tempdir().unwrap();
        let profile = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("private")).unwrap();
        let state = AppState::with_data_dir("test", root.path());
        let server = crate::UiServer::new(state);
        let broker = server.addon_broker();
        let launch = broker
            .register_profile(profile.path(), "127.0.0.1:43110".parse().unwrap())
            .await
            .unwrap();
        let metadata = std::fs::read(profile.path().join("epix-addons/client.json")).unwrap();
        assert!(!String::from_utf8(metadata)
            .unwrap()
            .contains(&launch.secret));
        let body = br#"{"command":"open"}"#;
        let headers = signed_headers(
            &launch.secret,
            &launch.client_id,
            &"77".repeat(32),
            now_ms(),
            body,
        );
        let request = || {
            let mut request = HttpRequest::builder()
                .method("POST")
                .uri(PATH)
                .header("host", "127.0.0.1:43110")
                .header("content-type", "application/json")
                .extension(ConnectInfo(
                    "127.0.0.1:43111".parse::<SocketAddr>().unwrap(),
                ))
                .body(Body::from(body.as_slice()))
                .unwrap();
            request.headers_mut().extend(headers.clone());
            request
        };
        let response = server.router().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let signed = hex::decode(response.headers()["x-epix-addon-mac"].to_str().unwrap()).unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), MAX_MIRROR_BYTES as usize)
            .await
            .unwrap();
        let auth = Auth::read(&headers).unwrap();
        authenticator(&launch.secret, RESPONSE_DOMAIN, &auth, Some(200), &bytes)
            .unwrap()
            .verify_slice(&signed)
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["result"]["profile_id"], launch.profile_id);
        assert_eq!(parsed["result"]["needs_reconciliation"], true);
        let replay = server.router().oneshot(request()).await.unwrap();
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
        assert!(replay.headers().get("x-epix-addon-mac").is_none());
    }

    #[tokio::test]
    async fn route_accepts_complete_inventory_at_field_limits() {
        use axum::{body::Body, http::Request as HttpRequest};
        use tower::ServiceExt;
        let root = tempfile::tempdir().unwrap();
        let profile = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("private")).unwrap();
        let server = crate::UiServer::new(AppState::with_data_dir("test", root.path()));
        let launch = server
            .addon_broker()
            .register_profile(profile.path(), "127.0.0.1:43110".parse().unwrap())
            .await
            .unwrap();
        let inventory = AddonInventory {
            addons: (0..2048)
                .map(|i| AddonInstalled {
                    // Foreign engine entries are length-bounded, not package
                    // manifest IDs. Exercise the largest accepted encoding.
                    addon_id: format!("{i:04}{}", "\u{0001}".repeat(251)),
                    version: "\u{0001}".repeat(128),
                    archive_sha256: Some("11".repeat(32)),
                    enabled: false,
                })
                .collect(),
            has_pending_installs: false,
        };
        let body = serde_json::to_vec(&serde_json::json!({
            "command": "reconcile", "inventory": inventory
        }))
        .unwrap();
        assert!(body.len() > 4 * 1024 * 1024);
        assert!(body.len() < MAX_REQUEST_BYTES);
        let headers = signed_headers(
            &launch.secret,
            &launch.client_id,
            &"88".repeat(32),
            now_ms(),
            &body,
        );
        let mut request = HttpRequest::builder()
            .method("POST")
            .uri(PATH)
            .header("host", "127.0.0.1:43110")
            .header("content-type", "application/json")
            .extension(ConnectInfo(
                "127.0.0.1:43111".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(body))
            .unwrap();
        request.headers_mut().extend(headers);
        let response = server.router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), MAX_MIRROR_BYTES as usize)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["result"]["needs_reconciliation"], false);
        assert_eq!(result["result"]["managed"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn route_rejects_large_bodies_before_dispatch() {
        use axum::{body::Body, http::Request as HttpRequest};
        use tower::ServiceExt;
        let server = crate::UiServer::new(AppState::new("test"));
        let request = HttpRequest::builder()
            .method("POST")
            .uri(PATH)
            .header("host", "127.0.0.1:43110")
            .extension(ConnectInfo(
                "127.0.0.1:43111".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(vec![b'x'; MAX_REQUEST_BYTES + 1]))
            .unwrap();
        assert_eq!(
            server.router().oneshot(request).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn protocol_matches_independent_hmac_vectors() {
        let auth = Auth {
            client_id: "22".repeat(32),
            nonce: "33".repeat(32),
            timestamp: "1793055000000".into(),
            time: 1_793_055_000_000,
            mac: String::new(),
        };
        let request = authenticator(
            &"11".repeat(32),
            REQUEST_DOMAIN,
            &auth,
            None,
            br#"{"command":"status"}"#,
        )
        .unwrap()
        .finalize()
        .into_bytes();
        let response = authenticator(
            &"11".repeat(32),
            RESPONSE_DOMAIN,
            &auth,
            Some(200),
            br#"{"ok":true,"result":null}"#,
        )
        .unwrap()
        .finalize()
        .into_bytes();
        assert_eq!(
            hex::encode(request),
            "c3eb00558bb43f3b629c3d0b0aa3fed50fba220446451b808c5ca12ec236165c"
        );
        assert_eq!(
            hex::encode(response),
            "7628e26d50fb7fb0cfbeddd504d4fde18109ec19263c3ac4fa34c44046cfcb77"
        );
    }

    fn signed_headers(
        secret: &str,
        client_id: &str,
        nonce: &str,
        time: u64,
        body: &[u8],
    ) -> HeaderMap {
        let auth = Auth {
            client_id: client_id.into(),
            nonce: nonce.into(),
            timestamp: time.to_string(),
            time,
            mac: String::new(),
        };
        let mac = hex::encode(
            authenticator(secret, REQUEST_DOMAIN, &auth, None, body)
                .unwrap()
                .finalize()
                .into_bytes(),
        );
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-epix-addon-client", client_id),
            ("x-epix-addon-nonce", nonce),
            ("x-epix-addon-time", &auth.timestamp),
            ("x-epix-addon-mac", &mac),
        ] {
            headers.insert(name, value.parse().unwrap());
        }
        headers
    }

    fn test_client(directory: &Path) -> Arc<Client> {
        Arc::new(Client {
            profile_id: "11".repeat(32),
            secret: "22".repeat(32),
            directory: ProtectedDirectory::open_child(directory, "native").unwrap(),
            session_id: Mutex::new("33".repeat(32)),
            nonces: Mutex::new(HashMap::new()),
            control: tokio::sync::Mutex::new(()),
        })
    }

    #[test]
    fn requests_require_exact_body_profile_nonce_time_and_no_page_origin() {
        let dir = tempfile::tempdir().unwrap();
        let broker = AddonBroker::new(AppState::new("test"));
        let client = test_client(dir.path());
        let id = "44".repeat(32);
        broker
            .clients
            .lock()
            .unwrap()
            .insert(id.clone(), client.clone());
        let nonce = "55".repeat(32);
        let body = br#"{"command":"status"}"#;
        let headers = signed_headers(&client.secret, &id, &nonce, 1_000_000, body);
        assert!(broker.authenticate(&headers, b"{}", 1_000_000).is_none());
        assert!(broker.authenticate(&headers, body, 1_060_001).is_none());
        let mut page = headers.clone();
        page.insert("origin", "null".parse().unwrap());
        assert!(broker.authenticate(&page, body, 1_000_000).is_none());
        let mut wrong_profile = headers.clone();
        wrong_profile.insert("x-epix-addon-client", "66".repeat(32).parse().unwrap());
        assert!(broker
            .authenticate(&wrong_profile, body, 1_000_000)
            .is_none());
        assert!(broker.authenticate(&headers, body, 1_000_000).is_some());
        assert!(broker.authenticate(&headers, body, 1_000_000).is_none());
    }

    #[test]
    fn response_signature_cannot_be_reused_for_another_status_or_request() {
        let secret = "11".repeat(32);
        let auth = Auth {
            client_id: "22".repeat(32),
            nonce: "33".repeat(32),
            timestamp: "1000000".into(),
            time: 1_000_000,
            mac: String::new(),
        };
        let body = br#"{"ok":false}"#;
        let signed = authenticator(&secret, RESPONSE_DOMAIN, &auth, Some(400), body)
            .unwrap()
            .finalize()
            .into_bytes();
        assert!(
            authenticator(&secret, RESPONSE_DOMAIN, &auth, Some(400), body)
                .unwrap()
                .verify_slice(&signed)
                .is_ok()
        );
        assert!(
            authenticator(&secret, RESPONSE_DOMAIN, &auth, Some(200), body)
                .unwrap()
                .verify_slice(&signed)
                .is_err()
        );
        assert!(authenticator(&secret, REQUEST_DOMAIN, &auth, None, body)
            .unwrap()
            .verify_slice(&signed)
            .is_err());
        assert!(
            authenticator(&secret, RESPONSE_DOMAIN, &auth, Some(400), b"{}")
                .unwrap()
                .verify_slice(&signed)
                .is_err()
        );
    }

    #[test]
    fn duplicate_headers_and_oversized_request_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let broker = AddonBroker::new(AppState::new("test"));
        let client = test_client(dir.path());
        let id = "44".repeat(32);
        broker
            .clients
            .lock()
            .unwrap()
            .insert(id.clone(), client.clone());
        let body = vec![b'x'; MAX_REQUEST_BYTES + 1];
        let mut headers = signed_headers(&client.secret, &id, &"55".repeat(32), 1_000_000, &body);
        assert!(broker.authenticate(&headers, &body, 1_000_000).is_none());
        headers.append("x-epix-addon-time", "1000000".parse().unwrap());
        assert!(Auth::read(&headers).is_none());
    }

    #[test]
    fn native_requests_cannot_supply_paths_profiles_or_sessions() {
        for body in [
            r#"{"command":"open","profile_id":"other"}"#,
            r#"{"command":"stage","operation_id":"op","archive_sha256":"hash","path":"/tmp/other.xpi"}"#,
            r#"{"command":"status","session_id":"other"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(body).is_err());
        }
    }
}
