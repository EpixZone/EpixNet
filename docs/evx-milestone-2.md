# EVX Milestone 2: real activation and grants

Milestone 1 (`docs/evx.md`) runs a signed fixture envelope through the
contained supervisor. Milestone 2 replaces the fixture with EpixNet's real
authority chain and gives the node a consent path and a management API, so a
xite's published program can be inspected, granted, run once and revoked on
a real node. Background scheduling is Milestone 3 and is out of scope here;
so are retained streams, publication and chain operations.

The plan this implements is `epixnet-process-platform-plan.md` sections
"Xite declaration in content.json" and "Explicit consent, management API,
and /list". Its rules in one line each: publisher requests never self-grant;
unsupported requirements disable the affected work rather than degrade
silently; authenticated updates within an existing grant activate without a
new prompt; broader authority waits for a new grant; a denied activation
never advances the version floor; grants, workspaces and journals live
outside every served root; a page cannot mint, widen or forge a grant.

## Components

### 1. `crates/evx-declaration` (new, pure)

Strict parser and manifest binder for the signed `evx` section of a root
`content.json`. No I/O except through a caller-supplied file reader.

```rust
pub struct Declaration { pub version: u64, pub programs: BTreeMap<String, Program>, pub jobs: BTreeMap<String, Job>, pub unsupported: Vec<Unsupported> }
pub struct Program { pub runtime_profile: String, pub entry: String, pub dependencies: Vec<String>, pub allow_run_once: bool, pub capabilities: BTreeSet<evx_api::Capability>, pub limits: evx_api::Limits }
pub struct Job { pub program: String, pub schedule: Schedule, pub max_concurrency: u32 }
pub enum Schedule { Interval { seconds: u64, anchor: Anchor, missed: Missed } }
pub struct Unsupported { pub path: String, pub reason: String }   // e.g. "streams.presence: retained streams not supported"

pub fn parse_bytes(raw: &[u8]) -> Result<Option<Declaration>, DeclarationError>;            // PRIMARY: strict decode of the stored content.json bytes (duplicate keys refused)
pub fn declaration_digest_bytes(raw: &[u8]) -> Result<Option<String>, DeclarationError>;  // sha256 hex of the canonical (sorted-key, compact) `evx` object, same decode
pub fn parse(content: &serde_json::Value) -> Result<Declaration, DeclarationError>;        // only on a value re-read from bytes the strict decode accepted
pub fn declaration_digest(content: &serde_json::Value) -> Result<String, DeclarationError>;
pub struct BoundProgram { pub program: String, pub entry: PinnedFile, pub dependencies: Vec<PinnedFile>, pub total_bytes: u64 }
pub struct PinnedFile { pub path: String, pub size: u64, pub sha512: String }
pub fn bind(decl: &Declaration, program: &str, content: &serde_json::Value) -> Result<BoundProgram, DeclarationError>; // entry + deps must be in `files` (required, not optional), sizes within evx_activation::MAX_ARTIFACT / MAX_TOTAL
```

Rules: `version` must be exactly 1; every id passes `evx_api::validate_identifier`;
`entry`/`dependencies` pass `evx_api::validate_relative_path`; a capability is
`{"api": "<name>", ...}` and maps onto the closed `evx_api::Capability` set
(`workspace.read`, `workspace.write`, `game.score.get`); an unknown `api`,
runtime profile other than `wasm-core-v1`, a `streams` section, a non-interval
schedule, or limits outside `evx_api::Limits::validate` put the affected
program or job into `unsupported` with a reason and leave the rest usable.
Unknown top-level fields and duplicate keys fail the whole section (strict,
no permissive fallback). Programs that reference undeclared jobs or vice versa
are unsupported. A missing `evx` section is `Ok(None)` at the caller.

### 2. `crates/evx-activation`: content-based activation

Keep the Ed25519 envelope path (fixtures, tests). Add the real one:

```rust
pub enum PublisherAuthority { Ed25519([u8; 32]), RootAddress(String) }   // XiteGrant gains `authority`; `public_key` stays for Ed25519 only
impl ActivationLoader {
    /// `content` must already be verified by the caller as the root content.json signed by `grant.xite`'s owner
    /// (`epix_content::verify_signer(content, xite)` is true). Captures entry + dependencies through `read`,
    /// checks each against the manifest's sha512 and size, and yields the same PendingActivation the envelope path does.
    pub fn verify_content(&self, content: &Value, bound: &BoundProgram, read: &mut dyn FnMut(&str) -> Result<Vec<u8>, AuthenticationError>) -> Result<PendingActivation, AuthenticationError>;
}
```

Version = `content["modified"]` as whole milliseconds (reject non-finite,
negative, or over `i64::MAX`); manifest digest = sha256 of
`epix_content::signed_data(content)`. `admit` and the checkpoint are reused
unchanged, so a denied content activation never advances the floor. The
activation's capabilities are the bound program's and must be a subset of the
grant's; the runtime profile must be in the grant's set. `FrozenActivation`
gains `declaration_digest()` and `program()`.

### 3. `crates/evx-state`: xite grants

Extend the durable model with the persistent grant the plan describes:

```rust
pub struct XiteGrant { pub xite: String, pub publisher: String /* root address */, pub enabled: bool, pub capabilities: BTreeSet<Capability>, pub runtime_profiles: BTreeSet<String>, pub limits: evx_api::Limits, pub allow_run_once: bool, pub allow_background: bool, pub created_unix: u64, pub expires_unix: Option<u64>, pub label: String /* user/device */ }
impl DurableState {
    pub fn set_xite_grant(&self, grant: &XiteGrant) -> Result<Generations>;   // authority generation bumps when enabled/capabilities/profiles/publisher change; limits generation when limits change
    pub fn xite_grant(&self, xite: &str) -> Result<Option<(XiteGrant, Generations)>>;
    pub fn revoke_xite(&self, xite: &str) -> Result<()>;                        // existing `revoke` semantics
    pub fn allow_once(&self, xite: &str, declaration_digest: &str, program: &str) -> Result<String>;  // one-shot token
    pub fn consume_allow_once(&self, xite: &str, token: &str, declaration_digest: &str, program: &str) -> Result<bool>;
    pub fn record_run(&self, xite: &str, run: &RunRecord) -> Result<()>;        // bounded history (keep last 50 per xite)
    pub fn runs(&self, xite: &str) -> Result<Vec<RunRecord>>;
}
```

The existing `GrantPolicy`/`set_grant` stays for the checkpoint/outbox model;
`XiteGrant` is derived into it. All of this lives in the same SQLite file.

### 4. `crates/epix-evx` (new): the node's EVX service and management API

An `epix_plugin::Plugin` named `Evx`, registered in `epix-node` next to the
others when the `evx` feature is enabled on macOS or Linux. Unsupported
targets omit the plugin, including its management commands. Owns an
`EvxService`:

- `DurableState` at `<data_root>/private/evx/state.sqlite`; workspaces at
  `<data_root>/private/evx/workspaces/<address>/`; both outside every served
  root (`data/<address>`). Never under a xite directory.
- Worker binary: `evx-worker` beside the node executable, overridable with
  the `EVX_WORKER` environment variable. Execution requires a supported macOS
  or Linux confinement profile. On those targets, an unavailable worker or
  confinement profile makes runs report `unsupported host`; management
  remains available. Windows and mobile products do not register the plugin.
- Reads the xite's root `content.json` BYTES with `XiteStorage::read_bounded`
  (never the decoded `AppState::content` value, which has already collapsed
  duplicate keys) and accepts it only when `epix_content::verify_signer`
  holds for the xite's address on the decoded value and
  `AppState::xite_core_complete(address)` is true; the declaration and its
  digest come from `parse_bytes` / `declaration_digest_bytes`, and program
  files are read with `XiteStorage::read_bounded` and re-hashed by the
  activation loader.

WebSocket commands (all params are JSON objects; errors use the usual
`{"error": ...}` convention):

| Command | Who | Behaviour |
| --- | --- | --- |
| `evxInspect` | the bound xite's page, or the wrapper | Inert: declaration summary, per-program entry/dependency hashes, declaration digest, requested vs effective capabilities and limits, unsupported items with reasons, grant status, integrity status (`verified` / `unsigned` / `incomplete`). Never compiles or instantiates. |
| `evxStatus` | the bound xite's page, or the wrapper | Grant status, generations, last runs (bounded), paused/revoked reasons. |
| `evxRequest` | the bound xite's page | Records that the page asked; returns the inspect payload for the wrapper's prompt. Grants nothing. |
| `evxGrant` | wrapper / operator socket only | `{xite, declaration_digest, mode: "enable" \| "once", program?, limits?}`. Refused unless `declaration_digest` matches the current verified declaration (expected-version check). `enable` persists a `XiteGrant` covering the declared capabilities and profiles with host-clamped limits; `once` mints an allow-once token for one program. |
| `evxRevoke` | wrapper / operator socket only | Disables the grant; running work is told to stop; nothing published is recalled. |
| `evxSetLimits` | wrapper / operator socket only | Adjusts limits within host policy; limits generation advances; usage is never reset. |
| `evxRunOnce` | wrapper / operator socket only | Runs one program now through `evx_host::run_activation` under the grant or a consumed allow-once token; persists input digest and result; returns the `RunResult`. Effectful; no ADMIN involved. |
| `evxRecoverWorkspace` | wrapper / operator socket only | Explicitly reconciles interrupted manual writes against host-owned provenance. Runs no guest and resumes no job. The wrapper requires a separate user confirmation, without granting the xite global ADMIN. |

Authority: the wrapper-only commands are gated in `epix-ui`'s dispatcher
exactly like `permissionAdd` (`WsSession::elevated(req_id)`, refused on a
restricted gateway except from the operator socket) through a new
`EVX_WRAPPER_COMMANDS` list, so no page id can ever reach them. `ADMIN`
grants nothing here and `evxGrant` grants no `ADMIN`. The `EVX` string is
not a `permissionAdd` permission and the allowlist must not accept it.

### 5. Wrapper consent prompt (`ui/media/all.js`, `ui/wrapper.html`)

An inner `evxRequest` message makes the wrapper call `evxInspect` for its
xite and show a dedicated dialog: xite and publisher, programs, requested
capabilities and limits, triggers, unsupported items, and whether the grant
would also cover authenticated updates. Buttons **Enable EVX for this
xite**, **Allow once**, **Deny**. Deny and dismissal send nothing. Enable or
Allow once send `evxGrant` from the wrapper's own socket with the inspect
payload's `declaration_digest`. The page gets `{cmd: "response", to: id,
result: {granted: bool, mode}}`. No EVX dialog is shown on a public gateway
(`ui_restrict`): the page is answered with an error.

### 6. `/list/<xite>/?evx=1` inspection view (`crates/epix-ui`)

The file manager gains an inert EVX panel built from `evxInspect`'s data:
escaped declaration, hashes, verification status, grant status, unsupported
items. It links programs as downloads, never navigates to active content,
and never compiles anything.

### 7. Tests (acceptance)

- Parser: every malformed shape from the plan (duplicate keys, unknown
  fields, bad ids, path escapes, oversized limits, unknown api, streams)
  fails or lands in `unsupported` exactly as specified; a valid section
  binds entry and dependencies to the manifest hashes.
- Activation: a tampered file, a missing dependency, an unsigned
  `content.json`, a wrong signer, a rollback (`modified` lower than the
  checkpoint) and a profile or capability beyond the grant are all denied,
  and the checkpoint is unchanged after every denial; a valid update inside
  the grant admits without a new grant; one asking for more stays denied
  until a new grant is stored.
- Grants: a page socket cannot run any wrapper-only command, with or
  without an elevated id; a wrapper socket can; a restricted gateway refuses
  all of them except from the operator socket; revocation stops a later run;
  `allow_once` is single-use and bound to the declaration digest.
- Service: workspace and state paths are outside `data/<address>`;
  `evxInspect` on a xite whose entry is a start-function module reports its
  hash without executing (no worker spawned); `evxRunOnce` on macOS runs the
  baseline fixture program end to end through the real worker.
- Wrapper: unit tests in `ui/tests/` for the dialog routing (deny sends
  nothing; enable sends `evxGrant` with the digest; gateway answers error).

## Non-goals in this milestone

Background scheduler and OS wake (M3), retained streams, publication,
chain reads/actions, XPC packaging, Linux/Windows confinement, the resource
dashboard beyond the inspect/status payloads.

## Review corrections

Activation checkpoints are persisted under the workspace admission lease,
before guest execution. Persistence failure denies the run. Replacing consent
revokes brokers using the old authority generation. Updating limits uses an
atomic limits-only transaction, so a concurrent revocation cannot be undone.
The wrapper's publisher-controlled fields are escaped for their specific HTML
or JavaScript context and substituted only once. Consent pages cannot be
framed, and wrapper WebSocket origin checks include the port. See
[`evx-review.md`](evx-review.md) for regression evidence and remaining gates.
