//! The EpixFrame WebSocket command API: a trait-based registry that xites call.
//!
//! This is the seam the plugin system extends - each command is a [`WsCommand`],
//! and plugins register additional commands into the [`CommandRegistry`].

use crate::state::AppState;
use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// The wrapper chrome (all.js) numbers its own WebSocket commands from this
/// base; the inner site page numbers from 1. Commands at or above this id are
/// treated as coming from the trusted wrapper and may run ADMIN actions.
const WRAPPER_ID_BASE: i64 = 1_000_000;

/// Commands that require the ADMIN permission, mirroring EpixNet's
/// `@flag.admin` set. An inner site page can only run these once the user has
/// granted that site ADMIN through the wrapper's permission prompt.
const ADMIN_COMMANDS: &[&str] = &[
    "announcerStats",
    "certList",
    "certSet",
    "channelJoinAllsite",
    "chartDbQuery",
    "chartGetPeerLocations",
    "configList",
    "configSet",
    "consoleLogRead",
    "consoleLogStream",
    "consoleLogStreamRemove",
    "dbRebuild",
    "dbReload",
    "feedQuery",
    "muteList",
    "notificationDismiss",
    "notificationMute",
    "notificationMuteStatus",
    "feedSearch",
    "notificationQuery",
    "optionalLimitSet",
    "optionalLimitStats",
    "peerAdd",
    // permissionAdd is intentionally NOT admin-gated (matches EpixNet): a site
    // grants itself a permission after the user confirms it in the wrapper,
    // over its own non-admin WS. This is how a merger site (Git Epix) gets its
    // Merger:<type> permission.
    "permissionDetails",
    "permissionRemove",
    "pluginConfigSet",
    "pluginList",
    "serverErrors",
    "serverGetWrapperNonce",
    "serverPortcheck",
    "serverShowdirectory",
    "serverShutdown",
    "serverUpdate",
    "sidebarGetHtmlTag",
    "sidebarGetPeers",
    "siteAdd",
    "siteDelete",
    "siteFavourite",
    "siteList",
    "sitePause",
    "siteRecoverPrivatekey",
    "siteReload",
    "siteResume",
    "siteSetAutodownloadBigfileLimit",
    "siteSetAutodownloadoptional",
    "siteSetLimit",
    "siteSetOwned",
    "siteSetSettingsValue",
    "siteUnfavourite",
    "siteblockAdd",
    "siteblockGet",
    "siteblockIgnoreAddSite",
    "siteblockList",
    "siteblockRemove",
    "userList",
    "userLogin",
    "userLogout",
    "userSelectForm",
    "userSet",
    "userSetGlobalSettings",
    "userSetSitePrivatekey",
    "userShowMasterSeed",
    "xidClearCache",
];

/// Whether a command requires ADMIN.
pub fn is_admin_command(cmd: &str) -> bool {
    ADMIN_COMMANDS.contains(&cmd)
}

/// Commands that create or clone a new site - blocked by NoNewSites.
const NEW_SITE_COMMANDS: &[&str] = &["siteAdd", "siteClone", "mergerSiteAdd"];

/// Commands that remove a site - also blocked by NoNewSites, so an operator can
/// lock the node's site set (no adds and no deletes) with one switch.
const DELETE_SITE_COMMANDS: &[&str] = &["siteDelete", "mergerSiteDelete"];

/// Commands that write or delete a xite's files/content. On a restricted
/// (public gateway) node these need genuine ownership of the bound xite, never
/// just the wrapper's elevated id - otherwise any visitor could rewrite or
/// delete files on a site the gateway only serves.
const WRITE_COMMANDS: &[&str] =
    &["fileWrite", "fileDelete", "siteSign", "sitePublish", "certAdd"];

/// ADMIN commands that are read-only and expose nothing sensitive, so a
/// restricted (public gateway) node still answers them - the read-only
/// dashboard a visitor sees needs the site list, network stats, peer info, and
/// the news feed. Everything else in `ADMIN_COMMANDS` (mutations, node config,
/// identities, logs, the master seed) stays server-side only. An allow-list, so
/// a newly added admin command is refused on a gateway until it is vetted here.
const GATEWAY_READ_COMMANDS: &[&str] = &[
    "announcerStats",
    "channelJoinAllsite",
    "chartDbQuery",
    "chartGetPeerLocations",
    "feedQuery",
    "feedSearch",
    "notificationQuery",
    "optionalLimitStats",
    "serverPortcheck",
    "sidebarGetHtmlTag",
    "sidebarGetPeers",
    "siteList",
];

/// Per-connection context handed to every command.
pub struct WsSession {
    pub state: Arc<AppState>,
    /// Unique id of this connection, for per-connection event routing: events
    /// caused by this connection's own commands are not echoed back to it
    /// (EpixNet's `ws != self`), and progress/notification replies to a
    /// command go only to it (EpixNet's `self.cmd`).
    pub id: u64,
    /// The xite address this WebSocket connection is bound to (if any).
    pub xite: Option<String>,
    /// Channels this connection has joined (`channelJoin`), e.g. `siteChanged`.
    /// Server-pushed events are delivered only for joined channels.
    pub channels: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Channels joined via `channelJoinAllsite`: for these, the connection
    /// receives events for *every* xite, not just its bound one (the dashboard
    /// uses this so its Sites panel updates for all sites).
    pub allsite_channels: std::sync::Mutex<std::collections::HashSet<String>>,
    /// A trusted local operator session (the admin Unix socket, reachable only
    /// with filesystem access to the data dir). Trusted sessions bypass the
    /// restricted-gateway gates and NoNewSites, since server-side admin is how
    /// a locked-down node is meant to be changed.
    pub trusted: bool,
}

impl WsSession {
    pub fn new(state: Arc<AppState>, xite: Option<String>) -> Self {
        Self::build(state, xite, false)
    }

    /// A trusted session for the local admin socket: full admin, no gateway
    /// restrictions. Only ever created for the filesystem-guarded Unix socket.
    pub fn new_trusted(state: Arc<AppState>, xite: Option<String>) -> Self {
        Self::build(state, xite, true)
    }

    fn build(state: Arc<AppState>, xite: Option<String>, trusted: bool) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            state,
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            xite,
            channels: std::sync::Mutex::new(std::collections::HashSet::new()),
            allsite_channels: std::sync::Mutex::new(std::collections::HashSet::new()),
            trusted,
        }
    }

    /// The xite address bound to this connection, or an error if none.
    pub fn address(&self) -> Result<&str, String> {
        self.xite.as_deref().ok_or_else(|| "no xite bound to this connection".to_string())
    }

    /// Resolve a possibly cross-origin `inner_path` to `(address, inner_path)`.
    /// A `cors-<address>/<path>` prefix routes to `<address>` when the bound site
    /// holds the `Cors:<address>` permission (the Cors plugin); otherwise the
    /// bound site + path is returned unchanged.
    pub async fn cors_target(&self, inner_path: &str) -> Result<(String, String), String> {
        let bound = self.address()?.to_string();
        if let Some(rest) = inner_path.strip_prefix("cors-") {
            if let Some((addr, inner)) = rest.split_once('/') {
                let perm = format!("Cors:{addr}");
                if self.state.site_permissions(&bound).await.iter().any(|p| *p == perm) {
                    return Ok((addr.to_string(), inner.to_string()));
                }
                return Err(format!("This site has no permission to access site {addr}"));
            }
        }
        Ok((bound, inner_path.to_string()))
    }

    /// Resolve an `inner_path` for a file/optional command to its real target
    /// `(address, inner_path)`, applying both cross-origin routings: a
    /// `cors-<address>/…` prefix (Cors permission) and a
    /// `merged-<type>/<address>/…` prefix (MergerSite). So fileGet, fileRules,
    /// fileNeed, and optionalFileInfo all reach a merged/cors site the same way.
    pub async fn resolve_target(&self, inner_path: &str) -> Result<(String, String), String> {
        let (address, inner) = self.cors_target(inner_path).await?;
        match AppState::split_merged_path(&inner) {
            Some((addr, inner)) => Ok((addr, inner)),
            None => Ok((address, inner)),
        }
    }

    /// Whether this connection has joined `channel`.
    pub fn in_channel(&self, channel: &str) -> bool {
        self.channels.lock().unwrap().contains(channel)
    }

    /// Whether this connection joined `channel` for *all* sites.
    pub fn in_allsite(&self, channel: &str) -> bool {
        self.allsite_channels.lock().unwrap().contains(channel)
    }

    /// Record joined channel(s) from a `channelJoin`/`channelJoinAllsite` param
    /// (accepts `{channels: [...]}`, `{channel: "…"}`, a bare string, or array).
    /// `allsite` also marks them as all-site subscriptions.
    pub fn join_channels(&self, params: &Value, allsite: bool) {
        let names = channel_names(params);
        self.channels.lock().unwrap().extend(names.iter().cloned());
        if allsite {
            self.allsite_channels.lock().unwrap().extend(names);
        }
    }
}

/// Extract channel names from a `channelJoin`/`channelJoinAllsite` param
/// (`{channels: [...]}`, `{channel: "…"}`, a bare string, or array).
fn channel_names(params: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut add = |v: &Value| {
        if let Some(s) = v.as_str() {
            out.push(s.to_string());
        }
    };
    match params {
        Value::String(_) => add(params),
        Value::Array(a) => a.iter().for_each(&mut add),
        Value::Object(o) => {
            if let Some(Value::Array(a)) = o.get("channels") {
                a.iter().for_each(&mut add);
            }
            if let Some(v) = o.get("channel") {
                add(v);
            }
        }
        _ => {}
    }
    out
}

#[async_trait]
pub trait WsCommand: Send + Sync {
    /// The command name as sent by the xite (e.g. `siteInfo`).
    fn name(&self) -> &'static str;
    async fn handle(&self, session: &WsSession, params: &Value) -> Result<Value, String>;
}

/// Maps command names to handlers. Plugins register more.
pub struct CommandRegistry {
    commands: HashMap<&'static str, Arc<dyn WsCommand>>,
    /// Which plugin a command belongs to (built-ins are absent = always on).
    command_plugin: HashMap<&'static str, String>,
}

impl CommandRegistry {
    pub fn empty() -> Self {
        Self { commands: HashMap::new(), command_plugin: HashMap::new() }
    }

    /// The built-in command set (enough for the wrapper + a xite to load).
    pub fn with_defaults() -> Self {
        let mut r = Self::empty();
        for c in default_commands() {
            r.register(c);
        }
        // Multiuser's identity commands only work while the plugin is enabled
        // (it ships disabled; the feature only compiles the code in).
        #[cfg(feature = "multiuser")]
        for cmd in ["userShowMasterSeed", "userList", "userLogin", "userSet", "userLogout"] {
            r.command_plugin.insert(
                r.commands.get(cmd).map(|c| c.name()).unwrap_or(cmd),
                "Multiuser".to_string(),
            );
        }
        r
    }

    pub fn register(&mut self, command: Arc<dyn WsCommand>) {
        self.commands.insert(command.name(), command);
    }

    /// Register a command owned by `plugin`; it is only dispatched while that
    /// plugin is enabled.
    pub fn register_for_plugin(&mut self, plugin: &str, command: Arc<dyn WsCommand>) {
        self.command_plugin.insert(command.name(), plugin.to_string());
        self.register(command);
    }

    pub fn has(&self, cmd: &str) -> bool {
        self.commands.contains_key(cmd)
    }

    /// Dispatch one command. `req_id` is the request id from the xite: the
    /// trusted wrapper chrome sends `id >= 1_000_000` (which the model treats as
    /// ADMIN), while an inner site page sends small ids and is only as
    /// privileged as the permissions the user has granted that site.
    pub async fn dispatch(
        &self,
        session: &WsSession,
        cmd: &str,
        params: &Value,
        req_id: i64,
    ) -> Result<Value, String> {
        // A restricted (internet-facing) node has no trusted admin client. A
        // normal node binds the UI to loopback, so only the local wrapper
        // reaches the command API - it proves itself with an elevated request
        // id, and the dashboard xite it drives holds ADMIN. Behind a reverse
        // proxy (the public gateway) neither holds: any visitor can send the
        // same elevated id, and any visitor can bind their socket to the
        // dashboard address to inherit its ADMIN grant. So when restricted,
        // admin is refused outright and only happens server-side.
        // The local admin socket is a trusted operator channel: it bypasses the
        // gateway restrictions entirely (that is the sanctioned way to change a
        // locked-down node).
        let restrict = session.state.ui_restrict().await && !session.trusted;
        if is_admin_command(cmd) {
            if restrict {
                // A locked gateway still answers the safe read-only admin
                // commands the public dashboard needs (site list, stats, peers,
                // feed); every mutation and sensitive read is server-side only.
                if !GATEWAY_READ_COMMANDS.contains(&cmd) {
                    return Err(format!("{cmd} is disabled on this gateway"));
                }
            } else {
                // Allowed from the trusted admin socket, the wrapper (elevated
                // id), or when the bound site actually holds ADMIN.
                let elevated = session.trusted || req_id >= WRAPPER_ID_BASE;
                let has_admin = match &session.xite {
                    Some(addr) => session.state.site_has_admin(addr).await,
                    None => false,
                };
                if !elevated && !has_admin {
                    return Err(format!("You don't have permission to run {cmd}"));
                }
            }
        }
        // Restricted node: writing or deleting a xite's files needs the node to
        // genuinely own it (hold the signing key). Serving a site never confers
        // write access, and the dashboard's ADMIN grant must not either - the
        // client chooses which site to bind to.
        if restrict && WRITE_COMMANDS.contains(&cmd) {
            let owns = match &session.xite {
                Some(addr) => session.state.xite_owned(addr).await,
                None => false,
            };
            if !owns {
                let msg = "This node is a read-only gateway; changes are disabled here";
                session.state.push_notification("error", msg, 0);
                return Err(msg.into());
            }
        }
        // UiConfig / UiPluginManager: turning the plugin off removes the feature
        // itself, not just its dashboard link - the pages stop loading (see the
        // route handlers) and their commands are declined here, so the only way
        // to change these is server-side (CLI/config file). Without this a
        // client that navigates straight to the command still reaches it.
        if !session.trusted
            && matches!(cmd, "configSet" | "configList")
            && !session.state.plugin_enabled("UiConfig").await
        {
            return Err("The configuration page is disabled on this node".into());
        }
        if !session.trusted
            && matches!(cmd, "pluginConfigSet" | "pluginList")
            && !session.state.plugin_enabled("UiPluginManager").await
        {
            return Err("The plugin manager is disabled on this node".into());
        }
        // NoNewSites: when the operator sets `no_new_sites`, lock the node's site
        // set - refuse commands that add/clone a new site or delete an existing
        // one.
        if !session.trusted
            && NEW_SITE_COMMANDS.contains(&cmd)
            && session.state.no_new_sites().await
        {
            let msg = "Adding new sites is disabled on this node";
            // Also push a toast: the dashboard fires these without a callback,
            // so the plain error response alone is invisible to the user.
            session.state.push_notification("error", msg, 0);
            return Err(msg.into());
        }
        if !session.trusted
            && DELETE_SITE_COMMANDS.contains(&cmd)
            && session.state.no_new_sites().await
        {
            let msg = "Deleting sites is disabled on this node";
            session.state.push_notification("error", msg, 0);
            return Err(msg.into());
        }
        // `as`: run another command in the context of a different xite
        // (EpixNet's actionAs). Allowed for the bound xite itself, or when the
        // CALLER's bound xite holds ADMIN; the inner command re-enters this
        // dispatcher on a rebound session, so its own gates still apply.
        if cmd == "as" {
            let target = params
                .get("address")
                .or_else(|| params.as_array().and_then(|a| a.first()))
                .and_then(|v| v.as_str())
                .ok_or("Missing address")?
                .to_string();
            let inner_cmd = params
                .get("cmd")
                .or_else(|| params.as_array().and_then(|a| a.get(1)))
                .and_then(|v| v.as_str())
                .ok_or("Missing cmd")?
                .to_string();
            let inner_params = params
                .get("params")
                .or_else(|| params.as_array().and_then(|a| a.get(2)))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            let caller_elevated = session.trusted
                || req_id >= WRAPPER_ID_BASE
                || match &session.xite {
                    Some(addr) => session.state.site_has_admin(addr).await,
                    None => false,
                };
            let allowed = caller_elevated || session.xite.as_deref() == Some(target.as_str());
            if !allowed {
                return Err(format!("No permission to run commands as {target}"));
            }
            let rebound = WsSession::new(session.state.clone(), Some(target));
            let inner_id = if caller_elevated { req_id.max(WRAPPER_ID_BASE) } else { req_id };
            return Box::pin(self.dispatch(&rebound, &inner_cmd, &inner_params, inner_id)).await;
        }
        // A command from a disabled plugin behaves as if unregistered.
        if let Some(plugin) = self.command_plugin.get(cmd) {
            if !session.state.plugin_enabled(plugin).await {
                return Ok(Value::Null);
            }
        }
        match self.commands.get(cmd) {
            Some(command) => command.handle(session, params).await,
            None => {
                // Log unimplemented commands so we can see what a xite needs,
                // but don't hard-error (that would break the page mid-load).
                eprintln!("[epix-ui] unhandled ws command: {cmd}");
                Ok(Value::Null)
            }
        }
    }
}

fn default_commands() -> Vec<Arc<dyn WsCommand>> {
    #[allow(unused_mut)]
    let mut cmds: Vec<Arc<dyn WsCommand>> = vec![
        Arc::new(Ping),
        Arc::new(ServerInfo),
        Arc::new(SiteInfo),
        Arc::new(ChannelJoin { cmd: "channelJoin" }),
        Arc::new(ChannelJoin { cmd: "channelJoinAllsite" }),
        Arc::new(AnnouncerInfo),
        Arc::new(PermissionAdd),
        Arc::new(PermissionRemove),
        Arc::new(PermissionDetails),
        Arc::new(MergerSiteList),
        Arc::new(MergerSiteAdd),
        Arc::new(MergerSiteDelete),
        Arc::new(ConfigSet),
        Arc::new(SiteListModifiedFiles),
        Arc::new(SiteAdd),
        Arc::new(SiteClone),
        Arc::new(ServerPortcheck),
        Arc::new(ServerUpdate),
        Arc::new(ServerShutdown),
        Arc::new(FileQuery),
        Arc::new(BadCert),
        Arc::new(SiteSetSettingsValue),
        Arc::new(SiteSign),
        Arc::new(SitePublish),
        Arc::new(FileWrite),
        Arc::new(FileDelete),
        Arc::new(FileRules),
        Arc::new(CorsPermission),
        Arc::new(SiteSetOwned),
        Arc::new(SiteRecoverPrivatekey),
        Arc::new(UserSetSitePrivatekey),
        Arc::new(SiteUpdate),
        Arc::new(SiteServing { cmd: "sitePause", serving: false }),
        Arc::new(SiteServing { cmd: "siteResume", serving: true }),
        Arc::new(SiteDelete),
        Arc::new(SiteSetAutodownloadoptional),
        Arc::new(OptionalHelp),
        Arc::new(OptionalHelpRemove),
        Arc::new(OptionalHelpAll),
        Arc::new(DbRebuild { cmd: "dbReload" }),
        Arc::new(DbRebuild { cmd: "dbRebuild" }),
        Arc::new(SiteFavourite { cmd: "siteFavourite", favorite: true }),
        Arc::new(SiteFavourite { cmd: "siteUnfavourite", favorite: false }),
        Arc::new(PeerAdd),
        Arc::new(ServerShowdirectory),
        Arc::new(XidClearCache),
        Arc::new(SiteblockIgnoreAddSite),
        // CryptMessage
        Arc::new(UserPublickey),
        Arc::new(EciesEncrypt),
        Arc::new(EciesDecrypt),
        Arc::new(AesEncrypt),
        Arc::new(AesDecrypt),
        Arc::new(EcdsaVerify),
        Arc::new(EcdsaSign),
        // Chain: Vrf randomness + XidResolver.
        Arc::new(VrfGetBeacon),
        Arc::new(VrfLatestBeacon),
        Arc::new(VrfMultiBlockBeacon),
        Arc::new(VrfDeriveRandom),
        Arc::new(VrfInvalidateCache),
        Arc::new(XidResolveName),
        Arc::new(EccPrivToPub),
        Arc::new(EccPubToAddr),
        Arc::new(UserGetSettings),
        Arc::new(UserSetSettings),
        // OptionalManager
        Arc::new(FileNeed),
        Arc::new(OptionalFileList),
        Arc::new(OptionalFileInfo),
        Arc::new(OptionalFileDelete),
        Arc::new(OptionalFilePin { pin: true }),
        Arc::new(OptionalFilePin { pin: false }),
        Arc::new(OptionalLimitStats),
        Arc::new(OptionalLimitSet),
        Arc::new(DbQuery),
        // xID identity resolution (the XidResolver plugin's WS API;
        // xidResolveName is registered with the chain commands above).
        Arc::new(XidResolve),
        Arc::new(XidResolveBatch),
        // Dashboard polling / lists - benign empty values.
        Arc::new(ServerErrors),
        Arc::new(ConfigList),
        Arc::new(PluginList),
        Arc::new(PluginConfigSet),
        Arc::new(ConsoleLogRead),
        Arc::new(ConsoleLogStream),
        Arc::new(ConsoleLogStreamRemove),
        Arc::new(ChartGetPeerLocations),
        Arc::new(AnnouncerStats),
        Arc::new(SiteList),
        Arc::new(ChartDbQuery),
        Arc::new(NotificationQuery),
        Arc::new(NotificationSubscribe),
        Arc::new(NotificationList),
        Arc::new(NotificationMute),
        Arc::new(NotificationMuteStatus),
        Arc::new(NotificationDismiss),
        Arc::new(NotificationDismissSelf),
        Arc::new(FeedQuery),
        Arc::new(FeedSearch),
        Arc::new(FeedFollow),
        Arc::new(FeedListFollow),
        Arc::new(simple("FilterIncludeList", json!([]))),
        Arc::new(simple("filterIncludeList", json!([]))),
        Arc::new(MuteAdd),
        Arc::new(MuteRemove),
        Arc::new(MuteList),
        Arc::new(SiteblockAdd),
        Arc::new(SiteblockRemove),
        Arc::new(SiteblockList),
        Arc::new(SiteblockGet),
        // Stateful - persist global settings so theme changes don't reload-loop.
        Arc::new(UserGetGlobalSettings),
        Arc::new(UserSetGlobalSettings),
        Arc::new(WrapperNonce),
        Arc::new(FileGet),
        // Certs: obtain + select an ID-provider identity.
        Arc::new(CertAdd),
        Arc::new(CertSelect),
        Arc::new(CertSet),
        Arc::new(CertList),
        Arc::new(CertXid),
        // File listing + site maintenance + feed search.
        Arc::new(DirList),
        Arc::new(FileList),
        Arc::new(SiteReload),
        Arc::new(SiteBadFiles),
        Arc::new(GetTrackers),
        // Bigfile authoring.
        Arc::new(BigfileUploadInit),
        Arc::new(SiteSetAutodownloadBigfileLimit),
    ];
    // Multiuser: identity login/switch commands (desktop only).
    #[cfg(feature = "multiuser")]
    {
        cmds.push(Arc::new(UserShowMasterSeed));
        cmds.push(Arc::new(UserList));
        cmds.push(Arc::new(UserLogin));
        cmds.push(Arc::new(UserSet));
        cmds.push(Arc::new(UserLogout));
    }
    cmds
}

struct UserGetGlobalSettings;
#[async_trait]
impl WsCommand for UserGetGlobalSettings {
    fn name(&self) -> &'static str {
        "userGetGlobalSettings"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.global_settings().await)
    }
}

struct UserSetGlobalSettings;
#[async_trait]
impl WsCommand for UserSetGlobalSettings {
    fn name(&self) -> &'static str {
        "userSetGlobalSettings"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        // Called as `userSetGlobalSettings([settings])` or with a bare object.
        let settings = p
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or_else(|| p.clone());
        if settings.is_object() {
            s.state.set_global_settings(settings).await;
        }
        Ok(Value::from("ok"))
    }
}

struct FileGet;
#[async_trait]
impl WsCommand for FileGet {
    fn name(&self) -> &'static str {
        "fileGet"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        // Params: a bare inner_path string, EpixNet's positional form
        // `[inner_path, required, format, timeout]` (what EpixFS sends), or an
        // object with those keys.
        let arr = p.as_array();
        let inner_path = p
            .as_str()
            .or_else(|| arr.and_then(|a| a.first()).and_then(|v| v.as_str()))
            .or_else(|| p.get("inner_path").and_then(|v| v.as_str()))
            .ok_or("fileGet: missing inner_path")?
            .to_string();
        // required defaults true when ABSENT, but an explicit null is falsy
        // (Python's `if required:`). EpixFS sends it positionally, often as
        // null, and sites probe maybe-missing files that way (git.js reads
        // packed-refs, which many repos don't have) - treating null as true
        // made every probe wait out the miss timeout, turning an instant page
        // into a tens-of-seconds load.
        let required_param = arr.and_then(|a| a.get(1)).or_else(|| p.get("required"));
        let required = match required_param {
            Some(v) => v.as_bool().unwrap_or(false),
            None => true,
        };
        let format = arr
            .and_then(|a| a.get(2))
            .and_then(|v| v.as_str())
            .or_else(|| p.get("format").and_then(|v| v.as_str()))
            .unwrap_or("text")
            .to_string();
        // Route `cors-…` (Cors permission) and `merged-…` (MergerSite) paths.
        let (target, inner) = s.resolve_target(&inner_path).await?;
        let mut bytes = s.state.read_file(&target, &inner).await;
        if bytes.is_none() && required {
            // EpixNet's needFile blocks (up to `timeout`, default 300s) until
            // the file arrives. Our command handling is serial per connection,
            // so a long wait here would freeze the session's other commands -
            // wait briefly (covers a file landing mid-clone), then answer null.
            // A file the site doesn't declare can never arrive: answer now.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while bytes.is_none() && std::time::Instant::now() < deadline {
                if matches!(
                    s.state.loading_file(&target, &inner),
                    crate::state::LoadingFile::NotInSite
                ) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                bytes = s.state.read_file(&target, &inner).await;
            }
        }
        match bytes {
            // base64 is how sites read binary files (git packs, images) over
            // the WS; lossy text corrupts them.
            Some(b) if format == "base64" => Ok(Value::from(b64_encode(&b))),
            Some(b) => Ok(Value::from(String::from_utf8_lossy(&b).into_owned())),
            None => Ok(Value::Null),
        }
    }
}

// ---- built-in commands ----

struct Ping;
#[async_trait]
impl WsCommand for Ping {
    fn name(&self) -> &'static str {
        "ping"
    }
    async fn handle(&self, _s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(Value::from("Pong!"))
    }
}

/// `configList` - editable node config keys with value + default.
struct ConfigList;
#[async_trait]
impl WsCommand for ConfigList {
    fn name(&self) -> &'static str {
        "configList"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.config_list().await)
    }
}

/// `notificationSubscribe(subscriptions)` - save the current site's notification
/// queries (`{name: [query, params]}`).
struct NotificationSubscribe;
#[async_trait]
impl WsCommand for NotificationSubscribe {
    fn name(&self) -> &'static str {
        "notificationSubscribe"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let site = s.address()?.to_string();
        let subs = p
            .get("subscriptions")
            .cloned()
            .or_else(|| p.as_array().and_then(|a| a.first()).cloned())
            .unwrap_or_else(|| p.clone());
        s.state.notification_subscribe(&site, subs).await;
        Ok(Value::from("ok"))
    }
}

/// `notificationList()` - the current site's notification subscriptions.
struct NotificationList;
#[async_trait]
impl WsCommand for NotificationList {
    fn name(&self) -> &'static str {
        "notificationList"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let site = s.address()?.to_string();
        Ok(s.state.notification_list(&site).await)
    }
}

/// `notificationMute(muted, site_address=None)` - global or per-site mute.
struct NotificationMute;
#[async_trait]
impl WsCommand for NotificationMute {
    fn name(&self) -> &'static str {
        "notificationMute"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let muted = p
            .get("muted")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let site = p
            .get("site_address")
            .or_else(|| p.as_array().and_then(|a| a.get(1)))
            .and_then(|v| v.as_str());
        s.state.notification_mute(muted, site).await;
        Ok(Value::from("ok"))
    }
}

/// `notificationMuteStatus()` - `{global_muted, site_mutes}`.
struct NotificationMuteStatus;
#[async_trait]
impl WsCommand for NotificationMuteStatus {
    fn name(&self) -> &'static str {
        "notificationMuteStatus"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.notification_mute_status().await)
    }
}

/// `notificationDismiss(site_address, name)` - mark a site's notification as
/// seen (admin; the dashboard bell's clear button).
struct NotificationDismiss;
#[async_trait]
impl WsCommand for NotificationDismiss {
    fn name(&self) -> &'static str {
        "notificationDismiss"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let site = arg_str(p, "site_address", 0)
            .ok_or("notificationDismiss: site_address required")?
            .to_string();
        let name =
            arg_str(p, "name", 1).ok_or("notificationDismiss: name required")?.to_string();
        s.state.notification_mark_dismissed(&site, &name).await;
        Ok(Value::from("ok"))
    }
}

/// `notificationDismissSelf(name)` - a site marks its own notification as seen
/// (non-admin: only its own subscriptions).
struct NotificationDismissSelf;
#[async_trait]
impl WsCommand for NotificationDismissSelf {
    fn name(&self) -> &'static str {
        "notificationDismissSelf"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let site = s.address()?.to_string();
        let name =
            arg_str(p, "name", 0).ok_or("notificationDismissSelf: name required")?.to_string();
        s.state.notification_mark_dismissed(&site, &name).await;
        Ok(Value::from("ok"))
    }
}

/// `userGetSettings()` - the current site's stored per-user settings.
struct UserGetSettings;
#[async_trait]
impl WsCommand for UserGetSettings {
    fn name(&self) -> &'static str {
        "userGetSettings"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let site = s.address()?.to_string();
        Ok(s.state.user_site_settings(&site).await)
    }
}

/// `userSetSettings(settings)` - store the current site's per-user settings
/// (EpixNet keeps them in users.json; sites use this for notification_seen
/// baselines, visited markers, and other private state).
struct UserSetSettings;
#[async_trait]
impl WsCommand for UserSetSettings {
    fn name(&self) -> &'static str {
        "userSetSettings"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let site = s.address()?.to_string();
        let settings = p
            .get("settings")
            .cloned()
            .or_else(|| p.as_array().and_then(|a| a.first()).cloned())
            .unwrap_or_else(|| p.clone());
        s.state.set_user_site_settings(&site, settings).await?;
        Ok(Value::from("ok"))
    }
}

/// `notificationQuery()` - notification counts across subscribed sites.
struct NotificationQuery;
#[async_trait]
impl WsCommand for NotificationQuery {
    fn name(&self) -> &'static str {
        "notificationQuery"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.notification_query().await)
    }
}

/// `pluginList` - loaded plugins with their enabled state.
struct PluginList;
#[async_trait]
impl WsCommand for PluginList {
    fn name(&self) -> &'static str {
        "pluginList"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let plugins: Vec<Value> = s
            .state
            .plugin_states()
            .await
            .into_iter()
            .map(|(name, enabled, default_enabled)| {
                json!({ "name": name, "enabled": enabled, "default_enabled": default_enabled, "source": "builtin" })
            })
            .collect();
        Ok(json!({ "plugins": plugins }))
    }
}

/// `pluginConfigSet(plugin, enabled)` - enable/disable a plugin at runtime
/// (persisted, no restart).
struct PluginConfigSet;
#[async_trait]
impl WsCommand for PluginConfigSet {
    fn name(&self) -> &'static str {
        "pluginConfigSet"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let name = p
            .get("plugin")
            .or_else(|| p.get("name"))
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_str())
            .ok_or("pluginConfigSet: plugin required")?;
        let enabled = p
            .get("enabled")
            .or_else(|| p.as_array().and_then(|a| a.get(1)))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        s.state.set_plugin_enabled(name, enabled).await;
        // The plugin list changed - push updated serverInfo to the dashboard.
        s.state.push_server_info().await;
        Ok(Value::from("ok"))
    }
}

/// `serverErrors` - recent node log lines for the dashboard console, each
/// `[date_added, level, message]`.
struct ServerErrors;
#[async_trait]
impl WsCommand for ServerErrors {
    fn name(&self) -> &'static str {
        "serverErrors"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(Value::Array(s.state.server_errors().await))
    }
}

/// `consoleLogRead` - recent log lines for the sidebar console (formatted
/// strings + byte-position metadata).
struct ConsoleLogRead;
#[async_trait]
impl WsCommand for ConsoleLogRead {
    fn name(&self) -> &'static str {
        "consoleLogRead"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.console_log_read().await)
    }
}

/// `consoleLogStream` - open a live log stream; returns `{stream_id}`. New lines
/// arrive as `logLineAdd` events.
struct ConsoleLogStream;
#[async_trait]
impl WsCommand for ConsoleLogStream {
    fn name(&self) -> &'static str {
        "consoleLogStream"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(json!({ "stream_id": s.state.console_log_stream_open().await }))
    }
}

/// `consoleLogStreamRemove(stream_id)` - stop a live log stream.
struct ConsoleLogStreamRemove;
#[async_trait]
impl WsCommand for ConsoleLogStreamRemove {
    fn name(&self) -> &'static str {
        "consoleLogStreamRemove"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let id = p
            .get("stream_id")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_i64())
            .ok_or("consoleLogStreamRemove: stream_id required")?;
        s.state.console_log_stream_remove(id).await;
        Ok(Value::from("ok"))
    }
}

/// `configSet(key, value)` - persist a node config value. Mirrors EpixNet's
/// actionConfigSet: saves it, and for `language` pushes the "language changed"
/// notification the dashboard expects.
struct ConfigSet;
#[async_trait]
impl WsCommand for ConfigSet {
    fn name(&self) -> &'static str {
        "configSet"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        // Accept [key, value] or {key, value}.
        let (key, value) = match p {
            Value::Array(a) => (
                a.first().and_then(|v| v.as_str()),
                a.get(1).cloned().unwrap_or(Value::Null),
            ),
            Value::Object(o) => (
                o.get("key").and_then(|v| v.as_str()),
                o.get("value").cloned().unwrap_or(Value::Null),
            ),
            _ => (None, Value::Null),
        };
        let key = key.ok_or("configSet: key required")?;
        // data_dir persists to epixnet.conf (and copies the data over), not
        // config.json - config.json lives inside the directory it would name.
        if key == "data_dir" {
            let dir = value.as_str().unwrap_or_default();
            let message = s.state.set_data_dir(dir).await?;
            s.state.push_notification("done", &message, 15000);
            return Ok(Value::from("ok"));
        }
        s.state.config_set(key, value).await;
        if key == "language" {
            s.state.push_notification(
                "done",
                "You have successfully changed the web interface's language!<br>\
                 Due to the browser's caching, the full change may take a moment.",
                10000,
            );
        }
        Ok(Value::from("ok"))
    }
}

struct ServerInfo;
#[async_trait]
impl WsCommand for ServerInfo {
    fn name(&self) -> &'static str {
        "serverInfo"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.server_info().await)
    }
}

/// `announcerStats` - per-tracker announce status for the dashboard.
struct AnnouncerStats;
#[async_trait]
impl WsCommand for AnnouncerStats {
    fn name(&self) -> &'static str {
        "announcerStats"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.announcer_stats().await)
    }
}

/// `siteAdd(address)` - ADMIN: start serving + downloading a xite by
/// address (EpixNet's `SiteManager.need`).
struct SiteAdd;
#[async_trait]
impl WsCommand for SiteAdd {
    fn name(&self) -> &'static str {
        "siteAdd"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = p
            .get("address")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_str())
            .ok_or("Missing address")?
            .to_string();
        if s.state.has_xite(&address).await {
            return Ok(json!({ "error": "Site already added" }));
        }
        // A trusted operator (the admin socket) may add a site even when
        // NoNewSites locks the set - that is the server-side `siteDownload`.
        let added = if s.trusted {
            s.state.ensure_xite_admin(&address).await
        } else {
            s.state.ensure_xite(&address).await
        };
        if added {
            Ok(Value::from("ok"))
        } else {
            Ok(json!({ "error": "Invalid address" }))
        }
    }
}

/// `siteClone(address, root_inner_path?, target_address?)` - copy a xite's
/// template into a new site we own (EpixNet's Site.clone).
struct SiteClone;
#[async_trait]
impl WsCommand for SiteClone {
    fn name(&self) -> &'static str {
        "siteClone"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let source = p
            .get("address")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_str())
            .ok_or("Missing address")?
            .to_string();
        // Don't reveal whether an unserved address exists (EpixNet returns
        // silently); serving it is the precondition anyway.
        if !s.state.has_any_alias(&source).await {
            return Ok(Value::Null);
        }
        let root = p
            .get("root_inner_path")
            .or_else(|| p.as_array().and_then(|a| a.get(1)))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target = p
            .get("target_address")
            .or_else(|| p.as_array().and_then(|a| a.get(2)))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        // A `target_address` is a source-code upgrade of an existing site, not a
        // brand-new one; only the new-site path navigates the browser (matching
        // EpixNet's `cbSiteClone`, which redirects only when target is unset).
        let is_new = target.is_none();
        let address = s.state.clone_xite(&source, &root, target).await?;
        if is_new {
            // Forward the wrapper to the freshly created site, like EpixNet's
            // `self.cmd("redirect", "/<new_address>")`. The redirect is routed to
            // the source site so it reaches that site's wrapper connection (the
            // one that handles wrapper commands), not just the app WS that issued
            // this command.
            s.state.push_redirect(&source, &format!("/{address}/"));
        } else {
            s.state.push_notification("done", "Site source code upgraded!", 8000);
        }
        Ok(json!({ "address": address }))
    }
}

/// `serverPortcheck` - ADMIN: report whether our fileserver port is reachable
/// (the runtime's port checker keeps this current; UPnP retries in its loop).
struct ServerPortcheck;
#[async_trait]
impl WsCommand for ServerPortcheck {
    fn name(&self) -> &'static str {
        "serverPortcheck"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let (opened, _ip) = s.state.port_status().await;
        Ok(Value::from(opened))
    }
}

/// `serverUpdate` - ADMIN. This node has no self-updater: updates ship
/// through the platform packages (installer, app store, cargo). Answer
/// honestly instead of pretending to restart.
struct ServerUpdate;
#[async_trait]
impl WsCommand for ServerUpdate {
    fn name(&self) -> &'static str {
        "serverUpdate"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let msg = "This node updates through its installer or package, not in place; \
                   install the new version and restart";
        s.state.push_notification("info", msg, 12000);
        Ok(json!({ "error": msg }))
    }
}

/// `serverShutdown` - ADMIN: stop the node process. The shells supervise the
/// process, so exit is the shutdown; state persists continuously. With
/// `{restart: true}` (the Config page after a restart-only setting changed) a
/// detached helper starts the node again once this process is gone.
struct ServerShutdown;
#[async_trait]
impl WsCommand for ServerShutdown {
    fn name(&self) -> &'static str {
        "serverShutdown"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let restart = p
            .get("restart")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let msg = if restart { "Restarting..." } else { "Shutting down..." };
        s.state.push_notification("info", msg, 5000);
        s.state.shutdown(restart).await;
        Ok(Value::from("ok"))
    }
}

/// `fileQuery(dir_inner_path, query?)` - rows from JSON files under a xite
/// directory, with the one-`*` wildcard and `dotted.path=val` filter of
/// EpixNet's QueryJson.
struct FileQuery;
#[async_trait]
impl WsCommand for FileQuery {
    fn name(&self) -> &'static str {
        "fileQuery"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let dir = p
            .get("dir_inner_path")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_str())
            .ok_or("Missing dir_inner_path")?;
        let query = p
            .get("query")
            .or_else(|| p.as_array().and_then(|a| a.get(1)))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        Ok(Value::Array(s.state.query_json_files(&address, dir, query).await))
    }
}

/// `badCert(sign)` - mark a cert signature bad; inbound user content carrying
/// it is rejected from then on.
struct BadCert;
#[async_trait]
impl WsCommand for BadCert {
    fn name(&self) -> &'static str {
        "badCert"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let sign = p
            .get("sign")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_str())
            .ok_or("Missing sign")?;
        s.state.add_bad_cert(sign);
        Ok(Value::from("ok"))
    }
}

/// `siteSetSettingsValue(key, value)` - ADMIN; EpixNet whitelists exactly one
/// key.
struct SiteSetSettingsValue;
#[async_trait]
impl WsCommand for SiteSetSettingsValue {
    fn name(&self) -> &'static str {
        "siteSetSettingsValue"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let key = p
            .get("key")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if key != "modified_files_notification" {
            return Ok(json!({ "error": "Can't change this key" }));
        }
        let value = p
            .get("value")
            .or_else(|| p.as_array().and_then(|a| a.get(1)))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let address = s.address()?.to_string();
        s.state.set_modified_files_notification(&address, value).await;
        Ok(Value::from("ok"))
    }
}

/// `siteListModifiedFiles` - files whose on-disk bytes differ from the signed
/// content.json (possibly-unsigned local changes).
struct SiteListModifiedFiles;
#[async_trait]
impl WsCommand for SiteListModifiedFiles {
    fn name(&self) -> &'static str {
        "siteListModifiedFiles"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        Ok(json!({ "modified_files": s.state.list_modified_files(&address).await }))
    }
}

struct WrapperNonce;
#[async_trait]
impl WsCommand for WrapperNonce {
    fn name(&self) -> &'static str {
        "serverGetWrapperNonce"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(json!({ "wrapper_nonce": s.state.wrapper_nonce() }))
    }
}

struct SiteInfo;
#[async_trait]
impl WsCommand for SiteInfo {
    fn name(&self) -> &'static str {
        "siteInfo"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        // A xite being cloned on demand is registered (empty) before the
        // download starts, so this is real - never null - during loading.
        let address = s.address()?;
        let mut info = s.state.site_info(address).await;
        // file_status (EpixNet's actionSiteInfo): the loading-screen wrapper
        // asks about its index.html on connect. If the file already landed
        // AND the core set is complete, answer with its file_done event - the
        // live event is missed when the WS connects after it fired, which
        // left the loading screen up forever. The core-complete gate matters
        // on a refresh mid-clone: index.html downloads first, and dismissing
        // on it alone drops the user into a site with its styles and scripts
        // still missing.
        let file_status = p
            .get("file_status")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_str());
        if let (Some(path), Value::Object(m)) = (file_status, &mut info) {
            if s.state.xite_file_exists(address, path).await
                && s.state.xite_core_complete(address).await
            {
                m.insert("event".to_string(), json!(["file_done", path]));
            }
        }
        Ok(info)
    }
}

/// `announcerInfo` - per-tracker announce stats for the loading screen's
/// discovery status line (EpixNet's `actionAnnouncerInfo`).
struct AnnouncerInfo;
#[async_trait]
impl WsCommand for AnnouncerInfo {
    fn name(&self) -> &'static str {
        "announcerInfo"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        // EpixNet blanks the stats unless the asking site holds ADMIN.
        let stats = if s.state.site_has_admin(&address).await {
            s.state.announcer_stats().await
        } else {
            json!({})
        };
        Ok(json!({ "address": address, "stats": stats }))
    }
}

/// `chartDbQuery(query, params)` - run a read-only query against the node's
/// network-stats chart database (the dashboard's Stats page). EpixFrame passes
/// either a bare query string or `[query, params]`.
struct ChartDbQuery;
#[async_trait]
impl WsCommand for ChartDbQuery {
    fn name(&self) -> &'static str {
        "chartDbQuery"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        // Accept `"SELECT …"`, `["SELECT …", params]`, or `{query, params}`.
        let (query, params) = match p {
            Value::String(q) => (Some(q.as_str()), Value::Null),
            Value::Array(a) => (
                a.first().and_then(|v| v.as_str()),
                a.get(1).cloned().unwrap_or(Value::Null),
            ),
            Value::Object(o) => (
                o.get("query").and_then(|v| v.as_str()),
                o.get("params").cloned().unwrap_or(Value::Null),
            ),
            _ => (None, Value::Null),
        };
        let query = query.ok_or("chartDbQuery: query required")?;
        match s.state.chart_query(query, &params).await {
            Ok(rows) => Ok(Value::Array(rows)),
            Err(e) => Ok(json!({ "error": e })),
        }
    }
}

/// `channelJoin` / `channelJoinAllsite` - subscribe the connection to server
/// push channels (`siteChanged`, `serverChanged`, `announcerChanged`), so it
/// receives the matching `setSiteInfo`/`setServerInfo`/`setAnnouncerInfo` events.
struct ChannelJoin {
    cmd: &'static str,
}
#[async_trait]
impl WsCommand for ChannelJoin {
    fn name(&self) -> &'static str {
        self.cmd
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        // An ADMIN site's joins carry all-site scope. The dashboard sends
        // channelJoinAllsite only once at page load; after a node restart the
        // wrapper auto-rejoins with plain channelJoin, and without this the
        // dashboard silently stops receiving other sites' events (rows frozen,
        // spinners stuck) until a manual refresh.
        let admin = match s.address() {
            Ok(addr) => s.state.site_has_admin(addr).await,
            Err(_) => false,
        };
        s.join_channels(p, self.cmd == "channelJoinAllsite" || admin);
        Ok(Value::from("ok"))
    }
}

/// `chartGetPeerLocations` - geolocated peer positions for the world map.
struct ChartGetPeerLocations;
#[async_trait]
impl WsCommand for ChartGetPeerLocations {
    fn name(&self) -> &'static str {
        "chartGetPeerLocations"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(Value::Array(s.state.peer_locations().await))
    }
}

/// `siteList` - every served xite's siteInfo, for the dashboard's Sites panel.
struct SiteList;
#[async_trait]
impl WsCommand for SiteList {
    fn name(&self) -> &'static str {
        "siteList"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(Value::Array(s.state.site_list().await))
    }
}

/// `dbQuery(query, params)` - run a read query against the xite's database.
/// EpixFrame passes `[query, params]`; we also accept a bare string or
/// `{query, params}`.
struct DbQuery;
#[async_trait]
impl WsCommand for DbQuery {
    fn name(&self) -> &'static str {
        "dbQuery"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?;
        let (query, params) = match p {
            Value::Array(a) => (
                a.first().and_then(|v| v.as_str()).ok_or("dbQuery: missing query")?,
                a.get(1).cloned().unwrap_or(Value::Null),
            ),
            Value::String(q) => (q.as_str(), Value::Null),
            Value::Object(o) => (
                o.get("query").and_then(|v| v.as_str()).ok_or("dbQuery: missing query")?,
                o.get("params").cloned().unwrap_or(Value::Null),
            ),
            _ => return Err("dbQuery: invalid params".into()),
        };
        let rows = s.state.db_query(address, query, &params).await?;
        Ok(Value::Array(rows))
    }
}

// ---- xID resolution --------------------------------------------------------

/// The plugin's response shape: `{name, tld, owner, active, revoked_at,
/// revoked_at_time, avatar, bio}`.
fn xid_info_value(info: &epix_chain::xid_identity::XidInfo) -> Value {
    json!({
        "name": info.name,
        "tld": info.tld,
        "owner": info.owner,
        "active": info.active,
        "revoked_at": info.revoked_at,
        "revoked_at_time": info.revoked_at_time,
        "avatar": info.avatar,
        "bio": info.bio,
    })
}

/// First string out of `[value]` / `{key: value}` params (sites use both).
fn xid_param<'a>(p: &'a Value, key: &str) -> Option<&'a str> {
    p.as_array()
        .and_then(|a| a.first())
        .or_else(|| p.get(key))
        .and_then(|v| v.as_str())
}

/// `xidResolve(address)` - reverse-resolve a linked identity address to its
/// xID name (chain-verified, cached). When the queried address is the user's
/// own auth address for this site and it isn't linked, the user's other
/// addresses (master + per-site auths) are tried too, matching EpixNet.
struct XidResolve;
#[async_trait]
impl WsCommand for XidResolve {
    fn name(&self) -> &'static str {
        "xidResolve"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = xid_param(p, "address").ok_or("xidResolve: address required")?;
        // Dotted values are xID directory names (e.g. "mud.epix"), not linked
        // addresses: xites pass the per-user data directory here. Forward-
        // resolve them, like xidResolveBatch does; the reverse lookup below
        // would just negative-cache a name.
        if address.contains('.') {
            return Ok(epix_chain::xid_identity::resolve_name(address)
                .await
                .map(|i| xid_info_value(&i))
                .unwrap_or(Value::Null));
        }
        if let Some(info) = epix_chain::xid_identity::resolve_identity(address).await {
            return Ok(xid_info_value(&info));
        }
        let own = s
            .state
            .user_auth_address(s.address()?)
            .await
            .map(|a| a == address)
            .unwrap_or(false);
        if own {
            for other in s.state.user_all_addresses().await {
                if other == address {
                    continue;
                }
                if let Some(info) = epix_chain::xid_identity::resolve_identity(&other).await {
                    return Ok(xid_info_value(&info));
                }
            }
        }
        Ok(Value::Null)
    }
}

/// `xidResolveBatch(addresses)` - resolve up to 50 addresses / dotted names
/// in one call; returns `{key: result-or-null}`.
struct XidResolveBatch;
#[async_trait]
impl WsCommand for XidResolveBatch {
    fn name(&self) -> &'static str {
        "xidResolveBatch"
    }
    async fn handle(&self, _s: &WsSession, p: &Value) -> Result<Value, String> {
        let list = p
            .as_array()
            .and_then(|a| a.first())
            .or_else(|| p.get("addresses"))
            .and_then(|v| v.as_array())
            .ok_or("xidResolveBatch: addresses must be a list")?;
        let mut out = serde_json::Map::new();
        for v in list.iter().take(50) {
            let Some(key) = v.as_str() else { continue };
            let resolved = if key.contains('.') {
                epix_chain::xid_identity::resolve_name(key).await
            } else {
                epix_chain::xid_identity::resolve_identity(key).await
            };
            out.insert(
                key.to_string(),
                resolved.map(|i| xid_info_value(&i)).unwrap_or(Value::Null),
            );
        }
        Ok(Value::Object(out))
    }
}

// ---- publish / sign --------------------------------------------------------

/// `fileWrite(inner_path, content_base64)` - write a file into the xite.
struct FileWrite;
#[async_trait]
impl WsCommand for FileWrite {
    fn name(&self) -> &'static str {
        "fileWrite"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let a = p.as_array();
        let inner_path = a
            .and_then(|a| a.first())
            .or_else(|| p.get("inner_path"))
            .and_then(|v| v.as_str())
            .ok_or("fileWrite: inner_path required")?;
        let b64 = a
            .and_then(|a| a.get(1))
            .or_else(|| p.get("content_base64"))
            .and_then(|v| v.as_str())
            .ok_or("fileWrite: content_base64 required")?;
        let bytes = b64_decode(b64).ok_or("fileWrite: invalid base64")?;
        // Route merged-/cors- prefixed paths to their real site (a merger page
        // writes into its merged sites, e.g. starring a repo in the index).
        let (target, inner) = s.resolve_target(inner_path).await?;
        s.state.write_file(&target, &inner, &bytes).await?;
        // Ingest written data files into the xite's database right away (like
        // EpixNet's storage.onUpdated), so the page's dbQuery sees the change
        // before the sign/publish round-trip. The writing connection is
        // excluded from the file_done echo (EpixNet notifies `ws != self`).
        if inner.ends_with(".json") && !inner.ends_with("content.json") {
            s.state.ingest_file_from(&target, &inner, Some(s.id)).await;
        }
        Ok(Value::from("ok"))
    }
}

/// `fileDelete(inner_path)` - delete a file from the xite (optional files are
/// also removed from content.json's `files_optional`, like EpixNet).
struct FileDelete;
#[async_trait]
impl WsCommand for FileDelete {
    fn name(&self) -> &'static str {
        "fileDelete"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let inner_path = p
            .as_str()
            .or_else(|| p.get("inner_path").and_then(|v| v.as_str()))
            .or_else(|| p.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()))
            .ok_or("fileDelete: inner_path required")?;
        let (address, inner_path) = s.resolve_target(inner_path).await?;
        s.state.delete_file(&address, &inner_path, Some(s.id)).await?;
        Ok(Value::from("ok"))
    }
}

/// `siteSetOwned(owned)` - claim/relinquish ownership (reveals the owner
/// sidebar sections; signing still needs the key).
struct SiteSetOwned;
#[async_trait]
impl WsCommand for SiteSetOwned {
    fn name(&self) -> &'static str {
        "siteSetOwned"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let owned = p
            .as_bool()
            .or_else(|| p.as_array().and_then(|a| a.first()).and_then(|v| v.as_bool()))
            .unwrap_or(true);
        s.state.set_owned(&address, owned).await;
        Ok(Value::from("ok"))
    }
}

/// `fileRules(inner_path)` - content rules (signers) for a path.
struct FileRules;
#[async_trait]
impl WsCommand for FileRules {
    fn name(&self) -> &'static str {
        "fileRules"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let inner_path = p
            .as_str()
            .or_else(|| p.get("inner_path").and_then(|v| v.as_str()))
            .or_else(|| p.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()))
            .unwrap_or("content.json");
        let (address, inner_path) = s.resolve_target(inner_path).await?;
        Ok(s.state.file_rules(&address, &inner_path).await)
    }
}

/// `corsPermission(address)` - grant this site read access to another site's
/// files (the `Cors:<address>` permission), so it can load `cors-<address>/…`.
struct CorsPermission;
#[async_trait]
impl WsCommand for CorsPermission {
    fn name(&self) -> &'static str {
        "corsPermission"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let site = s.address()?.to_string();
        // Accept a single address or a list.
        let addresses: Vec<String> = match p {
            Value::String(a) => vec![a.clone()],
            Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
            Value::Object(o) => o
                .get("address")
                .map(|v| match v {
                    Value::String(a) => vec![a.clone()],
                    Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                    _ => vec![],
                })
                .unwrap_or_default(),
            _ => vec![],
        };
        if addresses.is_empty() {
            return Err("corsPermission: address required".into());
        }
        for addr in addresses {
            let addr = require_address(&addr)?;
            s.state.add_permission(&site, &format!("Cors:{addr}")).await;
        }
        Ok(Value::from("ok"))
    }
}

/// `siteRecoverPrivatekey()` - recover the site key from the master seed.
struct SiteRecoverPrivatekey;
#[async_trait]
impl WsCommand for SiteRecoverPrivatekey {
    fn name(&self) -> &'static str {
        "siteRecoverPrivatekey"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        Ok(s.state.recover_privatekey(&address).await)
    }
}

/// `userSetSitePrivatekey(privatekey)` - save the site key (marks owned).
struct UserSetSitePrivatekey;
#[async_trait]
impl WsCommand for UserSetSitePrivatekey {
    fn name(&self) -> &'static str {
        "userSetSitePrivatekey"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let pk = p
            .as_str()
            .or_else(|| p.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()))
            .ok_or("userSetSitePrivatekey: privatekey required")?;
        s.state.set_site_privatekey(&address, pk).await?;
        Ok(Value::from("ok"))
    }
}

/// `siteUpdate(address)` - force a re-sync now.
struct SiteUpdate;
#[async_trait]
impl WsCommand for SiteUpdate {
    fn name(&self) -> &'static str {
        "siteUpdate"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = match p
            .get("address")
            .and_then(|v| v.as_str())
            .or_else(|| p.as_str())
            .or_else(|| p.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()))
        {
            Some(a) => require_address(a)?,
            None => s.address()?.to_string(),
        };
        // Run in the background (like EpixNet's updateThread) so this returns
        // immediately. Progress shows inline on the dashboard's site row via
        // setSiteInfo events (`updating` -> spinner, `updated` -> done), not a
        // popup notification.
        let state = s.state.clone();
        tokio::spawn(async move {
            state.push_site_info_event(&address, "updating").await;
            state.begin_site_update(&address);
            // Own task so a panic mid-sync still reaches the outcome push
            // below - without it the row's "Updating..." pill never clears.
            let joined = tokio::spawn({
                let state = state.clone();
                let address = address.clone();
                async move {
                    let ok = state.resync_xite(&address).await.is_ok();
                    // Root files alone miss a user_contents site's actual data
                    // (topics and posts live in per-user files) - sync those
                    // too, like the periodic resync cycle does.
                    state.sync_user_content(&address).await;
                    ok
                }
            })
            .await;
            state.end_site_update(&address);
            state.push_update_result(&address, joined.unwrap_or(false)).await;
        });
        Ok(Value::from("Updated"))
    }
}

/// `siteSign(privatekey, inner_path)` - rebuild + sign content.json.
/// `siteSign(privatekey, inner_path)` - sign the content.json governing
/// `inner_path`: the root one with the site's own key, a user/include one as
/// the current user (cert + auth key), like EpixNet's `actionSiteSign`.
struct SiteSign;
#[async_trait]
impl WsCommand for SiteSign {
    fn name(&self) -> &'static str {
        "siteSign"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let inner_path = p
            .get("inner_path")
            .or_else(|| p.as_array().and_then(|a| a.get(1)))
            .and_then(|v| v.as_str())
            .unwrap_or("content.json");
        // Merger sites sign into their merged site (`merged-…/` paths).
        let (address, inner_path) = s.resolve_target(inner_path).await?;
        sign_for(s, &address, &inner_path, sign_privatekey(p)).await?;
        // Push fresh siteInfo so the page re-renders with the new signed state -
        // EpixNet's `updateWebsocket(file_done=…)` after actionSiteSign. Without
        // it the sidebar keeps showing the pre-sign modified-files/sign panel.
        s.state.push_site_info(&address).await;
        Ok(Value::from("ok"))
    }
}

/// `sitePublish(privatekey, inner_path, sign)` - sign (unless told not to) then
/// push the governing content.json to peers.
struct SitePublish;
#[async_trait]
impl WsCommand for SitePublish {
    fn name(&self) -> &'static str {
        "sitePublish"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let inner_path = p
            .get("inner_path")
            .or_else(|| p.as_array().and_then(|a| a.get(1)))
            .and_then(|v| v.as_str())
            .unwrap_or("content.json");
        let (address, inner_path) = s.resolve_target(inner_path).await?;
        let sign = p.get("sign").and_then(|v| v.as_bool()).unwrap_or(true);
        let inner_path = s.state.content_inner_path(&address, &inner_path).await;
        if sign {
            // `"stored"` = use the site key saved in users.json (see sign_for).
            let privatekey = match sign_privatekey(p) {
                Some(pk) if pk == "stored" => Some(
                    s.state
                        .site_privatekey(&address)
                        .await
                        .ok_or("Site sign failed: Private key not found in users.json")?,
                ),
                other => other,
            };
            if inner_path == "content.json" {
                // Root: sign with the given key or the saved site key; with
                // neither, the file is assumed already signed.
                let key = match privatekey {
                    Some(pk) => Some(pk),
                    None => s.state.site_privatekey(&address).await,
                };
                if let Some(pk) = key {
                    s.state.sign_xite(&address, &pk).await?;
                }
            } else {
                s.state
                    .sign_user_content(&address, &inner_path, privatekey, Some(s.id))
                    .await?;
            }
        }
        let published = s.state.publish(&address, &inner_path, Some(s.id)).await?;
        // Fresh siteInfo so the page re-renders post-publish (the sidebar's
        // sign/publish panel and modified-files list reset) - EpixNet's
        // `site.updateWebsocket()` at the end of cbSitePublish.
        s.state.push_site_info(&address).await;
        // The page checks for the literal "ok" (EpixNet's actionSitePublish
        // responds "ok"; the peer count arrives as a notification - to the
        // publishing page only, like EpixNet's self.cmd).
        if published > 0 {
            s.state.push_notification_to(
                s.id,
                "done",
                &format!("Content published to {published} peers."),
                5000,
            );
        } else {
            s.state.push_notification_to(
                s.id,
                "info",
                "Content publish failed: no peers reachable right now. It will spread on the next sync.",
                7000,
            );
        }
        Ok(Value::from("ok"))
    }
}

/// Sign the content.json governing `inner_path` and return its path: the root
/// content.json needs the site's own key (explicit or stored); any other one
/// is user/include content signed as the current user.
async fn sign_for(
    s: &WsSession,
    address: &str,
    inner_path: &str,
    privatekey: Option<String>,
) -> Result<String, String> {
    // `"stored"` is EpixNet's sentinel for "use the site key saved in
    // users.json" (the sidebar and wrapper infopanel send it when
    // site_info.privatekey is true) - never a literal key.
    let privatekey = match privatekey {
        Some(pk) if pk == "stored" => Some(
            s.state
                .site_privatekey(address)
                .await
                .ok_or("Site sign failed: Private key not found in users.json")?,
        ),
        other => other,
    };
    let content_path = s.state.content_inner_path(address, inner_path).await;
    if content_path == "content.json" {
        let key = match privatekey {
            Some(pk) => pk,
            None => s
                .state
                .site_privatekey(address)
                .await
                .ok_or("siteSign: privatekey required")?,
        };
        s.state.sign_xite(address, &key).await?;
    } else {
        s.state.sign_user_content(address, &content_path, privatekey, Some(s.id)).await?;
    }
    Ok(content_path)
}

/// Pull the private key out of `[privatekey, ...]` or `{privatekey}` (a JSON
/// null means "use the site's own key", which we don't hold - treated as none).
fn sign_privatekey(p: &Value) -> Option<String> {
    p.get("privatekey")
        .or_else(|| p.as_array().and_then(|a| a.first()))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

// ---- CryptMessage: ECIES + AES + ECC helpers -------------------------------

/// The public key to encrypt to: an explicit base64 SEC1 key, or the user's own
/// per-xite encrypt key when the arg is an index (int) / absent.
async fn resolve_pubkey(s: &WsSession, address: &str, arg: Option<&Value>) -> Result<Vec<u8>, String> {
    match arg {
        Some(Value::String(b64)) => b64_decode(b64).ok_or("eciesEncrypt: bad public key".into()),
        other => {
            let index = other.and_then(|v| v.as_u64()).unwrap_or(0);
            s.state.user_encrypt_publickey(address, index).await
        }
    }
}

/// The private key to decrypt with: an explicit WIF/hex, or the user's own
/// per-xite encrypt key when the arg is an index (int) / absent.
async fn resolve_privkey(s: &WsSession, address: &str, arg: Option<&Value>) -> Result<String, String> {
    match arg {
        Some(Value::String(pk)) if !pk.is_empty() => Ok(pk.clone()),
        other => {
            let index = other.and_then(|v| v.as_u64()).unwrap_or(0);
            s.state.user_encrypt_privatekey(address, index).await
        }
    }
}

/// `userPublickey(index)` - the user's encrypt public key (base64) for this xite.
struct UserPublickey;
#[async_trait]
impl WsCommand for UserPublickey {
    fn name(&self) -> &'static str {
        "userPublickey"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let index = p.as_array().and_then(|a| a.first()).or(Some(p)).and_then(|v| v.as_u64()).unwrap_or(0);
        let pk = s.state.user_encrypt_publickey(&address, index).await?;
        Ok(Value::from(b64_encode(&pk)))
    }
}

/// `eciesEncrypt(text, publickey=0, return_aes_key=false)`.
struct EciesEncrypt;
#[async_trait]
impl WsCommand for EciesEncrypt {
    fn name(&self) -> &'static str {
        "eciesEncrypt"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let a = p.as_array();
        let text = a.and_then(|a| a.first()).and_then(|v| v.as_str()).ok_or("eciesEncrypt: text required")?;
        let pubkey = resolve_pubkey(s, &address, a.and_then(|a| a.get(1))).await?;
        let return_key = a.and_then(|a| a.get(2)).and_then(|v| v.as_bool()).unwrap_or(false);

        let (blob, k_enc) = epix_crypt::ecies::ecies_encrypt(text.as_bytes(), &pubkey)?;
        if return_key {
            Ok(json!([b64_encode(&blob), b64_encode(&k_enc)]))
        } else {
            Ok(Value::from(b64_encode(&blob)))
        }
    }
}

/// `eciesDecrypt(param, privatekey=0)` - `param` is one base64 blob or a list.
struct EciesDecrypt;
#[async_trait]
impl WsCommand for EciesDecrypt {
    fn name(&self) -> &'static str {
        "eciesDecrypt"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let a = p.as_array();
        let param = a.and_then(|a| a.first()).ok_or("eciesDecrypt: param required")?;
        let privatekey = resolve_privkey(s, &address, a.and_then(|a| a.get(1))).await?;

        let decode_one = |b64: &str| -> Value {
            b64_decode(b64)
                .and_then(|blob| epix_crypt::ecies::ecies_decrypt(&blob, &privatekey).ok())
                .and_then(|pt| String::from_utf8(pt).ok())
                .map(Value::from)
                .unwrap_or(Value::Null)
        };

        match param {
            Value::Array(items) => {
                Ok(Value::Array(items.iter().filter_map(|v| v.as_str()).map(decode_one).collect()))
            }
            Value::String(b64) => Ok(decode_one(b64)),
            _ => Err("eciesDecrypt: invalid param".into()),
        }
    }
}

/// `aesEncrypt(text, key=null)` → `[key_b64, iv_b64, ciphertext_b64]`.
struct AesEncrypt;
#[async_trait]
impl WsCommand for AesEncrypt {
    fn name(&self) -> &'static str {
        "aesEncrypt"
    }
    async fn handle(&self, _s: &WsSession, p: &Value) -> Result<Value, String> {
        let a = p.as_array();
        let text = a.and_then(|a| a.first()).and_then(|v| v.as_str()).unwrap_or("");
        let key = match a.and_then(|a| a.get(1)).and_then(|v| v.as_str()) {
            Some(b64) => b64_decode(b64).ok_or("aesEncrypt: bad key")?,
            None => epix_crypt::ecies::aes_new_key().to_vec(),
        };
        let iv = epix_crypt::ecies::aes_new_iv();
        let ct = epix_crypt::ecies::aes_encrypt(text.as_bytes(), &key, &iv)?;
        Ok(json!([b64_encode(&key), b64_encode(&iv), b64_encode(&ct)]))
    }
}

/// `aesDecrypt(iv, ciphertext, key)` → decrypted text (or null on failure).
struct AesDecrypt;
#[async_trait]
impl WsCommand for AesDecrypt {
    fn name(&self) -> &'static str {
        "aesDecrypt"
    }
    async fn handle(&self, _s: &WsSession, p: &Value) -> Result<Value, String> {
        let a = p.as_array().ok_or("aesDecrypt: expected params array")?;
        // Single form: [iv, ciphertext, key] (all strings).
        if a.len() == 3 && a.iter().all(|v| v.is_string()) {
            let get = |i: usize| a.get(i).and_then(|v| v.as_str()).and_then(b64_decode);
            let (iv, ct, key) = (
                get(0).ok_or("aesDecrypt: iv")?,
                get(1).ok_or("aesDecrypt: ciphertext")?,
                get(2).ok_or("aesDecrypt: key")?,
            );
            return Ok(aes_try_keys(&iv, &ct, std::slice::from_ref(&key)));
        }
        // Batch form: [ [[iv, ciphertext], …], [key, …] ]. For each ciphertext,
        // try every key and return the text of the first that decrypts (or null).
        let items = a.first().and_then(|v| v.as_array()).ok_or("aesDecrypt: encrypted_texts")?;
        let keys: Vec<Vec<u8>> = a
            .get(1)
            .and_then(|v| v.as_array())
            .ok_or("aesDecrypt: keys")?
            .iter()
            .filter_map(|k| k.as_str().and_then(b64_decode))
            .collect();
        let mut out = Vec::with_capacity(items.len());
        for pair in items {
            let iv = pair.get(0).and_then(|v| v.as_str()).and_then(b64_decode);
            let ct = pair.get(1).and_then(|v| v.as_str()).and_then(b64_decode);
            match (iv, ct) {
                (Some(iv), Some(ct)) => out.push(aes_try_keys(&iv, &ct, &keys)),
                _ => out.push(Value::Null),
            }
        }
        Ok(Value::Array(out))
    }
}

/// Try each key against `(iv, ciphertext)`, returning the first valid-UTF-8
/// plaintext as a JSON string, else `Null`.
fn aes_try_keys(iv: &[u8], ct: &[u8], keys: &[Vec<u8>]) -> Value {
    for key in keys {
        if let Ok(pt) = epix_crypt::ecies::aes_decrypt(ct, key, iv) {
            if let Ok(text) = String::from_utf8(pt) {
                return Value::from(text);
            }
        }
    }
    Value::Null
}

/// `ecdsaSign(data, privatekey?)` - sign `data`. With no key, the user's auth
/// private key for the bound site is used.
struct EcdsaSign;
#[async_trait]
impl WsCommand for EcdsaSign {
    fn name(&self) -> &'static str {
        "ecdsaSign"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let data = arg_str(p, "data", 0).ok_or("ecdsaSign: data required")?;
        let privatekey = match arg_str(p, "privatekey", 1) {
            Some(pk) => pk.to_string(),
            None => {
                let address = s.address()?.to_string();
                s.state.user_auth_privatekey(&address).await?
            }
        };
        Ok(Value::from(epix_crypt::sign(data, &privatekey)?))
    }
}

// ---- Chain: Vrf randomness beacon + XidResolver ----------------------------

/// Read a positional-or-named integer arg.
fn arg_u64(p: &Value, key: &str, idx: usize) -> Option<u64> {
    p.get(key)
        .or_else(|| p.as_array().and_then(|a| a.get(idx)))
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
}

/// Serialize a Vrf beacon for the wire.
fn beacon_json(b: &epix_chain::Beacon) -> Value {
    json!({
        "height": b.height,
        "beacon": b.beacon,
        "proposer": b.proposer,
        "timestamp": b.timestamp,
    })
}

/// `vrfGetBeacon(height)` - the randomness beacon at a block height.
struct VrfGetBeacon;
#[async_trait]
impl WsCommand for VrfGetBeacon {
    fn name(&self) -> &'static str {
        "vrfGetBeacon"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let height = arg_u64(p, "height", 0).ok_or("vrfGetBeacon: height required")?;
        let vrf = epix_chain::Vrf::new(s.state.chain_rpc_url().await);
        match vrf.beacon(height).await {
            Ok(b) => Ok(beacon_json(&b)),
            Err(e) => Ok(json!({ "error": e.to_string() })),
        }
    }
}

/// `vrfLatestBeacon()` - the most recent finalized beacon.
struct VrfLatestBeacon;
#[async_trait]
impl WsCommand for VrfLatestBeacon {
    fn name(&self) -> &'static str {
        "vrfLatestBeacon"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let vrf = epix_chain::Vrf::new(s.state.chain_rpc_url().await);
        match vrf.latest_beacon().await {
            Ok(b) => Ok(beacon_json(&b)),
            Err(e) => Ok(json!({ "error": e.to_string() })),
        }
    }
}

/// `vrfMultiBlockBeacon(end_height, blocks)` - a beacon combined over a window.
struct VrfMultiBlockBeacon;
#[async_trait]
impl WsCommand for VrfMultiBlockBeacon {
    fn name(&self) -> &'static str {
        "vrfMultiBlockBeacon"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let end = arg_u64(p, "end_height", 0).ok_or("vrfMultiBlockBeacon: end_height required")?;
        let blocks = arg_u64(p, "blocks", 1).unwrap_or(1);
        let vrf = epix_chain::Vrf::new(s.state.chain_rpc_url().await);
        match vrf.multi_block_beacon(end, blocks).await {
            Ok(combined) => Ok(json!({ "beacon": combined })),
            Err(e) => Ok(json!({ "error": e.to_string() })),
        }
    }
}

/// `vrfDeriveRandom(beacon, seed, count)` - deterministic values from a beacon.
/// Pure (no RPC): `sha256(beacon ‖ seed ‖ i)` per the reference derivation.
struct VrfDeriveRandom;
#[async_trait]
impl WsCommand for VrfDeriveRandom {
    fn name(&self) -> &'static str {
        "vrfDeriveRandom"
    }
    async fn handle(&self, _s: &WsSession, p: &Value) -> Result<Value, String> {
        let beacon = arg_str(p, "beacon", 0).ok_or("vrfDeriveRandom: beacon required")?;
        let seed = arg_str(p, "seed", 1).unwrap_or("");
        let count = arg_u64(p, "count", 2).unwrap_or(1) as usize;
        Ok(json!(epix_chain::derive_random(beacon, seed, count)))
    }
}

/// `vrfInvalidateCache()` - the node builds a fresh Vrf client per request, so
/// there is no persistent cache to clear; a successful no-op.
struct VrfInvalidateCache;
#[async_trait]
impl WsCommand for VrfInvalidateCache {
    fn name(&self) -> &'static str {
        "vrfInvalidateCache"
    }
    async fn handle(&self, _s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(Value::from("ok"))
    }
}

/// `xidResolveName(name, tld)` - resolve a chain name to its attested snapshot
/// (owner, identities, DNS records) via the Merkle-proof-verified resolver.
struct XidResolveName;
#[async_trait]
impl WsCommand for XidResolveName {
    fn name(&self) -> &'static str {
        "xidResolveName"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let raw = arg_str(p, "name", 0)
            .or_else(|| arg_str(p, "xid_name", 0))
            .ok_or("xidResolveName: name required")?;
        let (name, tld) = match arg_str(p, "tld", 1) {
            Some(tld) => (raw, tld),
            None => raw.rsplit_once('.').unwrap_or((raw, "epix")),
        };
        let resolver = epix_chain::XidResolver::new(s.state.chain_rpc_url().await);
        match resolver.resolve(name, tld).await {
            Ok(snap) => Ok(serde_json::to_value(snap).unwrap_or(Value::Null)),
            Err(e) => Ok(json!({ "error": e.to_string() })),
        }
    }
}

/// `ecdsaVerify(data, address, signature)` → bool.
struct EcdsaVerify;
#[async_trait]
impl WsCommand for EcdsaVerify {
    fn name(&self) -> &'static str {
        "ecdsaVerify"
    }
    async fn handle(&self, _s: &WsSession, p: &Value) -> Result<Value, String> {
        let a = p.as_array().ok_or("ecdsaVerify: expected [data, address, signature]")?;
        let data = a.first().and_then(|v| v.as_str()).ok_or("ecdsaVerify: data")?;
        let address = a.get(1).and_then(|v| v.as_str()).ok_or("ecdsaVerify: address")?;
        let sig = a.get(2).and_then(|v| v.as_str()).ok_or("ecdsaVerify: signature")?;
        Ok(Value::from(epix_crypt::verify(data, address, sig)))
    }
}

/// `eccPrivToPub(privatekey)` → base64 compressed public key.
struct EccPrivToPub;
#[async_trait]
impl WsCommand for EccPrivToPub {
    fn name(&self) -> &'static str {
        "eccPrivToPub"
    }
    async fn handle(&self, _s: &WsSession, p: &Value) -> Result<Value, String> {
        let pk = p.as_array().and_then(|a| a.first()).or(Some(p)).and_then(|v| v.as_str()).ok_or("eccPrivToPub: privatekey")?;
        Ok(Value::from(b64_encode(&epix_crypt::private_to_compressed_pubkey(pk)?)))
    }
}

/// `eccPubToAddr(publickey_hex)` → epix1 address.
struct EccPubToAddr;
#[async_trait]
impl WsCommand for EccPubToAddr {
    fn name(&self) -> &'static str {
        "eccPubToAddr"
    }
    async fn handle(&self, _s: &WsSession, p: &Value) -> Result<Value, String> {
        let hexkey = p.as_array().and_then(|a| a.first()).or(Some(p)).and_then(|v| v.as_str()).ok_or("eccPubToAddr: publickey")?;
        let bytes = hex::decode(hexkey).map_err(|e| e.to_string())?;
        Ok(Value::from(epix_crypt::pubkey_to_address(&bytes)?))
    }
}

// ---- Newsfeed: aggregate followed sites' feeds -----------------------------

/// `feedFollow(feeds)` - save `{feed_name: [query, params]}` for the current site.
struct FeedFollow;
#[async_trait]
impl WsCommand for FeedFollow {
    fn name(&self) -> &'static str {
        "feedFollow"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let feeds = p.as_array().and_then(|a| a.first()).cloned().unwrap_or_else(|| p.clone());
        s.state.set_feed_follow(&address, feeds).await;
        Ok(Value::from("ok"))
    }
}

/// `feedListFollow()` - the current site's follows.
struct FeedListFollow;
#[async_trait]
impl WsCommand for FeedListFollow {
    fn name(&self) -> &'static str {
        "feedListFollow"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.feed_follow(s.address()?).await)
    }
}

/// `feedQuery(limit, day_limit)` - run each followed site's feed queries against
/// that site's db and merge the rows by `date_added` (newest first).
struct FeedQuery;
#[async_trait]
impl WsCommand for FeedQuery {
    fn name(&self) -> &'static str {
        "feedQuery"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let (limit, day_limit) = feed_limits(p);
        let follows = s.state.all_follows().await;

        let mut rows: Vec<Value> = Vec::new();
        let mut num_sites = 0;
        for (site, feeds) in &follows {
            let Some(feeds) = feeds.as_object() else { continue };
            num_sites += 1;
            for (name, query_set) in feeds {
                let (raw, params) = split_feed(query_set);
                if !is_safe_feed_sql(raw) {
                    continue;
                }
                let full = build_feed_query(raw, day_limit, limit, params);
                if !is_safe_feed_sql(&full) {
                    continue;
                }
                let Ok(res) = s.state.db_query(site, &full, &Value::Null).await else { continue };
                for mut row in res {
                    let Some(obj) = row.as_object_mut() else { continue };
                    // Normalize + sanity-check date_added (ms -> s; drop future items).
                    let Some(mut date) = obj.get("date_added").and_then(|v| v.as_f64()) else { continue };
                    if date > 1e12 {
                        date /= 1000.0;
                    }
                    if date > now_secs() + 120.0 {
                        continue;
                    }
                    obj.insert("date_added".into(), json!(date));
                    obj.insert("site".into(), json!(site));
                    obj.insert("feed_name".into(), json!(name));
                    rows.push(row);
                }
            }
        }

        rows.sort_by(|a, b| {
            let da = a["date_added"].as_f64().unwrap_or(0.0);
            let db = b["date_added"].as_f64().unwrap_or(0.0);
            db.partial_cmp(&da).unwrap_or(std::cmp::Ordering::Equal)
        });
        // No global cap: `limit` applies per feed query (in build_feed_query),
        // like EpixNet - a global truncate would let one busy feed crowd every
        // other site out of the merged view.
        Ok(json!({ "rows": rows, "num": rows.len(), "sites": num_sites }))
    }
}

/// `feedSearch(search, limit, day_limit)` - search every served xite's
/// dbschema-declared feeds (EpixNet's `actionFeedSearch`): the text becomes a
/// LIKE over the outer `body`/`title` aliases, with `site:` and `type:`
/// filters parsed out of the search string.
struct FeedSearch;
#[async_trait]
impl WsCommand for FeedSearch {
    fn name(&self) -> &'static str {
        "feedSearch"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let search = arg_str(p, "search", 0).unwrap_or("").to_string();
        let lookup = |key: &str, idx: usize| -> Option<&Value> {
            p.get(key).or_else(|| p.as_array().and_then(|a| a.get(idx)))
        };
        let as_num = |v: &Value| v.as_i64().or_else(|| v.as_str().and_then(|t| t.parse().ok()));
        let limit = lookup("limit", 1).and_then(as_num).unwrap_or(30).max(0) as usize;
        // Explicit null = no day filter, same as feedQuery.
        let day_limit = match lookup("day_limit", 2) {
            None => 30,
            Some(Value::Null) => 0,
            Some(v) => as_num(v).unwrap_or(30),
        };
        let (text, filters) = parse_search(&search);

        let mut rows: Vec<Value> = Vec::new();
        let mut num_sites = 0;
        for (address, title, feeds) in s.state.feed_sources().await {
            if let Some(want) = filters.get("site") {
                let want = want.to_lowercase();
                if want != address.to_lowercase() && want != title.to_lowercase() {
                    continue;
                }
            }
            num_sites += 1;
            for (feed_name, query) in feeds {
                if !is_safe_feed_sql(&query) {
                    continue;
                }
                // The type filter matches the literal query text, like EpixNet.
                if let Some(t) = filters.get("type") {
                    if !query.contains(t.as_str()) {
                        continue;
                    }
                }
                // Filters go on the wrapped aliases: `body`/`title` exist on
                // every feed's outer SELECT, and the CAST keeps the TEXT
                // strftime comparable to integer timestamps (see feedQuery).
                let mut wheres = vec!["1".to_string()];
                if day_limit > 0 {
                    wheres.push(format!(
                        "date_added > CAST(strftime('%s','now','-{day_limit} day') AS INTEGER)"
                    ));
                }
                let mut params: Vec<Value> = Vec::new();
                if !text.is_empty() {
                    wheres.push("(body LIKE ? OR title LIKE ?)".to_string());
                    let like = format!("%{}%", text.replace(' ', "%"));
                    params.push(json!(like));
                    params.push(json!(like));
                }
                let full = format!(
                    "SELECT * FROM ({query}) WHERE {} ORDER BY date_added DESC LIMIT {limit}",
                    wheres.join(" AND ")
                );
                if !is_safe_feed_sql(&full) {
                    continue;
                }
                let Ok(res) = s.state.db_query(&address, &full, &json!(params)).await else {
                    continue;
                };
                for mut row in res {
                    let Some(obj) = row.as_object_mut() else { continue };
                    let Some(mut date) = obj.get("date_added").and_then(|v| v.as_f64()) else {
                        continue;
                    };
                    if date > 1e12 {
                        date /= 1000.0;
                    }
                    if date > now_secs() + 120.0 {
                        continue;
                    }
                    obj.insert("date_added".into(), json!(date));
                    obj.insert("site".into(), json!(address));
                    obj.insert("feed_name".into(), json!(feed_name));
                    rows.push(row);
                }
            }
        }
        rows.sort_by(|a, b| {
            let da = a["date_added"].as_f64().unwrap_or(0.0);
            let db = b["date_added"].as_f64().unwrap_or(0.0);
            db.partial_cmp(&da).unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(json!({ "rows": rows, "num": rows.len(), "sites": num_sites }))
    }
}

/// Split `site:`/`type:` filters out of a feedSearch string (EpixNet's
/// `parseSearch`): everything before the first marker is the search text.
fn parse_search(search: &str) -> (String, std::collections::HashMap<String, String>) {
    let mut markers: Vec<(usize, &str)> = ["site:", "type:"]
        .iter()
        .flat_map(|m| search.match_indices(m).map(|(i, _)| (i, *m)).collect::<Vec<_>>())
        .collect();
    let mut filters = std::collections::HashMap::new();
    if markers.is_empty() {
        return (search.trim().to_string(), filters);
    }
    markers.sort();
    let text = search[..markers[0].0].trim().to_string();
    for (i, (pos, marker)) in markers.iter().enumerate() {
        let start = pos + marker.len();
        let end = markers.get(i + 1).map(|(p, _)| *p).unwrap_or(search.len());
        filters.insert(
            marker.trim_end_matches(':').to_string(),
            search[start..end].trim().to_string(),
        );
    }
    (text, filters)
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Parse `feedQuery`'s `(limit, day_limit)` from `[limit, day_limit]` or
/// `{limit, day_limit}` (defaults 10 / 3). An explicit `null` day_limit means
/// NO day filter (0) - the dashboard sends that to page back to the beginning
/// of the feed's history, and EpixNet's plugin treats None as unfiltered.
/// Only an absent key gets the 3-day default.
fn feed_limits(p: &Value) -> (usize, i64) {
    let lookup = |key: &str, idx: usize| -> Option<&Value> {
        p.get(key).or_else(|| p.as_array().and_then(|a| a.get(idx)))
    };
    let as_num = |v: &Value| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok()));
    let limit = lookup("limit", 0).and_then(as_num).unwrap_or(10).max(0) as usize;
    let day_limit = match lookup("day_limit", 1) {
        None => 3,
        Some(Value::Null) => 0,
        Some(v) => as_num(v).unwrap_or(3),
    };
    (limit, day_limit)
}

/// A follow entry is `[query, params]` (or a bare query string).
fn split_feed(query_set: &Value) -> (&str, &Value) {
    match query_set {
        Value::Array(a) => (
            a.first().and_then(|v| v.as_str()).unwrap_or(""),
            a.get(1).unwrap_or(&Value::Null),
        ),
        Value::String(s) => (s.as_str(), &Value::Null),
        _ => ("", &Value::Null),
    }
}

/// Wrap a feed query as a subquery with the day filter, ordering, and limit,
/// inlining `:params` (quoted) if present. Wrapping keeps `UNION` feeds intact.
fn build_feed_query(raw: &str, day_limit: i64, limit: usize, params: &Value) -> String {
    // CAST matters: strftime returns TEXT, and the subquery's date_added is an
    // expression with no column affinity - SQLite orders every INTEGER below
    // every TEXT, so without the cast the comparison is false for ALL rows and
    // the whole feed comes back empty.
    let day_filter = if day_limit > 0 {
        format!(
            "WHERE date_added > CAST(strftime('%s','now','-{day_limit} day') AS INTEGER)"
        )
    } else {
        String::new()
    };
    let mut q = format!("SELECT * FROM ({raw}) {day_filter} ORDER BY date_added DESC LIMIT {limit}");
    if q.contains(":params") {
        let inlined = params
            .as_array()
            .map(|a| a.iter().map(sqlquote).collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        q = q.replace(":params", &inlined);
    }
    q
}

/// SQL-literal-quote a JSON scalar (numbers verbatim, strings single-quoted).
fn sqlquote(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => (*b as i64).to_string(),
        Value::String(s) => format!("'{}'", s.replace('\'', "''")),
        _ => "null".into(),
    }
}

// ---- OptionalManager -------------------------------------------------------

/// `fileNeed(inner_path)` - download a file (optional or required) on demand.
struct FileNeed;
#[async_trait]
impl WsCommand for FileNeed {
    fn name(&self) -> &'static str {
        "fileNeed"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let inner_path = arg_str(p, "inner_path", 0).ok_or("fileNeed: inner_path required")?;
        let (address, inner_path) = s.resolve_target(inner_path).await?;
        s.state.file_need(&address, &inner_path).await?;
        Ok(Value::from("ok"))
    }
}

/// `optionalFileList(address, orderby, limit, filter)` - this xite's optional files.
struct OptionalFileList;
#[async_trait]
impl WsCommand for OptionalFileList {
    fn name(&self) -> &'static str {
        "optionalFileList"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let filter = p.get("filter").and_then(|v| v.as_str()).unwrap_or("downloaded");
        Ok(Value::Array(s.state.optional_file_list(&address, filter).await?))
    }
}

/// `optionalFileInfo(inner_path)`.
struct OptionalFileInfo;
#[async_trait]
impl WsCommand for OptionalFileInfo {
    fn name(&self) -> &'static str {
        "optionalFileInfo"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let inner_path = arg_str(p, "inner_path", 0).ok_or("optionalFileInfo: inner_path required")?;
        let (address, inner_path) = s.resolve_target(inner_path).await?;
        s.state.optional_file_info(&address, &inner_path).await
    }
}

/// `optionalFileDelete(inner_path)`.
struct OptionalFileDelete;
#[async_trait]
impl WsCommand for OptionalFileDelete {
    fn name(&self) -> &'static str {
        "optionalFileDelete"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let inner_path = arg_str(p, "inner_path", 0).ok_or("optionalFileDelete: inner_path required")?;
        s.state.optional_file_delete(&address, inner_path).await
    }
}

/// `optionalFilePin` / `optionalFileUnpin`.
struct OptionalFilePin {
    pin: bool,
}
#[async_trait]
impl WsCommand for OptionalFilePin {
    fn name(&self) -> &'static str {
        if self.pin { "optionalFilePin" } else { "optionalFileUnpin" }
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let inner_path = arg_str(p, "inner_path", 0).ok_or("inner_path required")?;
        s.state.set_pin(&address, inner_path, self.pin).await;
        Ok(Value::from("ok"))
    }
}

/// `optionalLimitStats` - optional-file storage usage (`{limit, used, free}`).
struct OptionalLimitStats;
#[async_trait]
impl WsCommand for OptionalLimitStats {
    fn name(&self) -> &'static str {
        "optionalLimitStats"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.optional_limit_stats().await)
    }
}

/// `optionalLimitSet(limit)` - set the optional-files cap (`"10%"` or a GB
/// number).
struct OptionalLimitSet;
#[async_trait]
impl WsCommand for OptionalLimitSet {
    fn name(&self) -> &'static str {
        "optionalLimitSet"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let limit = arg_str(p, "limit", 0).ok_or("optionalLimitSet: limit required")?;
        s.state.set_optional_limit(limit).await;
        Ok(Value::from("ok"))
    }
}

// ---- MergerSite ------------------------------------------------------------

/// `permissionAdd(permission)` - grant a permission to the current xite (e.g.
/// `Merger:ZeroMe`, which makes it a merger site).
struct PermissionAdd;
#[async_trait]
impl WsCommand for PermissionAdd {
    fn name(&self) -> &'static str {
        "permissionAdd"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let permission = p
            .as_str()
            .or_else(|| p.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()))
            .ok_or("permissionAdd: permission required")?;
        s.state.add_permission(&address, permission).await;
        Ok(Value::from("ok"))
    }
}

/// `permissionRemove(permission)` - revoke a permission from the current xite.
struct PermissionRemove;
#[async_trait]
impl WsCommand for PermissionRemove {
    fn name(&self) -> &'static str {
        "permissionRemove"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let permission = p
            .as_str()
            .or_else(|| p.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()))
            .ok_or("permissionRemove: permission required")?;
        s.state.remove_permission(&address, permission).await;
        Ok(Value::from("ok"))
    }
}

/// `permissionDetails(permission)` - the human-readable description the wrapper
/// shows in the grant prompt. ADMIN carries an explicit trust warning.
struct PermissionDetails;
#[async_trait]
impl WsCommand for PermissionDetails {
    fn name(&self) -> &'static str {
        "permissionDetails"
    }
    async fn handle(&self, _s: &WsSession, p: &Value) -> Result<Value, String> {
        let permission = p
            .as_str()
            .or_else(|| p.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()))
            .unwrap_or("");
        let details = match permission {
            "ADMIN" => "Allow this xite to administrate your Epix node \
                <span style='color: red'>(Make sure you trust the xite developer before accepting!)</span>",
            "NOSANDBOX" => "Allow this xite to run any code on your machine \
                <span style='color: red'>(Make sure you trust the xite developer before accepting!)</span>",
            p if p.starts_with("Merger:") => "Allow this xite to read and list other xites of a given type",
            _ => "",
        };
        Ok(Value::from(details))
    }
}

/// `mergerSiteList(query_site_info)` - the sites merged into this merger site.
struct MergerSiteList;
#[async_trait]
impl WsCommand for MergerSiteList {
    fn name(&self) -> &'static str {
        "mergerSiteList"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let query_info = p
            .as_bool()
            .or_else(|| p.as_array().and_then(|a| a.first()).and_then(|v| v.as_bool()))
            .unwrap_or(false);
        s.state.merger_list(&address, query_info).await
    }
}

/// Collect one or more addresses from a param (string or array).
fn arg_addresses(p: &Value) -> Vec<String> {
    match p {
        Value::String(a) => vec![a.clone()],
        // Positional call: the addresses are the first argument, which is
        // itself a list - `cmd("mergerSiteAdd", [needed])` sends
        // `[["addr", ...]]`. Unwrap that single nested array.
        Value::Array(a) if a.len() == 1 && a[0].is_array() => a[0]
            .as_array()
            .map(|inner| inner.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => p
            .get("addresses")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .or_else(|| p.get("address").and_then(|v| v.as_str()).map(|s| vec![s.to_string()]))
            .unwrap_or_default(),
    }
}

/// `mergerSiteAdd(addresses)` - clone the requested sites into the node and
/// link them into this merger's database (EpixNet's actionMergerSiteAdd,
/// which needs each address via SiteManager). One address adds without
/// asking; several ask the user first. Responds "ok" right away and clones
/// in the background, like EpixNet.
struct MergerSiteAdd;
#[async_trait]
impl WsCommand for MergerSiteAdd {
    fn name(&self) -> &'static str {
        "mergerSiteAdd"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        if s.state.merger_types(&address).await.is_empty() {
            return Err("Not a merger site".into());
        }
        let mut targets = Vec::new();
        for a in arg_addresses(p) {
            targets.push(require_address(&a)?);
        }
        if targets.is_empty() {
            return Err("mergerSiteAdd: addresses required".into());
        }
        let state = s.state.clone();
        let merger = address.clone();
        tokio::spawn(async move {
            if targets.len() > 1 {
                let body = format!("Add <b>{}</b> new site?", targets.len());
                if !state.confirm(&merger, &body, "Add").await {
                    return;
                }
            }
            let mut added = 0;
            for target in &targets {
                if state.ensure_xite(target).await {
                    added += 1;
                } else {
                    state.push_notification(
                        "error",
                        &format!("Adding <b>{target}</b> failed"),
                        0,
                    );
                }
            }
            if added > 0 {
                state.rebuild_merger_dbs().await;
                state.push_notification(
                    "done",
                    &format!("Added <b>{added}</b> new site"),
                    5000,
                );
                state.push_site_info(&merger).await;
            }
        });
        Ok(Value::from("ok"))
    }
}

/// `mergerSiteDelete(address)` - remove a merged site from the node.
struct MergerSiteDelete;
#[async_trait]
impl WsCommand for MergerSiteDelete {
    fn name(&self) -> &'static str {
        "mergerSiteDelete"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        if s.state.merger_types(&address).await.is_empty() {
            return Err("Not a merger site".into());
        }
        for target in arg_addresses(p) {
            s.state.remove_xite(&require_address(&target)?).await;
        }
        s.state.rebuild_merger_dbs().await;
        Ok(Value::from("ok"))
    }
}

// ---- Multiuser: identity login / switch ------------------------------------

/// `userShowMasterSeed()` - reveal the active identity's master seed.
#[cfg(feature = "multiuser")]
struct UserShowMasterSeed;
#[cfg(feature = "multiuser")]
#[async_trait]
impl WsCommand for UserShowMasterSeed {
    fn name(&self) -> &'static str {
        "userShowMasterSeed"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(json!({ "master_seed": s.state.multiuser_current_seed().await }))
    }
}

/// `userList()` - master addresses of every known identity (active first).
#[cfg(feature = "multiuser")]
struct UserList;
#[cfg(feature = "multiuser")]
#[async_trait]
impl WsCommand for UserList {
    fn name(&self) -> &'static str {
        "userList"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(json!(s.state.multiuser_list().await))
    }
}

/// `userLogin(master_seed)` - add/select an identity from a master seed.
#[cfg(feature = "multiuser")]
struct UserLogin;
#[cfg(feature = "multiuser")]
#[async_trait]
impl WsCommand for UserLogin {
    fn name(&self) -> &'static str {
        "userLogin"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let seed = arg_str(p, "master_seed", 0).ok_or("master_seed required")?;
        let addr = s.state.multiuser_login(seed).await?;
        Ok(json!({ "master_address": addr }))
    }
}

/// `userSet(master_address)` - switch the active identity.
#[cfg(feature = "multiuser")]
struct UserSet;
#[cfg(feature = "multiuser")]
#[async_trait]
impl WsCommand for UserSet {
    fn name(&self) -> &'static str {
        "userSet"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let addr = arg_str(p, "master_address", 0).ok_or("master_address required")?;
        s.state.multiuser_select(addr).await?;
        Ok(Value::from("ok"))
    }
}

/// `userLogout()` - revert to the primary identity.
#[cfg(feature = "multiuser")]
struct UserLogout;
#[cfg(feature = "multiuser")]
#[async_trait]
impl WsCommand for UserLogout {
    fn name(&self) -> &'static str {
        "userLogout"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        s.state.multiuser_logout().await?;
        Ok(Value::from("ok"))
    }
}

// ---- Site management actions (sidebar controls) ----------------------------

/// The target xite for a site action: an explicit `address` param, else the
/// bound xite.
/// Site commands reference a xite by its bech32 address only. A `.epix` name
/// (xID) is rejected so commands, events, grants, and persistence all key off
/// one identity; names are translated to addresses at the HTTP/WS edges.
fn require_address(addr: &str) -> Result<String, String> {
    if addr.contains('.') {
        return Err(format!("Site commands take the epix1 address, not a name: {addr}"));
    }
    Ok(addr.to_string())
}

fn target_address(s: &WsSession, p: &Value) -> Result<String, String> {
    match arg_str(p, "address", 0) {
        Some(a) => require_address(a),
        None => Ok(s.address()?.to_string()),
    }
}

/// `sitePause`/`siteResume` - stop or resume re-syncing a xite.
struct SiteServing {
    cmd: &'static str,
    serving: bool,
}
#[async_trait]
impl WsCommand for SiteServing {
    fn name(&self) -> &'static str {
        self.cmd
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = target_address(s, p)?;
        if s.state.set_serving(&address, self.serving).await {
            Ok(Value::from("ok"))
        } else {
            Err(format!("Unknown site: {address}"))
        }
    }
}

/// `siteDelete` - remove a xite from the node and delete its files.
struct SiteDelete;
#[async_trait]
impl WsCommand for SiteDelete {
    fn name(&self) -> &'static str {
        "siteDelete"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = target_address(s, p)?;
        if s.state.remove_xite(&address).await {
            Ok(Value::from("ok"))
        } else {
            Err(format!("Unknown site: {address}"))
        }
    }
}

/// `siteSetAutodownloadoptional` - toggle auto-downloading optional files.
/// `optionalHelp(directory, title, address?)` - opt into helping distribute
/// the optional files under a directory. Returns the count and total size.
struct OptionalHelp;
#[async_trait]
impl WsCommand for OptionalHelp {
    fn name(&self) -> &'static str {
        "optionalHelp"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = match arg_str(p, "address", 2) {
            Some(a) => a.to_string(),
            None => s.address()?.to_string(),
        };
        let directory = arg_str(p, "directory", 0).ok_or("optionalHelp: directory required")?;
        let title = arg_str(p, "title", 1).unwrap_or_default();
        let (num, size) = s
            .state
            .optional_help_add(&address, &directory, &title)
            .await
            .ok_or("Unknown site")?;
        s.state.push_notification(
            "done",
            &format!("You started to help distribute {title}. Directory: {directory}"),
            10000,
        );
        Ok(json!({ "num": num, "size": size }))
    }
}

/// `optionalHelpRemove(directory, address?)` - stop helping a directory.
struct OptionalHelpRemove;
#[async_trait]
impl WsCommand for OptionalHelpRemove {
    fn name(&self) -> &'static str {
        "optionalHelpRemove"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = match arg_str(p, "address", 1) {
            Some(a) => a.to_string(),
            None => s.address()?.to_string(),
        };
        let directory = arg_str(p, "directory", 0).ok_or("optionalHelpRemove: directory required")?;
        if s.state.optional_help_remove(&address, &directory).await {
            Ok(Value::from("ok"))
        } else {
            Ok(json!({ "error": "Not found" }))
        }
    }
}

/// `optionalHelpAll(value, address?)` - toggle auto-downloading every new
/// optional file on the site.
struct OptionalHelpAll;
#[async_trait]
impl WsCommand for OptionalHelpAll {
    fn name(&self) -> &'static str {
        "optionalHelpAll"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = match arg_str(p, "address", 1) {
            Some(a) => a.to_string(),
            None => s.address()?.to_string(),
        };
        let value = p
            .get("value")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        s.state.set_autodownloadoptional(&address, value).await;
        Ok(Value::from(value))
    }
}

struct SiteSetAutodownloadoptional;
#[async_trait]
impl WsCommand for SiteSetAutodownloadoptional {
    fn name(&self) -> &'static str {
        "siteSetAutodownloadoptional"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let on = p
            .get("owned")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        s.state.set_autodownloadoptional(&address, on).await;
        Ok(Value::from("ok"))
    }
}

/// `dbReload`/`dbRebuild` - rebuild the xite's database from its files.
struct DbRebuild {
    cmd: &'static str,
}
#[async_trait]
impl WsCommand for DbRebuild {
    fn name(&self) -> &'static str {
        self.cmd
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = target_address(s, p)?;
        if s.state.rebuild_xite_db(&address).await {
            Ok(Value::from("ok"))
        } else {
            Err(format!("Unknown site: {address}"))
        }
    }
}

/// `siteFavourite`/`siteUnfavourite` - toggle the sidebar favourite star.
struct SiteFavourite {
    cmd: &'static str,
    favorite: bool,
}
#[async_trait]
impl WsCommand for SiteFavourite {
    fn name(&self) -> &'static str {
        self.cmd
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = target_address(s, p)?;
        if s.state.set_favorite(&address, self.favorite).await {
            Ok(Value::from("ok"))
        } else {
            Err(format!("Unknown site: {address}"))
        }
    }
}

/// `peerAdd(ip, port, site_address?)` - add a peer to a xite's known set.
struct PeerAdd;
#[async_trait]
impl WsCommand for PeerAdd {
    fn name(&self) -> &'static str {
        "peerAdd"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ip = arg_str(p, "ip", 0).ok_or("ip required")?;
        let port = p
            .get("port")
            .or_else(|| p.as_array().and_then(|a| a.get(1)))
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .ok_or("port required")?;
        let address = match arg_str(p, "site_address", 2) {
            Some(a) => a.to_string(),
            None => s.address()?.to_string(),
        };
        s.state.add_peer_ipport(&address, ip, port as u16).await?;
        Ok(Value::from("updated"))
    }
}

/// `serverShowdirectory(directory, address?)` - open a xite's folder (or the
/// data dir) in the OS file manager. Local, desktop-oriented.
struct ServerShowdirectory;
#[async_trait]
impl WsCommand for ServerShowdirectory {
    fn name(&self) -> &'static str {
        "serverShowdirectory"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let directory = arg_str(p, "directory", 0).unwrap_or("backup");
        let path = if directory == "backup" {
            s.state.data_dir().ok_or("no data directory")?
        } else {
            let address = match arg_str(p, "address", 1) {
                Some(a) => a.to_string(),
                None => s.address()?.to_string(),
            };
            s.state.xite_root(&address).await.ok_or_else(|| format!("Unknown site: {address}"))?
        };
        open_path(&path);
        Ok(Value::from("ok"))
    }
}

/// Open a filesystem path in the OS file manager (best effort).
fn open_path(path: &std::path::Path) {
    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let program = "xdg-open";
    let _ = std::process::Command::new(program).arg(path).spawn();
}

/// `xidClearCache` - clear the xID resolver cache. The node's resolver cache is
/// per-process at the chain layer; clearing it here is a successful no-op.
struct XidClearCache;
#[async_trait]
impl WsCommand for XidClearCache {
    fn name(&self) -> &'static str {
        "xidClearCache"
    }
    async fn handle(&self, _s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(Value::from("ok"))
    }
}

/// `siteblockIgnoreAddSite(site_address)` - unblock a site so it can be added.
struct SiteblockIgnoreAddSite;
#[async_trait]
impl WsCommand for SiteblockIgnoreAddSite {
    fn name(&self) -> &'static str {
        "siteblockIgnoreAddSite"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = arg_str(p, "site_address", 0).ok_or("site_address required")?;
        s.state.siteblock_remove(address).await;
        Ok(Value::from("ok"))
    }
}

// ---- ContentFilter: mute + siteblock lists ---------------------------------

/// Read a positional-or-named string arg from the command params.
fn arg_str<'a>(p: &'a Value, key: &str, idx: usize) -> Option<&'a str> {
    p.get(key)
        .or_else(|| p.as_array().and_then(|a| a.get(idx)))
        .and_then(|v| v.as_str())
        .or_else(|| p.as_str())
}

/// `certAdd` - store a cert issued by an ID provider (bound to the site's auth
/// address) and select it globally. Not admin (any site can offer a cert).
struct CertAdd;
#[async_trait]
impl WsCommand for CertAdd {
    fn name(&self) -> &'static str {
        "certAdd"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let domain = arg_str(p, "domain", 0).ok_or("certAdd: domain required")?;
        let auth_type = arg_str(p, "auth_type", 1).unwrap_or("web");
        let auth_user_name = arg_str(p, "auth_user_name", 2).unwrap_or("");
        let cert = arg_str(p, "cert", 3).unwrap_or("");
        match s.state.cert_add(&address, domain, auth_type, auth_user_name, cert).await? {
            Some(true) => {
                s.state.push_notification(
                    "done",
                    &format!("New certificate added: {auth_type}/{auth_user_name}@{domain}"),
                    5000,
                );
                s.state.push_site_info(&address).await;
                Ok(Value::from("ok"))
            }
            // A different cert already exists for this domain: ask the user to
            // confirm the change (EpixNet's confirm prompt), then replace.
            Some(false) => {
                let ok = s
                    .state
                    .confirm(
                        &address,
                        &format!("Change your certificate to {auth_type}/{auth_user_name}@{domain}?"),
                        "Change",
                    )
                    .await;
                if !ok {
                    return Ok(Value::from("Not changed"));
                }
                s.state
                    .cert_replace(&address, domain, auth_type, auth_user_name, cert)
                    .await?;
                s.state.push_notification(
                    "done",
                    &format!("Certificate changed to {auth_type}/{auth_user_name}@{domain}"),
                    5000,
                );
                s.state.push_site_info(&address).await;
                Ok(Value::from("ok"))
            }
            None => Ok(Value::from("Not changed")),
        }
    }
}

/// `certSelect` - choose which stored identity to use on this site. Full picker
/// UI needs wrapper confirm/injectScript events (a follow-up); for now this
/// selects the first acceptable cert (or leaves the current one) and returns the
/// account list so a caller can display choices.
struct CertSelect;
#[async_trait]
impl WsCommand for CertSelect {
    fn name(&self) -> &'static str {
        "certSelect"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let accepted: Vec<String> = p
            .get("accepted_domains")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let accept_any = p.get("accept_any").and_then(|v| v.as_bool()).unwrap_or(accepted.is_empty());

        let certs = s.state.cert_list(&address).await;
        // Pick an acceptable cert to select (already-selected wins; else first).
        let acceptable = |domain: &str| accept_any || accepted.iter().any(|d| d == domain);
        let already = certs.iter().find(|c| c["selected"].as_bool() == Some(true));
        let choice = already
            .filter(|c| c["domain"].as_str().is_some_and(acceptable))
            .or_else(|| certs.iter().find(|c| c["domain"].as_str().is_some_and(acceptable)));
        if let Some(cert) = choice {
            if let Some(domain) = cert["domain"].as_str() {
                s.state.cert_set(domain).await;
                s.state.push_site_info(&address).await;
            }
        }
        // Return the accounts so a UI can present them (None + the certs).
        Ok(json!(certs))
    }
}

/// `certSet {domain}` - select a cert on all sites (portable cert), or clear
/// with an empty domain. Admin.
struct CertSet;
#[async_trait]
impl WsCommand for CertSet {
    fn name(&self) -> &'static str {
        "certSet"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let domain = arg_str(p, "domain", 0).unwrap_or("");
        s.state.cert_set(domain).await;
        if let Ok(addr) = s.address() {
            let addr = addr.to_string();
            s.state.push_site_info(&addr).await;
        }
        Ok(Value::from("ok"))
    }
}

/// `certXid` - the xID identity flow (EpixNet's `actionCertXid`). With no
/// name, shows the account picker (discovered linked xID names + a "New"
/// link) and acts on the choice; with a name, acquires that cert directly.
/// Self-signs the cert once the chosen address is verified on chain as an
/// active linked identity, else offers to open the xID site to link it.
struct CertXid;
#[async_trait]
impl WsCommand for CertXid {
    fn name(&self) -> &'static str {
        "certXid"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        // Optional direct name: positional `[name]` or `{xid_name}`.
        let xid_name = arg_str(p, "xid_name", 0).filter(|n| !n.is_empty());
        s.state.cert_xid(&address, xid_name).await
    }
}

/// `certList` - the user's certs with which is selected for this site. Admin.
struct CertList;
#[async_trait]
impl WsCommand for CertList {
    fn name(&self) -> &'static str {
        "certList"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        Ok(json!(s.state.cert_list(&address).await))
    }
}

/// `bigfileUploadInit {inner_path, size}` - start a Bigfile upload; returns the
/// POST URL, piece size, and the file's path relative to content.json. The
/// browser then POSTs the bytes to that URL.
struct BigfileUploadInit;
#[async_trait]
impl WsCommand for BigfileUploadInit {
    fn name(&self) -> &'static str {
        "bigfileUploadInit"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        let inner_path = arg_str(p, "inner_path", 0).ok_or("bigfileUploadInit: inner_path required")?;
        let size = p
            .get("size")
            .or_else(|| p.as_array().and_then(|a| a.get(1)))
            .and_then(|v| v.as_u64())
            .ok_or("bigfileUploadInit: size required")?;
        let (nonce, piece_size, file_relative_path) =
            s.state.bigfile_upload_init(&address, inner_path, size).await?;
        Ok(json!({
            "url": format!("/EpixNet-Internal/BigfileUpload?upload_nonce={nonce}"),
            "piece_size": piece_size,
            "inner_path": inner_path,
            "file_relative_path": file_relative_path,
        }))
    }
}

/// `siteSetAutodownloadBigfileLimit {limit}` - the max big-file size (MB) to
/// auto-download; persisted in config. Admin.
struct SiteSetAutodownloadBigfileLimit;
#[async_trait]
impl WsCommand for SiteSetAutodownloadBigfileLimit {
    fn name(&self) -> &'static str {
        "siteSetAutodownloadBigfileLimit"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let limit = p
            .get("limit")
            .or_else(|| p.as_array().and_then(|a| a.first()))
            .and_then(|v| v.as_i64())
            .ok_or("limit required")?;
        s.state.config_set("autodownload_bigfile_size_limit", json!(limit)).await;
        Ok(Value::from("ok"))
    }
}

/// `dirList {inner_path, stats?}` - list a directory's entries. With `stats`,
/// returns `[{name, is_dir, size}]`; otherwise just the names. Alias-/cors-/
/// merger-aware via resolve_target.
struct DirList;
#[async_trait]
impl WsCommand for DirList {
    fn name(&self) -> &'static str {
        "dirList"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let inner_path = arg_str(p, "inner_path", 0).unwrap_or("");
        let stats = p.get("stats").and_then(|v| v.as_bool()).unwrap_or(false);
        let (address, inner) = s.resolve_target(inner_path).await?;
        let entries = s.state.list_dir(&address, &inner).await.ok_or("dir not found")?;
        if stats {
            Ok(Value::Array(entries))
        } else {
            // Names only.
            Ok(Value::Array(
                entries.iter().filter_map(|e| e.get("name").cloned()).collect(),
            ))
        }
    }
}

/// `fileList {inner_path}` - recursively list every file under a directory as
/// inner paths.
struct FileList;
#[async_trait]
impl WsCommand for FileList {
    fn name(&self) -> &'static str {
        "fileList"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let inner_path = arg_str(p, "inner_path", 0).unwrap_or("");
        let (address, inner) = s.resolve_target(inner_path).await?;
        let files = s.state.walk_files(&address, &inner).await.ok_or("dir not found")?;
        Ok(json!(files))
    }
}

/// `siteReload {inner_path?}` - re-check the site for a newer content.json and
/// download changes (EpixNet reloads content + downloads). Admin.
struct SiteReload;
#[async_trait]
impl WsCommand for SiteReload {
    fn name(&self) -> &'static str {
        "siteReload"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let address = s.address()?.to_string();
        s.state.resync_xite(&address).await?;
        s.state.push_site_info(&address).await;
        Ok(Value::from("ok"))
    }
}

/// `siteBadFiles` - inner paths still missing/failed for this site.
struct SiteBadFiles;
#[async_trait]
impl WsCommand for SiteBadFiles {
    fn name(&self) -> &'static str {
        "siteBadFiles"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(json!(s.state.bad_files(s.address()?).await))
    }
}

/// `getTrackers` - the trackers this node announces to (AnnounceShare's shared
/// set), as address strings.
struct GetTrackers;
#[async_trait]
impl WsCommand for GetTrackers {
    fn name(&self) -> &'static str {
        "getTrackers"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let mut trackers: Vec<String> =
            s.state.shared_trackers().await.iter().map(|t| t.to_string()).collect();
        for t in s.state.extra_trackers().await {
            let t = t.to_string();
            if !trackers.contains(&t) {
                trackers.push(t);
            }
        }
        Ok(json!(trackers))
    }
}

struct MuteAdd;
#[async_trait]
impl WsCommand for MuteAdd {
    fn name(&self) -> &'static str {
        "muteAdd"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let auth = arg_str(p, "auth_address", 0).ok_or("muteAdd: auth_address required")?;
        let cert = arg_str(p, "cert_user_id", 1).unwrap_or("");
        let reason = arg_str(p, "reason", 2).unwrap_or("");
        s.state.mute_add(auth, cert, reason).await;
        Ok(Value::from("ok"))
    }
}

struct MuteRemove;
#[async_trait]
impl WsCommand for MuteRemove {
    fn name(&self) -> &'static str {
        "muteRemove"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let auth = arg_str(p, "auth_address", 0).ok_or("muteRemove: auth_address required")?;
        s.state.mute_remove(auth).await;
        Ok(Value::from("ok"))
    }
}

struct MuteList;
#[async_trait]
impl WsCommand for MuteList {
    fn name(&self) -> &'static str {
        "muteList"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.mute_list().await)
    }
}

struct SiteblockAdd;
#[async_trait]
impl WsCommand for SiteblockAdd {
    fn name(&self) -> &'static str {
        "siteblockAdd"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let site = arg_str(p, "site_address", 0).ok_or("siteblockAdd: site_address required")?;
        let site = require_address(site)?;
        let reason = arg_str(p, "reason", 1).unwrap_or("");
        s.state.siteblock_add(&site, reason).await;
        Ok(Value::from("ok"))
    }
}

struct SiteblockRemove;
#[async_trait]
impl WsCommand for SiteblockRemove {
    fn name(&self) -> &'static str {
        "siteblockRemove"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let site = arg_str(p, "site_address", 0).ok_or("siteblockRemove: site_address required")?;
        let site = require_address(site)?;
        s.state.siteblock_remove(&site).await;
        Ok(Value::from("ok"))
    }
}

struct SiteblockList;
#[async_trait]
impl WsCommand for SiteblockList {
    fn name(&self) -> &'static str {
        "siteblockList"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(s.state.siteblock_list().await)
    }
}

struct SiteblockGet;
#[async_trait]
impl WsCommand for SiteblockGet {
    fn name(&self) -> &'static str {
        "siteblockGet"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let site = arg_str(p, "site_address", 0).ok_or("siteblockGet: site_address required")?;
        Ok(s.state.siteblock_get(site).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::XiteEntry;
    use epix_xite::XiteStorage;

    #[tokio::test]
    async fn aes_decrypt_handles_single_and_batch_forms() {
        let state = AppState::new("test");
        let session = WsSession::new(state, Some("1site".into()));
        let iv = [7u8; 16];
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let ct1 = epix_crypt::ecies::aes_encrypt(b"hello", &key1, &iv).unwrap();
        let ct2 = epix_crypt::ecies::aes_encrypt(b"world", &key2, &iv).unwrap();

        // Single form: [iv, ct, key].
        let single = AesDecrypt
            .handle(&session, &json!([b64_encode(&iv), b64_encode(&ct1), b64_encode(&key1)]))
            .await
            .unwrap();
        assert_eq!(single, json!("hello"));

        // Batch form: two ciphertexts, two candidate keys; each finds its key.
        let batch = AesDecrypt
            .handle(
                &session,
                &json!([
                    [[b64_encode(&iv), b64_encode(&ct1)], [b64_encode(&iv), b64_encode(&ct2)]],
                    [b64_encode(&key1), b64_encode(&key2)]
                ]),
            )
            .await
            .unwrap();
        assert_eq!(batch, json!(["hello", "world"]));
    }

    #[tokio::test]
    async fn vrf_derive_random_wires_through_the_command() {
        let state = AppState::new("test");
        let session = WsSession::new(state, Some("1site".into()));
        let out = VrfDeriveRandom
            .handle(&session, &json!(["deadbeef", "myseed", 3]))
            .await
            .unwrap();
        // Returns `count` deterministic values, matching the pure derivation.
        let arr = out.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(out, json!(epix_chain::derive_random("deadbeef", "myseed", 3)));
    }

    #[tokio::test]
    async fn ecdsa_sign_then_verify_roundtrips() {
        let state = AppState::new("test");
        let session = WsSession::new(state, Some("1site".into()));
        // Sign with the user's auth key for the site (no explicit privatekey).
        let sig = EcdsaSign.handle(&session, &json!(["a message"])).await.unwrap();
        let sig = sig.as_str().unwrap();
        // The signer address is the user's auth address for this site.
        let address = session.state.user_auth_address("1site").await.unwrap();
        assert!(epix_crypt::verify("a message", &address, sig));
    }

    #[tokio::test]
    async fn server_info_reflects_upnp_port_status() {
        let state = AppState::new("test");
        let session = WsSession::new(state.clone(), Some("1site".into()));

        // Closed by default: port_opened false, ip_external false, port 0.
        let info = ServerInfo.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(info["port_opened"], false);
        assert_eq!(info["ip_external"], false);
        assert_eq!(info["fileserver_port"], 0);

        // The bound seeding port is reported.
        state.set_fileserver_port(26552).await;
        let info = ServerInfo.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(info["fileserver_port"], 26552);

        // Once UPnP opens the port, serverInfo shows it + the external IP string.
        state.set_port_status(true, Some("203.0.113.7".into())).await;
        let info = ServerInfo.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(info["port_opened"], true);
        assert_eq!(info["ip_external"], "203.0.113.7");

        // If we learn the IP but the port isn't open, ip_external stays false.
        state.set_port_status(false, Some("203.0.113.7".into())).await;
        let info = ServerInfo.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(info["port_opened"], false);
        assert_eq!(info["ip_external"], false);

        // A configured ip_external is a manual override, reported even when the
        // port isn't open.
        state.config_set("ip_external", json!("198.51.100.9")).await;
        let info = ServerInfo.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(info["ip_external"], "198.51.100.9");
    }

    #[tokio::test]
    async fn server_info_network_status_per_network_reachability() {
        let state = AppState::new("test");
        let session = WsSession::new(state.clone(), Some("1site".into()));

        // Nothing set up: no network reachable, clearnet disabled (port 0).
        let ns = ServerInfo.handle(&session, &Value::Null).await.unwrap()["network_status"].clone();
        assert_eq!(ns["reachable"], false);
        assert_eq!(ns["clearnet"]["enabled"], false);
        assert_eq!(ns["tor"]["reachable"], false);
        assert_eq!(ns["i2p"]["reachable"], false);

        // Clearnet port open -> clearnet reachable -> node reachable.
        state.set_fileserver_port(26552).await;
        state.set_port_status(true, Some("203.0.113.7".into())).await;
        let ns = ServerInfo.handle(&session, &Value::Null).await.unwrap()["network_status"].clone();
        assert_eq!(ns["reachable"], true);
        assert_eq!(ns["clearnet"]["reachable"], true);
        assert_eq!(ns["clearnet"]["port"], 26552);
        assert_eq!(ns["clearnet"]["ip"], "203.0.113.7");

        // Clearnet closed, but Tor up with a published onion -> still reachable.
        state.set_port_status(false, None).await;
        state.set_tor_status(true, "OK").await;
        state.set_onion_address("abcdef").await;
        let ns = ServerInfo.handle(&session, &Value::Null).await.unwrap()["network_status"].clone();
        assert_eq!(ns["clearnet"]["reachable"], false);
        assert_eq!(ns["tor"]["reachable"], true);
        assert_eq!(ns["tor"]["address"], "abcdef.onion");
        assert_eq!(ns["reachable"], true);

        // I2P with a built tunnel and address -> reachable, address suffixed.
        // Enabled but still starting (empty b32): not reachable, no address.
        state.set_i2p_status(json!({ "mode": "both", "phase": "Starting\u{2026}", "tunnels_built": 2, "b32": "" })).await;
        let ns = ServerInfo.handle(&session, &Value::Null).await.unwrap()["network_status"].clone();
        assert_eq!(ns["i2p"]["enabled"], true);
        assert_eq!(ns["i2p"]["reachable"], false);
        assert_eq!(ns["i2p"]["address"], Value::Null);

        // Inbound destination published (non-empty b32): reachable, suffixed.
        state.set_i2p_status(json!({ "mode": "both", "phase": "ready", "tunnels_built": 2, "b32": "xyz.b32" })).await;
        let ns = ServerInfo.handle(&session, &Value::Null).await.unwrap()["network_status"].clone();
        assert_eq!(ns["i2p"]["reachable"], true);
        assert_eq!(ns["i2p"]["address"], "xyz.b32.i2p");
    }

    #[tokio::test]
    async fn server_info_exposes_ui_restrict() {
        let state = AppState::new("test");
        let session = WsSession::new(state.clone(), Some("1site".into()));

        // Off by default.
        let info = ServerInfo.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(info["ui_restrict"], false);

        // Reflects the config (accepts the string "true", like ui_restrict()).
        state.config_set("ui_restrict", json!("true")).await;
        let info = ServerInfo.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(info["ui_restrict"], true);
    }

    #[tokio::test]
    async fn config_set_saves_and_notifies_on_language() {
        let state = AppState::new("test");
        let mut events = state.subscribe_events();
        let session = WsSession::new(state.clone(), Some("1site".into()));

        ConfigSet.handle(&session, &json!(["language", "de"])).await.unwrap();
        // Saved.
        assert_eq!(state.config_get("language").await, Some(json!("de")));
        // serverInfo reflects it.
        let info = ServerInfo.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(info["language"], "de");
        // A notification was pushed.
        let ev = events.try_recv().unwrap();
        let payload: Value = serde_json::from_str(&ev.payload).unwrap();
        assert_eq!(payload["cmd"], "notification");
        assert_eq!(payload["params"][0], "done");

        // A non-language key saves but pushes nothing.
        ConfigSet.handle(&session, &json!(["fileserver_port", 26552])).await.unwrap();
        assert_eq!(state.config_get("fileserver_port").await, Some(json!(26552)));
        assert!(events.try_recv().is_err());
    }

    #[tokio::test]
    async fn channel_join_records_subscriptions() {
        let session = WsSession::new(AppState::new("test"), Some("1site".into()));
        assert!(!session.in_channel("siteChanged"));

        // The wrapper form: {channels: [...]}.
        ChannelJoin { cmd: "channelJoin" }
            .handle(&session, &json!({ "channels": ["siteChanged", "serverChanged"] }))
            .await
            .unwrap();
        assert!(session.in_channel("siteChanged"));
        assert!(session.in_channel("serverChanged"));
        assert!(!session.in_channel("announcerChanged"));

        // channelJoin is site-scoped: not an all-site subscription.
        assert!(!session.in_allsite("siteChanged"));

        // channelJoinAllsite's {channel: "…"} form records + marks all-site, so
        // the connection receives that channel's events for every xite.
        ChannelJoin { cmd: "channelJoinAllsite" }
            .handle(&session, &json!({ "channel": "siteChanged" }))
            .await
            .unwrap();
        assert!(session.in_channel("siteChanged"));
        assert!(session.in_allsite("siteChanged"));
    }

    #[tokio::test]
    async fn cors_routes_only_with_permission() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite("1A", XiteEntry { storage: XiteStorage::new(dir.path().join("a")), content: None })
            .await;
        let session = WsSession::new(state.clone(), Some("1A".into()));

        // No Cors permission: a cors- path is rejected.
        assert!(session.cors_target("cors-1B/data.json").await.is_err());
        // A normal path resolves to the bound site.
        assert_eq!(
            session.cors_target("index.html").await.unwrap(),
            ("1A".to_string(), "index.html".to_string())
        );

        // Grant Cors:1B (as corsPermission does), then the cors- path routes to 1B.
        CorsPermission.handle(&session, &json!("1B")).await.unwrap();
        assert_eq!(
            session.cors_target("cors-1B/data.json").await.unwrap(),
            ("1B".to_string(), "data.json".to_string())
        );
    }

    #[tokio::test]
    async fn no_new_sites_blocks_add_and_delete_commands() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite("1Existing", XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;
        let registry = CommandRegistry::with_defaults();
        let session = WsSession::new(state.clone(), Some("1Existing".into()));
        state.add_permission("1Existing", "ADMIN").await;
        state.set_plugin_enabled("NoNewSites", true).await;

        // Deleting is refused while the node's site set is locked.
        let del = registry
            .dispatch(&session, "siteDelete", &json!({ "address": "1Existing" }), 1)
            .await;
        assert!(del.unwrap_err().contains("disabled"));
        assert!(state.has_xite("1Existing").await, "site survived the refused delete");

        // Unlocked again: the delete goes through.
        state.set_plugin_enabled("NoNewSites", false).await;
        let del = registry
            .dispatch(&session, "siteDelete", &json!({ "address": "1Existing" }), 2)
            .await;
        assert!(del.is_ok());
        assert!(!state.has_xite("1Existing").await);
    }

    #[cfg(feature = "multiuser")]
    #[tokio::test]
    async fn multiuser_commands_follow_the_plugin_toggle() {
        let state = AppState::new("test");
        let registry = CommandRegistry::with_defaults();
        let session = WsSession::new(state.clone(), Some("1Wrapper".into()));

        // Plugin off (the default): the command behaves as if unregistered.
        let off = registry.dispatch(&session, "userList", &json!([]), 1_000_001).await;
        assert_eq!(off.unwrap(), Value::Null);

        // Toggled on: it answers.
        state.set_plugin_enabled("Multiuser", true).await;
        let on = registry.dispatch(&session, "userList", &json!([]), 1_000_002).await;
        assert!(on.unwrap().is_array());
    }

    #[tokio::test]
    async fn admin_commands_are_gated_until_granted() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new("test");
        let addr = "1SomeXite";
        state
            .add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;
        let registry = CommandRegistry::with_defaults();
        let session = WsSession::new(state.clone(), Some(addr.into()));

        // Inner page (small id), no ADMIN yet: an admin command is refused.
        let denied = registry.dispatch(&session, "siteList", &json!([]), 5).await;
        assert!(denied.is_err(), "siteList must be denied without ADMIN");
        assert!(denied.unwrap_err().contains("permission"));

        // The trusted wrapper (elevated id) may run it even without a site grant.
        assert!(registry.dispatch(&session, "siteList", &json!([]), 1_000_001).await.is_ok());

        // Granting the site ADMIN (as the wrapper does after the user confirms)
        // then lets the inner page run admin commands too.
        state.add_permission(addr, "ADMIN").await;
        assert!(registry.dispatch(&session, "siteList", &json!([]), 6).await.is_ok());

        // A non-admin command is always allowed for the bound site.
        assert!(registry.dispatch(&session, "siteInfo", &json!([]), 7).await.is_ok());
    }

    #[tokio::test]
    async fn merger_site_lists_and_routes_merged_files() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new("test");

        // A merger site granted `Merger:ZeroMe`.
        let merger = "1Merger";
        state.add_xite(merger, XiteEntry { storage: XiteStorage::new(dir.path().join("m")), content: None }).await;
        state.add_permission(merger, "Merger:ZeroMe").await;

        // A merged site of that type, with a file.
        let merged = "1Merged";
        let mstore = XiteStorage::new(dir.path().join("d"));
        mstore.write("data.txt", b"merged file").unwrap();
        state
            .add_xite(merged, XiteEntry { storage: mstore, content: Some(json!({ "merged_type": "ZeroMe" })) })
            .await;
        // A site of a different merged type is excluded.
        state
            .add_xite("1Other", XiteEntry { storage: XiteStorage::new(dir.path().join("o")), content: Some(json!({ "merged_type": "OtherApp" })) })
            .await;

        let session = WsSession::new(state.clone(), Some(merger.into()));
        let list = MergerSiteList.handle(&session, &json!([false])).await.unwrap();
        assert_eq!(list["1Merged"], "ZeroMe");
        assert!(list.get("1Other").is_none(), "different merged type excluded");

        // fileGet routes a merged-<type>/<address>/<path> read to the merged site.
        let f = FileGet.handle(&session, &json!("merged-ZeroMe/1Merged/data.txt")).await.unwrap();
        assert_eq!(f, "merged file");

        // A non-merger site can't list.
        let s2 = WsSession::new(state, Some(merged.into()));
        assert!(MergerSiteList.handle(&s2, &json!([false])).await.is_err());
    }

    #[tokio::test]
    async fn cryptmessage_commands_round_trip() {
        let state = AppState::new("test");
        let addr = "1CryptSite";
        let session = WsSession::new(state.clone(), Some(addr.into()));

        // ECIES to my own key (index 0), then decrypt with my own key.
        let enc = EciesEncrypt.handle(&session, &json!(["secret 🔒", 0])).await.unwrap();
        let ct = enc.as_str().unwrap().to_string();
        let dec = EciesDecrypt.handle(&session, &json!([ct, 0])).await.unwrap();
        assert_eq!(dec, "secret 🔒");

        // AES round trip: aesEncrypt -> [key, iv, ct]; aesDecrypt([iv, ct, key]).
        let aes = AesEncrypt.handle(&session, &json!(["aes data"])).await.unwrap();
        let a = aes.as_array().unwrap();
        let dec = AesDecrypt.handle(&session, &json!([a[1], a[2], a[0]])).await.unwrap();
        assert_eq!(dec, "aes data");

        // ECC helpers + ecdsaVerify against a real signature.
        let pk = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let address = epix_crypt::privatekey_to_address(pk).unwrap();
        let sig = epix_crypt::sign("hello", pk).unwrap();
        assert_eq!(EcdsaVerify.handle(&session, &json!(["hello", address, sig])).await.unwrap(), true);

        // eccPrivToPub (base64 compressed) -> hex -> eccPubToAddr == address.
        let pub_b64 = EccPrivToPub.handle(&session, &json!([pk])).await.unwrap();
        let pub_bytes = b64_decode(pub_b64.as_str().unwrap()).unwrap();
        let derived = EccPubToAddr.handle(&session, &json!([hex::encode(&pub_bytes)])).await.unwrap();
        assert_eq!(derived, address);
    }

    #[tokio::test]
    async fn content_filter_mutes_and_siteblocks() {
        let state = AppState::new("test");
        let session = WsSession::new(state.clone(), Some("1site".into()));

        MuteAdd
            .handle(&session, &json!(["1AuthorAddr", "bob@xid.epix", "spam"]))
            .await
            .unwrap();
        let list = MuteList.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(list["1AuthorAddr"]["cert_user_id"], "bob@xid.epix");
        assert_eq!(list["1AuthorAddr"]["reason"], "spam");

        MuteRemove.handle(&session, &json!(["1AuthorAddr"])).await.unwrap();
        assert!(MuteList.handle(&session, &Value::Null).await.unwrap().as_object().unwrap().is_empty());

        SiteblockAdd.handle(&session, &json!(["1BadSite", "malware"])).await.unwrap();
        assert_eq!(SiteblockGet.handle(&session, &json!(["1BadSite"])).await.unwrap()["reason"], "malware");
        assert_eq!(SiteblockGet.handle(&session, &json!(["1GoodSite"])).await.unwrap(), Value::Bool(false));
        let blocks = SiteblockList.handle(&session, &Value::Null).await.unwrap();
        assert!(blocks["1BadSite"].is_object());
    }

    #[tokio::test]
    async fn bigfile_upload_init_and_finish() {
        let state = AppState::new("test");
        let dir = tempfile::tempdir().unwrap();
        let storage = epix_xite::XiteStorage::new(dir.path());
        storage.write("content.json", br#"{"address":"1Big","files_optional":{}}"#).unwrap();
        state
            .add_xite(
                "1Big",
                crate::state::XiteEntry {
                    storage,
                    // Owned site so the upload permission check passes.
                    content: Some(json!({ "address": "1Big" })),
                },
            )
            .await;
        state.set_owned("1Big", true).await;

        // A multi-piece file (3 pieces of 4 bytes) via the state path.
        let body = b"AAAABBBBCCCC";
        let (nonce, piece_size, rel) =
            state.bigfile_upload_init("1Big", "data/movie.bin", body.len() as u64).await.unwrap();
        assert_eq!(piece_size, 1024 * 1024);
        assert_eq!(rel, "movie.bin");

        // Finish with a small forced piece size by re-initing won't change piece
        // size; instead exercise finish with the real 1MB piece (single piece).
        let result = state.bigfile_upload_finish(&nonce, body).await.unwrap();
        assert_eq!(result.piece_num, 1, "12 bytes < 1MB is a single piece");
        assert_eq!(result.merkle_root, epix_xite::XiteStorage::hash_bytes(body));

        // The file was written and content.json gained a files_optional entry.
        assert_eq!(state.read_file("1Big", "data/movie.bin").await.as_deref(), Some(&body[..]));
        let content = state.content("1Big").await.unwrap();
        let entry = &content["files_optional"]["data/movie.bin"];
        assert_eq!(entry["size"], body.len());
        assert_eq!(entry["sha512"], result.merkle_root);

        // The nonce is single-use.
        assert!(state.bigfile_upload_finish(&nonce, body).await.is_err());
    }

    #[tokio::test]
    async fn dir_and_file_listing() {
        let state = AppState::new("test");
        let dir = tempfile::tempdir().unwrap();
        let storage = epix_xite::XiteStorage::new(dir.path());
        storage.write("index.html", b"<html>").unwrap();
        storage.write("js/app.js", b"1").unwrap();
        storage.write("js/lib/x.js", b"2").unwrap();
        state
            .add_xite(
                "1Files",
                crate::state::XiteEntry { storage, content: Some(json!({ "address": "1Files" })) },
            )
            .await;
        let session = WsSession::new(state, Some("1Files".into()));

        // dirList of the root: names only (dirs first).
        let names = DirList.handle(&session, &json!({ "inner_path": "" })).await.unwrap();
        let names: Vec<String> =
            names.as_array().unwrap().iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        assert!(names.contains(&"index.html".to_string()));
        assert!(names.contains(&"js".to_string()));

        // dirList with stats: objects with name/is_dir/size.
        let stats = DirList.handle(&session, &json!({ "inner_path": "", "stats": true })).await.unwrap();
        assert!(stats[0].get("is_dir").is_some());

        // fileList recurses.
        let files = FileList.handle(&session, &json!({ "inner_path": "" })).await.unwrap();
        let files: Vec<String> =
            files.as_array().unwrap().iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        assert!(files.contains(&"js/lib/x.js".to_string()), "recursive: {files:?}");
        assert_eq!(files.len(), 3);
    }

    #[tokio::test]
    async fn file_delete_removes_files_and_optional_entries() {
        let state = AppState::new("test");
        let dir = tempfile::tempdir().unwrap();
        let storage = epix_xite::XiteStorage::new(dir.path());
        storage.write("data/post.json", b"{}").unwrap();
        storage.write("movie.mp4", b"xxxx").unwrap();
        let content = json!({
            "address": "1Del",
            "files": { "data/post.json": { "size": 2, "sha512": "aa" } },
            "files_optional": { "movie.mp4": { "size": 4, "sha512": "bb" } },
        });
        storage.write("content.json", &serde_json::to_vec(&content).unwrap()).unwrap();
        state
            .add_xite(
                "1Del",
                crate::state::XiteEntry { storage: storage.clone(), content: Some(content) },
            )
            .await;
        let session = WsSession::new(state, Some("1Del".into()));

        // A required file: deleted from disk.
        let out = FileDelete.handle(&session, &json!(["data/post.json"])).await.unwrap();
        assert_eq!(out, json!("ok"));
        assert!(!storage.exists("data/post.json"));

        // An optional file: deleted AND dropped from content.json files_optional.
        FileDelete.handle(&session, &json!(["movie.mp4"])).await.unwrap();
        assert!(!storage.exists("movie.mp4"));
        let on_disk: Value =
            serde_json::from_slice(&storage.read("content.json").unwrap()).unwrap();
        assert!(on_disk["files_optional"].get("movie.mp4").is_none());

        // A missing non-optional file errors.
        assert!(FileDelete.handle(&session, &json!(["nope.txt"])).await.is_err());
    }

    #[tokio::test]
    async fn cert_add_select_list_flow() {
        let state = AppState::new("test");
        let dir = tempfile::tempdir().unwrap();
        state
            .add_xite(
                "talk.epix",
                crate::state::XiteEntry {
                    storage: epix_xite::XiteStorage::new(dir.path()),
                    content: Some(json!({ "address": "talk.epix" })),
                },
            )
            .await;
        let session = WsSession::new(state, Some("talk.epix".into()));

        // No certs yet.
        let list = CertList.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(list.as_array().unwrap().len(), 0);

        // certAdd stores + selects a cert for this site's identity.
        CertAdd
            .handle(&session, &json!({
                "domain": "xid.epix",
                "auth_type": "xid",
                "auth_user_name": "alice",
                "cert": "sig",
            }))
            .await
            .unwrap();
        let list = CertList.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["domain"], "xid.epix");
        assert_eq!(list[0]["auth_user_name"], "alice");
        assert_eq!(list[0]["selected"], true);

        // siteInfo now reports the cert user id.
        let info = SiteInfo.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(info["cert_user_id"], "alice@xid.epix");

        // certSet "" clears it everywhere.
        CertSet.handle(&session, &json!([""])).await.unwrap();
        let info = SiteInfo.handle(&session, &Value::Null).await.unwrap();
        assert!(info["cert_user_id"].is_null());
    }

    #[test]
    fn feed_sql_safety() {
        assert!(is_safe_feed_sql("SELECT post_id, title, date_added FROM post"));
        assert!(is_safe_feed_sql("SELECT * FROM post WHERE body LIKE '%hi%'"));
        assert!(!is_safe_feed_sql("SELECT 1; DROP TABLE post"));
        assert!(!is_safe_feed_sql("SELECT 1 -- comment"));
        assert!(!is_safe_feed_sql("DELETE FROM post"));
        assert!(!is_safe_feed_sql("SELECT 1 /* x */"));
        assert!(!is_safe_feed_sql("INSERT INTO post VALUES (1)"));
    }

    #[test]
    fn parse_search_splits_site_and_type_filters() {
        // EpixNet's parseSearch: everything before the first marker is the
        // text; marker values run to the next marker or the end.
        let (text, filters) = parse_search("hello world");
        assert_eq!(text, "hello world");
        assert!(filters.is_empty());

        let (text, filters) = parse_search("exploit site: EpixTalk type: comment");
        assert_eq!(text, "exploit");
        assert_eq!(filters["site"], "EpixTalk");
        assert_eq!(filters["type"], "comment");

        let (text, filters) = parse_search("site:talk.epix");
        assert_eq!(text, "");
        assert_eq!(filters["site"], "talk.epix");
    }

    #[test]
    fn feed_limits_null_day_limit_means_unfiltered() {
        // Absent -> the 3-day default.
        assert_eq!(feed_limits(&json!({ "limit": 20 })), (20, 3));
        // Explicit null -> no day filter (the dashboard pages back to the
        // beginning of history this way; EpixNet treats None the same).
        assert_eq!(feed_limits(&json!({ "limit": 20, "day_limit": null })), (20, 0));
        assert_eq!(feed_limits(&json!([20, null])), (20, 0));
        // A real value passes through.
        assert_eq!(feed_limits(&json!({ "limit": 50, "day_limit": 8 })), (50, 8));
    }

    #[test]
    fn build_feed_query_wraps_and_inlines_params() {
        let q = build_feed_query("SELECT * FROM post", 3, 10, &Value::Null);
        assert!(q.starts_with("SELECT * FROM (SELECT * FROM post)"));
        // CAST is load-bearing: strftime is TEXT and the subquery column has no
        // affinity, so an uncast comparison is false for every integer row.
        assert!(q.contains("date_added > CAST(strftime"), "cast day filter: {q}");
        assert!(q.ends_with("ORDER BY date_added DESC LIMIT 10"));

        let q = build_feed_query("SELECT * FROM post WHERE id IN (:params)", 0, 5, &json!([1, "a'b"]));
        assert!(q.contains("IN (1,'a''b')"), "params inlined + escaped: {q}");
        assert!(!q.contains("strftime"), "no day filter when day_limit=0");
    }

    #[tokio::test]
    async fn feed_query_aggregates_followed_sites() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "dbschema.json",
                br#"{ "db_name":"Blog","db_file":"db.db","version":2,
                     "maps": { "data/.*/data.json": { "to_table": [{"node":"posts","table":"post"}] } },
                     "tables": { "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["date_added","INTEGER"],["json_id","INTEGER"]] } } }"#,
            )
            .unwrap();
        storage
            .write(
                "data/alice/data.json",
                br#"{ "posts": [ {"post_id":1,"title":"Old","date_added":100},
                                 {"post_id":2,"title":"New","date_added":300} ] }"#,
            )
            .unwrap();

        let site = "1BlogAddr";
        let state = AppState::new("test");
        state.add_xite(site, XiteEntry { storage, content: None }).await;
        state
            .set_feed_follow(
                site,
                json!({ "posts": ["SELECT post_id, title, date_added FROM post", []] }),
            )
            .await;

        let session = WsSession::new(state, Some(site.to_string()));
        // day_limit = 0 so ancient test timestamps aren't filtered.
        let out = FeedQuery.handle(&session, &json!([10, 0])).await.unwrap();

        assert_eq!(out["sites"], 1);
        assert_eq!(out["num"], 2);
        let rows = out["rows"].as_array().unwrap();
        // Newest first, tagged with site + feed_name.
        assert_eq!(rows[0]["title"], "New");
        assert_eq!(rows[1]["title"], "Old");
        assert_eq!(rows[0]["site"], site);
        assert_eq!(rows[0]["feed_name"], "posts");
    }
}

/// Reject SQL that could break out of a single SELECT (matches EpixNet's
/// `is_safe_feed_sql`): no statement terminators/comments, no mutation/admin
/// keywords in statement position.
fn is_safe_feed_sql(sql: &str) -> bool {
    if sql.is_empty()
        || sql.contains(';')
        || sql.contains("--")
        || sql.contains("/*")
        || sql.contains("*/")
        || sql.contains('\0')
    {
        return false;
    }
    const FORBIDDEN: &[&str] = &[
        "insert", "update", "delete", "drop", "attach", "detach", "pragma", "begin", "commit",
        "rollback", "create", "alter", "vacuum", "reindex",
    ];
    let lower = sql.to_lowercase();
    for tok in lower.split(|c: char| !c.is_alphanumeric() && c != '_') {
        if FORBIDDEN.contains(&tok) {
            return false;
        }
    }
    true
}

/// A command that always returns a fixed value (for stubs the xite tolerates).
fn simple(name: &'static str, value: Value) -> SimpleCommand {
    SimpleCommand { name, value }
}

struct SimpleCommand {
    name: &'static str,
    value: Value,
}

#[async_trait]
impl WsCommand for SimpleCommand {
    fn name(&self) -> &'static str {
        self.name
    }
    async fn handle(&self, _s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(self.value.clone())
    }
}
