//! The EpixFrame WebSocket command API: a trait-based registry that xites call.
//!
//! This is the seam the plugin system extends — each command is a [`WsCommand`],
//! and plugins register additional commands into the [`CommandRegistry`].

use crate::state::AppState;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// Per-connection context handed to every command.
pub struct WsSession {
    pub state: Arc<AppState>,
    /// The xite address this WebSocket connection is bound to (if any).
    pub xite: Option<String>,
}

impl WsSession {
    fn address(&self) -> Result<&str, String> {
        self.xite.as_deref().ok_or_else(|| "no xite bound to this connection".to_string())
    }
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
}

impl CommandRegistry {
    pub fn empty() -> Self {
        Self { commands: HashMap::new() }
    }

    /// The built-in command set (enough for the wrapper + a xite to load).
    pub fn with_defaults() -> Self {
        let mut r = Self::empty();
        for c in default_commands() {
            r.register(c);
        }
        r
    }

    pub fn register(&mut self, command: Arc<dyn WsCommand>) {
        self.commands.insert(command.name(), command);
    }

    pub fn has(&self, cmd: &str) -> bool {
        self.commands.contains_key(cmd)
    }

    pub async fn dispatch(
        &self,
        session: &WsSession,
        cmd: &str,
        params: &Value,
    ) -> Result<Value, String> {
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
    vec![
        Arc::new(Ping),
        Arc::new(ServerInfo),
        Arc::new(SiteInfo),
        Arc::new(simple("channelJoin", json!("ok"))),
        Arc::new(simple("channelJoinAllsite", json!("ok"))),
        Arc::new(simple("announcerInfo", json!({ "stats": {} }))),
        Arc::new(simple("permissionAdd", json!("ok"))),
        Arc::new(simple("permissionDetails", json!(""))),
        Arc::new(simple("configSet", json!("ok"))),
        Arc::new(simple("siteListModifiedFiles", json!({ "modified_files": [] }))),
        Arc::new(simple("userGetSettings", json!({}))),
        Arc::new(simple("userSetSettings", json!("ok"))),
        Arc::new(simple("optionalLimitStats", json!({ "limit": "10%", "used": 0, "free": 0 }))),
        Arc::new(simple("dbQuery", json!([]))),
        // Dashboard polling / lists — benign empty values.
        Arc::new(simple("serverErrors", json!([]))),
        Arc::new(simple("announcerStats", json!({}))),
        Arc::new(simple("siteList", json!([]))),
        Arc::new(simple("notificationQuery", json!([]))),
        Arc::new(simple("feedQuery", json!({ "rows": [] }))),
        Arc::new(simple("feedListFollow", json!({}))),
        Arc::new(simple("FilterIncludeList", json!([]))),
        Arc::new(simple("muteList", json!([]))),
        // Stateful — persist global settings so theme changes don't reload-loop.
        Arc::new(UserGetGlobalSettings),
        Arc::new(UserSetGlobalSettings),
        Arc::new(WrapperNonce),
        Arc::new(FileGet),
    ]
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
        let address = s.address()?;
        // params may be a bare inner_path string or an object with `inner_path`.
        let inner_path = p
            .as_str()
            .or_else(|| p.get("inner_path").and_then(|v| v.as_str()))
            .ok_or("fileGet: missing inner_path")?;
        match s.state.read_file(address, inner_path).await {
            Some(bytes) => Ok(Value::from(String::from_utf8_lossy(&bytes).into_owned())),
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

struct ServerInfo;
#[async_trait]
impl WsCommand for ServerInfo {
    fn name(&self) -> &'static str {
        "serverInfo"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        Ok(json!({
            "version": s.state.version,
            "rev": 8192,
            "platform": std::env::consts::OS,
            "ip_external": false,
            "tor_enabled": false,
            "tor_status": "Disabled",
            "ui_ip": "127.0.0.1",
            "ui_port": 43110,
            "debug": false,
            "offline": false,
            "plugins": [],
            "language": "en",
        }))
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
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let address = s.address()?;
        let content = s.state.content(address).await.unwrap_or(Value::Null);
        let short = if address.len() > 6 { &address[..6] } else { address };
        Ok(json!({
            "address": address,
            "address_short": short,
            "address_hash": "",
            "auth_address": "",
            "auth_key": "",
            "cert_user_id": Value::Null,
            "content": content,
            "content_updated": Value::Null,
            "bad_files": 0,
            "size_limit": 10,
            "next_size_limit": 10,
            "peers": 1,
            "started_task_num": 0,
            "tasks": 0,
            "workers": 0,
            "event": Value::Null,
            "settings": {
                "permissions": ["ADMIN"],
                "serving": true,
                "own": true,
                "size": 0,
                "modified": 0,
            },
        }))
    }
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
