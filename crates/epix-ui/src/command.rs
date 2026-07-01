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
    /// The xite address bound to this connection, or an error if none.
    pub fn address(&self) -> Result<&str, String> {
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
        Arc::new(DbQuery),
        // Dashboard polling / lists — benign empty values.
        Arc::new(simple("serverErrors", json!([]))),
        Arc::new(simple("announcerStats", json!({}))),
        Arc::new(simple("siteList", json!([]))),
        Arc::new(simple("notificationQuery", json!([]))),
        Arc::new(FeedQuery),
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
        Ok(s.state.site_info(address).await)
    }
}

/// `dbQuery(query, params)` — run a read query against the xite's database.
/// ZeroFrame passes `[query, params]`; we also accept a bare string or
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

// ---- Newsfeed: aggregate followed sites' feeds -----------------------------

/// `feedFollow(feeds)` — save `{feed_name: [query, params]}` for the current site.
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

/// `feedListFollow()` — the current site's follows.
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

/// `feedQuery(limit, day_limit)` — run each followed site's feed queries against
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
        rows.truncate(limit);
        Ok(json!({ "rows": rows, "num": rows.len(), "sites": num_sites }))
    }
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Parse `feedQuery`'s `(limit, day_limit)` from `[limit, day_limit]` or
/// `{limit, day_limit}` (defaults 10 / 3).
fn feed_limits(p: &Value) -> (usize, i64) {
    let get = |key: &str, idx: usize, default: i64| -> i64 {
        p.get(key)
            .or_else(|| p.as_array().and_then(|a| a.get(idx)))
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(default)
    };
    (get("limit", 0, 10).max(0) as usize, get("day_limit", 1, 3))
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
    let day_filter = if day_limit > 0 {
        format!("WHERE date_added > strftime('%s','now','-{day_limit} day')")
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

// ---- ContentFilter: mute + siteblock lists ---------------------------------

/// Read a positional-or-named string arg from the command params.
fn arg_str<'a>(p: &'a Value, key: &str, idx: usize) -> Option<&'a str> {
    p.get(key)
        .or_else(|| p.as_array().and_then(|a| a.get(idx)))
        .and_then(|v| v.as_str())
        .or_else(|| p.as_str())
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
        let reason = arg_str(p, "reason", 1).unwrap_or("");
        s.state.siteblock_add(site, reason).await;
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
        s.state.siteblock_remove(site).await;
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
    async fn content_filter_mutes_and_siteblocks() {
        let state = AppState::new("test");
        let session = WsSession { state: state.clone(), xite: Some("1site".into()) };

        MuteAdd
            .handle(&session, &json!(["1AuthorAddr", "bob@zeroid.bit", "spam"]))
            .await
            .unwrap();
        let list = MuteList.handle(&session, &Value::Null).await.unwrap();
        assert_eq!(list["1AuthorAddr"]["cert_user_id"], "bob@zeroid.bit");
        assert_eq!(list["1AuthorAddr"]["reason"], "spam");

        MuteRemove.handle(&session, &json!(["1AuthorAddr"])).await.unwrap();
        assert!(MuteList.handle(&session, &Value::Null).await.unwrap().as_object().unwrap().is_empty());

        SiteblockAdd.handle(&session, &json!(["1BadSite", "malware"])).await.unwrap();
        assert_eq!(SiteblockGet.handle(&session, &json!(["1BadSite"])).await.unwrap()["reason"], "malware");
        assert_eq!(SiteblockGet.handle(&session, &json!(["1GoodSite"])).await.unwrap(), Value::Bool(false));
        let blocks = SiteblockList.handle(&session, &Value::Null).await.unwrap();
        assert!(blocks["1BadSite"].is_object());
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
    fn build_feed_query_wraps_and_inlines_params() {
        let q = build_feed_query("SELECT * FROM post", 3, 10, &Value::Null);
        assert!(q.starts_with("SELECT * FROM (SELECT * FROM post)"));
        assert!(q.contains("date_added > strftime"));
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
                br#"{ "db_name":"Blog","db_file":"db/db.db","version":2,
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

        let session = WsSession { state, xite: Some(site.to_string()) };
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
