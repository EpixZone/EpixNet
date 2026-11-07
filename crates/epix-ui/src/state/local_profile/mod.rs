//! Opt-in, per-xite local profiles, without an xID dependency. Public documents
//! use the normal verified child-manifest pipeline; private groups contain only
//! authenticated profiles and use the existing native ECIES implementation.
mod protocol;
mod storage;
#[cfg(test)]
mod tests;

use super::AppState;
use crate::command::{WsCommand, WsSession};
use async_trait::async_trait;
use protocol::{string, Keys};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use storage::{Document, Documents};

#[derive(Clone, Copy)]
pub(crate) enum LocalProfileCommand {
    Info,
    Create,
    PublicPost,
    GroupCreate,
    Seal,
    Open,
    Verify,
    List,
    LinkXid,
}
impl LocalProfileCommand {
    pub(crate) fn is_command(cmd: &str) -> bool {
        cmd.starts_with("localProfile")
    }
}

#[async_trait]
impl WsCommand for LocalProfileCommand {
    fn name(&self) -> &'static str {
        match self {
            Self::Info => "localProfileInfo",
            Self::Create => "localProfileCreate",
            Self::PublicPost => "localProfilePublicPost",
            Self::GroupCreate => "localProfileGroupCreate",
            Self::Seal => "localProfileSeal",
            Self::Open => "localProfileOpen",
            Self::Verify => "localProfileVerify",
            Self::List => "localProfileList",
            Self::LinkXid => "localProfileLinkXid",
        }
    }
    async fn handle(&self, session: &WsSession, params: &Value) -> Result<Value, String> {
        if session.state.ui_restrict().await {
            return Err("Local profiles are unavailable on public gateways".into());
        }
        let address = session.address()?;
        let granted = session
            .state
            .xite_permissions(address)
            .await
            .iter()
            .any(|p| p == "LOCAL_PROFILE");
        if !granted {
            if matches!(self, Self::Info) {
                return Ok(
                    json!({"available":true,"granted":false,"profile":null,"can_link_xid":false,"limits":limits()}),
                );
            }
            return Err("LOCAL_PROFILE permission required".into());
        }
        if !params.is_object() {
            return Err("Local profile parameters must be an object".into());
        }
        if serde_json::to_vec(params).map_err(|e| e.to_string())?.len() > protocol::MAX_RECORD {
            return Err("Local profile request exceeds limit".into());
        }
        let state = session.state.clone();
        let guard = state.local_profile_lock.clone().lock_owned().await;
        if !state
            .xite_permissions(address)
            .await
            .iter()
            .any(|p| p == "LOCAL_PROFILE")
        {
            return Err("LOCAL_PROFILE permission required".into());
        }
        let canonical = state.local_profile_canonical(address).await?;
        let (keys, user_id, identity) = {
            let user = state.user.read().await;
            let scope = format!("{}:{canonical}", user.master_address);
            if session.local_profile_scope.get_or_init(|| scope.clone()) != &scope {
                return Err("Local profile changed; reopen this xite".into());
            }
            (
                Keys::from_seed(&user.master_seed, &canonical)?,
                user.master_address.clone(),
                user.identity_for(address).cloned(),
            )
        };
        let operation = Operation {
            state,
            address: address.to_string(),
            params: params.clone(),
            keys,
            user_id,
            identity,
            origin: session.id,
            guard,
        };
        let command = *self;
        // A disconnected page cannot release the identity/permission guard while
        // an owned child promotion is still committing its accepted update.
        tokio::spawn(async move { command.execute(operation).await })
            .await
            .map_err(|_| "Local profile operation failed".to_string())?
    }
}

fn limits() -> Value {
    json!({"group_members":protocol::MAX_MEMBERS,"text_bytes":protocol::MAX_TEXT,
        "document_bytes":storage::MAX_DOCUMENT,"public_history":128,"private_history":32,
        "list_documents":64,"list_attempts":128,"list_bytes":8*1024*1024,
        "record_checks":512,"decrypt_attempts":256})
}

struct Operation {
    state: Arc<AppState>,
    address: String,
    params: Value,
    keys: Keys,
    user_id: String,
    identity: Option<epix_user::Identity>,
    origin: u64,
    guard: tokio::sync::OwnedMutexGuard<()>,
}

impl LocalProfileCommand {
    async fn execute(&self, operation: Operation) -> Result<Value, String> {
        let Operation {
            state,
            address,
            params,
            keys,
            user_id,
            identity,
            origin,
            guard: _operation,
        } = operation;
        let address = address.as_str();
        let params = &params;
        if matches!(self, Self::Open | Self::Verify) {
            let record = if matches!(self, Self::Open) {
                &params["envelope"]
            } else {
                &params["record"]
            };
            let mut result = verify_view(&keys, record)?;
            resolve_profile_xid(&mut result).await;
            return Ok(result);
        }
        let documents = state.local_documents(address, &keys.author).await?;
        let own = documents
            .docs
            .iter()
            .find(|(author, _)| author == &keys.author)
            .map(|(_, doc)| doc.clone())
            .unwrap_or_default();
        let working_keys = keys.clone();
        let mut view = tokio::task::spawn_blocking(move || View::build(&working_keys, documents))
            .await
            .map_err(|_| "Local profile reader failed")??;
        match self {
            Self::Info => {
                let mut profile = view.own_profile(&keys.author);
                if let Some(profile) = &mut profile {
                    resolve_profile_xid(profile).await;
                }
                return Ok(
                    json!({"available":true,"granted":true,"profile":profile,"can_link_xid":identity.is_some(),"limits":limits()}),
                );
            }
            Self::List => {
                // Resolve a bounded set. Identity linkage is optional;
                // an offline/unknown name never prevents local chat operation.
                let mut lookups = 0;
                for profile in &mut view.profiles {
                    if !profile["xid"].is_null() && lookups < 4 {
                        resolve_profile_xid(profile).await;
                        lookups += 1;
                    }
                }
                return Ok(view.json());
            }
            _ => {}
        }
        let record = self.mutation(&keys, &own, &view, params, identity.as_ref())?;
        if state.user.read().await.master_address != user_id {
            return Err("Local profile changed; reopen this xite".into());
        }
        if !state
            .xite_permissions(address)
            .await
            .iter()
            .any(|p| p == "LOCAL_PROFILE")
        {
            return Err("LOCAL_PROFILE permission required".into());
        }
        let mut typed = verify_view(&keys, &record)?;
        state
            .local_commit(address, &keys, own.revision, record.clone(), origin)
            .await
            .map_err(|_| {
                "Signed profile update failed; reload and check this xite's user-content rules"
            })?;
        resolve_profile_xid(&mut typed).await;
        drop(_operation);
        let manifest = format!("data/users/{}/content.json", keys.author);
        let publish = match state.publish(address, &manifest, Some(origin), false).await {
            Ok(peers) => {
                json!({"status":if peers>0 {"accepted_by_peers"}else{"local_only"},"peers":peers})
            }
            Err(_) => {
                json!({"status":"local_only","peers":0,"error":"Peer publication failed; the signed update is saved locally"})
            }
        };
        Ok(json!({"record":typed,"publish":publish}))
    }
}

impl LocalProfileCommand {
    fn mutation(
        &self,
        keys: &Keys,
        own: &Document,
        view: &View,
        params: &Value,
        identity: Option<&epix_user::Identity>,
    ) -> Result<Value, String> {
        if matches!(self, Self::Create) {
            return keys.profile(string(params, "display_name")?, own.profile.as_ref());
        }
        let profile = own.profile.as_ref().ok_or("Create a local profile first")?;
        protocol::verify_profile(profile, &keys.xite)?;
        if profile["author"] != keys.author || profile["encryption_key"] != keys.public {
            return Err("Stored local profile does not match this identity".into());
        }
        match self {
            Self::PublicPost => {
                keys.public_post(profile, string(params, "room")?, string(params, "text")?)
            }
            Self::GroupCreate => {
                let profiles = params["profiles"]
                    .as_array()
                    .ok_or("Missing group profiles")?;
                let group = keys.group(string(params, "title")?, profiles, profile)?;
                keys.seal(&group, "invitation", "")
            }
            Self::Seal => {
                let group = view
                    .signed_groups
                    .get(string(params, "group_id")?)
                    .ok_or("Unknown private group")?;
                keys.seal(group, "message", string(params, "text")?)
            }
            Self::LinkXid => keys.link(profile, identity.ok_or("Select a linked xID first")?),
            _ => Err("Not a local profile mutation".into()),
        }
    }
}

struct ReadBudget {
    seen: HashSet<(String, String)>,
    decrypt: usize,
    verify: usize,
}

struct View {
    profiles: Vec<Value>,
    public_messages: Vec<Value>,
    private_messages: Vec<Value>,
    groups: Vec<Value>,
    signed_groups: HashMap<String, Value>,
    truncated: bool,
    rejected: usize,
}
impl View {
    fn build(keys: &Keys, documents: Documents) -> Result<Self, String> {
        let mut view = Self {
            profiles: Vec::new(),
            public_messages: Vec::new(),
            private_messages: Vec::new(),
            groups: Vec::new(),
            signed_groups: HashMap::new(),
            truncated: documents.truncated,
            rejected: documents.rejected,
        };
        let mut budget = ReadBudget {
            seen: HashSet::new(),
            decrypt: 256,
            verify: 512,
        };
        for (author, doc) in documents.docs {
            view.add_document(keys, &author, doc, &mut budget);
        }
        view.groups = view
            .signed_groups
            .values()
            .map(|group| group_view(keys, group))
            .collect();
        view.groups
            .sort_by(|a, b| a["group_id"].as_str().cmp(&b["group_id"].as_str()));
        for messages in [&mut view.public_messages, &mut view.private_messages] {
            messages.sort_by_key(|v| {
                (
                    v["sent_at"].as_u64().unwrap_or(0),
                    v["id"].as_str().unwrap_or("").to_string(),
                )
            });
        }
        Ok(view)
    }
    fn add_document(&mut self, keys: &Keys, author: &str, doc: Document, budget: &mut ReadBudget) {
        let Some(profile) = doc.profile else {
            self.rejected += 1;
            return;
        };
        if profile["author"] != author || protocol::verify_profile(&profile, &keys.xite).is_err() {
            self.rejected += 1;
            return;
        }
        self.profiles.push(profile_view(keys, &profile));
        for record in doc.public_messages.into_iter().chain(doc.private_messages) {
            if budget.verify == 0 {
                self.truncated = true;
                break;
            }
            self.add_record(keys, author, record, budget);
        }
    }

    fn add_record(&mut self, keys: &Keys, author: &str, record: Value, budget: &mut ReadBudget) {
        budget.verify -= 1;
        if record["author"] != author {
            self.rejected += 1;
            return;
        }
        let duplicate = (
            author.to_string(),
            record["id"].as_str().unwrap_or("").to_string(),
        );
        if budget.seen.contains(&duplicate) {
            return;
        }
        let accepted = match record["kind"].as_str() {
            Some("public") => match protocol::verify_public(&record, &keys.xite) {
                Ok(()) => {
                    self.public_messages.push(public_view(keys, &record));
                    true
                }
                Err(_) => {
                    self.rejected += 1;
                    false
                }
            },
            Some("private") => self.add_private(keys, &record, budget),
            _ => {
                self.rejected += 1;
                false
            }
        };
        if accepted {
            budget.seen.insert(duplicate);
        }
    }

    fn add_private(&mut self, keys: &Keys, record: &Value, budget: &mut ReadBudget) -> bool {
        if budget.decrypt == 0 {
            self.truncated = true;
            return false;
        }
        match keys.open(record, &mut budget.decrypt) {
            Ok(message) => {
                self.signed_groups.insert(
                    protocol::group_id(&message["group"]),
                    message["group"].clone(),
                );
                self.private_messages.push(private_view(keys, &message));
                return true;
            }
            Err(error) if error == "Not a recipient" => {}
            Err(error) if error == "Private read budget exhausted" => self.truncated = true,
            Err(_) => self.rejected += 1,
        }
        false
    }

    fn own_profile(&self, author: &str) -> Option<Value> {
        self.profiles
            .iter()
            .find(|p| p["author"] == author)
            .cloned()
    }
    fn json(self) -> Value {
        json!({"profiles":self.profiles,"public_messages":self.public_messages,"private_messages":self.private_messages,"groups":self.groups,"truncated":self.truncated,"rejected":self.rejected})
    }
}
fn profile_view(keys: &Keys, profile: &Value) -> Value {
    let link = &profile["xid"];
    json!({"author":profile["author"],"display_name":profile["display_name"],"encryption_key":profile["encryption_key"],
        "own":profile["author"]==keys.author,"signed_profile":profile,
        "xid":if link.is_null(){Value::Null}else{json!({"name":link["name"],"status":"unknown"})}})
}
fn public_view(keys: &Keys, record: &Value) -> Value {
    json!({"kind":"public","id":record["id"],"author":record["author"],"display_name":record["profile"]["display_name"],
        "room":record["room"],"text":record["text"],"sent_at":record["sent_at"],"own":record["author"]==keys.author})
}
fn group_view(keys: &Keys, group: &Value) -> Value {
    let members: Vec<_> = group["members"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| profile_view(keys, p))
        .collect();
    json!({"group_id":protocol::group_id(group),"title":group["title"],"members":members,"own_member":true})
}
fn private_view(keys: &Keys, message: &Value) -> Value {
    let group = &message["group"];
    let profile = group["members"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["author"] == message["author"]);
    let mut result = group_view(keys, group);
    let map = result.as_object_mut().expect("group view object");
    for field in ["kind", "id", "author", "sent_at", "text"] {
        map.insert(field.into(), message[field].clone());
    }
    map.insert(
        "display_name".into(),
        profile
            .map(|p| p["display_name"].clone())
            .unwrap_or(Value::Null),
    );
    map.insert("own".into(), json!(message["author"] == keys.author));
    result
}
fn verify_view(keys: &Keys, record: &Value) -> Result<Value, String> {
    match record["kind"].as_str() {
        Some("profile") => {
            protocol::verify_profile(record, &keys.xite)?;
            Ok(profile_view(keys, record))
        }
        Some("public") => {
            protocol::verify_public(record, &keys.xite)?;
            Ok(public_view(keys, record))
        }
        Some("private") => {
            let mut budget = protocol::MAX_MEMBERS;
            Ok(private_view(keys, &keys.open(record, &mut budget)?))
        }
        _ => Err("Unsupported local profile record".into()),
    }
}
async fn resolve_profile_xid(profile: &mut Value) {
    let link = &profile["signed_profile"]["xid"];
    let (Some(name), Some(author)) = (link["name"].as_str(), link["author"].as_str()) else {
        return;
    };
    let Some(label) = name.strip_suffix(".epix") else {
        return;
    };
    let lookup = epix_chain::xid_signers::resolve_identities_or_cached(label, "epix");
    let status = match tokio::time::timeout(Duration::from_millis(800), lookup).await {
        Ok(Ok((identities, stale))) => {
            if identities.iter().any(|i| {
                i.address == author && (!i.active || i.revoked_at != 0 || i.revoked_at_time != 0)
            }) {
                "revoked"
            } else if identities.iter().any(|i| i.address == author && i.active) {
                if stale {
                    "stale"
                } else {
                    "verified"
                }
            } else {
                "unknown"
            }
        }
        _ => "unknown",
    };
    profile["xid"]["status"] = json!(status);
}
