//! Bounded discovery of EPIXNET DNS hints. The snapshot endpoint is not a
//! proof: callers must resolve the returned names through the verified path.

use super::XidResolver;
use crate::{ChainError, Result};
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const PAGE_SIZE: usize = 10;
const PAGE_BYTES: usize = 512 * 1024;
const PAGES_PER_PASS: usize = 64;
const PASS_BUDGET: Duration = Duration::from_secs(20);
const HINT_TTL: Duration = Duration::from_secs(10 * 60);
const FAILURE_COOLDOWN: Duration = Duration::from_secs(5);
const MAX_HINTS: usize = 4096;
const MAX_CURSORS: usize = 128;
const MAX_CURSOR_BYTES: usize = 2048;
const MAX_CANDIDATES: usize = 8;

struct Hint {
    address: String,
    name: String,
    observed: Instant,
}

#[derive(Default)]
pub(super) struct Index {
    epoch: u64,
    endpoints: Vec<String>,
    hints: VecDeque<Hint>,
    cursor: Option<String>,
    recent_cursors: VecDeque<String>,
    completed: Option<Instant>,
    /// Eviction means an index miss cannot be cached as a negative answer.
    evicted: bool,
    retry_at: Option<Instant>,
}

impl Index {
    fn prepare(&mut self, endpoints: &[String]) {
        let expired = self.completed.is_some_and(|at| at.elapsed() >= HINT_TTL);
        if self.endpoints != endpoints || expired {
            *self = Self {
                epoch: self.epoch,
                endpoints: endpoints.to_vec(),
                ..Self::default()
            };
        }
        let before = self.hints.len();
        self.hints.retain(|hint| hint.observed.elapsed() < HINT_TTL);
        self.evicted |= before != self.hints.len();
    }

    fn candidates(&mut self, address: &str, tried: &[String]) -> Vec<String> {
        let mut names = Vec::new();
        let mut recent = Vec::new();
        // Move hits to the back, keeping recently viewed addresses in the LRU.
        for _ in 0..self.hints.len() {
            let hint = self.hints.pop_front().expect("bounded iteration");
            if hint.address == address {
                if !tried.contains(&hint.name) {
                    names.push(hint.name.clone());
                }
                recent.push(hint);
            } else {
                self.hints.push_back(hint);
            }
        }
        self.hints.extend(recent);
        names.sort();
        names.dedup();
        names.truncate(MAX_CANDIDATES);
        names
    }

    fn remember(&mut self, address: &str, name: String) {
        self.hints
            .retain(|hint| hint.address != address || hint.name != name);
        self.hints.push_back(Hint {
            address: address.to_string(),
            name,
            observed: Instant::now(),
        });
        if self.hints.len() > MAX_HINTS {
            self.hints.pop_front();
            self.evicted = true;
        }
    }

    fn apply_page(&mut self, page: &Value) -> Result<()> {
        let domains = page
            .get("domains")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("snapshot has no domains array"))?;
        if domains.len() > PAGE_SIZE {
            return Err(malformed("snapshot exceeds requested page size"));
        }
        let next = next_cursor(page)?;
        if next
            .as_ref()
            .is_some_and(|key| self.recent_cursors.contains(key))
        {
            return Err(malformed("snapshot pagination repeated a cursor"));
        }
        for domain in domains {
            self.remember_domain(domain);
        }
        if let Some(key) = &next {
            self.recent_cursors.push_back(key.clone());
            if self.recent_cursors.len() > MAX_CURSORS {
                self.recent_cursors.pop_front();
            }
        }
        self.completed = next.is_none().then(Instant::now);
        self.cursor = next;
        Ok(())
    }

    fn remember_domain(&mut self, domain: &Value) {
        let Some(name) = domain_name(domain) else {
            return;
        };
        if let Some(address) = epixnet_address(domain) {
            self.remember(address, name);
        }
    }
}

fn epixnet_address(domain: &Value) -> Option<&str> {
    // Match DomainSnapshot::xite_address: the first EPIXNET record is the
    // candidate. The page byte limit bounds scanning without truncating DNS.
    let record = domain
        .get("dns_records")?
        .as_array()?
        .iter()
        .find(|record| {
            record
                .get("record_type")
                .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
                == Some(crate::types::EPIXNET_RECORD_TYPE as u64)
        })?;
    let address = record.get("value")?.as_str()?.trim();
    (address.starts_with("epix1")
        && address.len() <= 90
        && address.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    .then_some(address)
}

fn domain_name(domain: &Value) -> Option<String> {
    let record = domain.get("record")?;
    if record.get("tld")?.as_str()? != "epix" {
        return None;
    }
    let name = record.get("name")?.as_str()?;
    let bytes = name.as_bytes();
    if bytes.len() > 63
        || !bytes.first()?.is_ascii_alphanumeric()
        || !bytes.last()?.is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return None;
    }
    Some(format!("{name}.epix"))
}

fn next_cursor(page: &Value) -> Result<Option<String>> {
    let pagination = page
        .get("pagination")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("snapshot has no pagination"))?;
    let next = match pagination.get("next_key") {
        Some(Value::String(key)) => key.as_str(),
        Some(Value::Null) | None => "",
        _ => return Err(malformed("snapshot cursor is not a string")),
    };
    if next.len() > MAX_CURSOR_BYTES {
        return Err(malformed("snapshot cursor is too large"));
    }
    Ok((!next.is_empty()).then(|| next.to_string()))
}

fn malformed(message: &str) -> ChainError {
    ChainError::Malformed(message.to_string())
}

pub(super) async fn lookup(
    resolver: &XidResolver,
    address: &str,
    tried: &[String],
) -> Result<Vec<String>> {
    crate::chain_egress_ok()?;
    if crate::verify_finality_enabled() && !crate::trust_usable() {
        return Err(ChainError::TrustNotEstablished);
    }
    // One scan per resolver, shared by every requesting tab/xite. Progress is
    // committed after each page, so cancellation never discards earlier pages.
    let epoch = resolver.reverse_epoch.load(Ordering::Acquire);
    let mut index = resolver.reverse_index.lock().await;
    ensure_current(resolver, epoch)?;
    if index.epoch != epoch {
        *index = Index {
            epoch,
            ..Index::default()
        };
    }
    index.prepare(&resolver.endpoints());
    let names = index.candidates(address, tried);
    if !names.is_empty() || (index.completed.is_some() && !index.evicted) {
        return Ok(names);
    }
    if index.retry_at.is_some_and(|at| at > Instant::now()) {
        return Err(ChainError::Rpc(
            "registry lookup is waiting to retry".into(),
        ));
    }
    if index.completed.is_some() {
        // A bounded cache may have evicted this address. Restart discovery on
        // a miss rather than inventing a permanent negative result.
        index.cursor = None;
        index.recent_cursors.clear();
        index.completed = None;
    }
    scan(resolver, address, tried, &mut index).await
}

fn ensure_current(resolver: &XidResolver, epoch: u64) -> Result<()> {
    if resolver.reverse_epoch.load(Ordering::Acquire) != epoch {
        return Err(ChainError::Rpc("registry lookup was cleared".into()));
    }
    Ok(())
}

async fn scan(
    resolver: &XidResolver,
    address: &str,
    tried: &[String],
    index: &mut Index,
) -> Result<Vec<String>> {
    let deadline = tokio::time::Instant::now() + PASS_BUDGET;
    for _ in 0..PAGES_PER_PASS {
        let page = next_page(resolver, index, deadline).await;
        // A cleared generation must neither publish a page nor install a
        // retry cooldown into the replacement index.
        ensure_current(resolver, index.epoch)?;
        if let Err(error) = page.and_then(|page| index.apply_page(&page)) {
            index.retry_at = Some(Instant::now() + FAILURE_COOLDOWN);
            return Err(error);
        }
        index.retry_at = None;
        let names = index.candidates(address, tried);
        if !names.is_empty() || index.completed.is_some() {
            return Ok(names);
        }
    }
    // This is deliberately not a negative result: the next call continues
    // with the saved cursor, even when the registry grows beyond one pass.
    Err(ChainError::Rpc(
        "registry lookup will resume after its page budget".into(),
    ))
}

async fn next_page(
    resolver: &XidResolver,
    index: &Index,
    deadline: tokio::time::Instant,
) -> Result<Value> {
    let changed = resolver.reverse_changed.notified();
    tokio::pin!(changed);
    changed.as_mut().enable();
    ensure_current(resolver, index.epoch)?;
    tokio::select! {
        _ = &mut changed => Err(ChainError::Rpc("registry lookup was cleared".into())),
        result = tokio::time::timeout_at(deadline, fetch_page(resolver, index.cursor.as_deref())) => {
            result.map_err(|_| ChainError::Rpc(
                "registry lookup will resume after its time budget".into()
            ))?
        }
    }
}

async fn fetch_page(resolver: &XidResolver, cursor: Option<&str>) -> Result<Value> {
    crate::chain_egress_ok()?;
    let client = resolver.client().await?;
    crate::rotate_endpoints(&resolver.endpoints(), &resolver.preferred, |base| {
        let client = client.clone();
        let cursor = cursor.map(str::to_string);
        async move {
            let mut url = reqwest::Url::parse(&format!("{base}/xid/v1/state_snapshot"))
                .map_err(|error| ChainError::Rpc(error.to_string()))?;
            url.query_pairs_mut().append_pair("pagination.limit", "10");
            if let Some(cursor) = cursor {
                url.query_pairs_mut().append_pair("pagination.key", &cursor);
            }
            let response = client
                .get(url)
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|error| ChainError::Rpc(error.to_string()))?;
            read_page(response).await
        }
    })
    .await
}

async fn read_page(mut response: reqwest::Response) -> Result<Value> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ChainError::Rpc(error.to_string()))?
    {
        if bytes.len().saturating_add(chunk.len()) > PAGE_BYTES {
            return Err(malformed("snapshot page exceeds byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| malformed(&format!("invalid snapshot JSON: {error}")))
}
