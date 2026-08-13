//! Generic local (never-shared) feed & notification sources.
//!
//! The dashboard's `feedQuery` and the wrapper badge's `notification_query` run
//! SQL over each xite's *shared* database. That is useless for data a node holds
//! only privately — most importantly a decrypted mailbox, whose whole point is
//! that nothing about it is shared. A [`LocalFeedSource`] lets a plugin
//! contribute rows and a badge count computed from its own private state, folded
//! into the same dashboard feed and badge with zero shared-DB footprint.
//!
//! This is generic: mail is the first source, but any pool-backed (or otherwise
//! private) feature can register one.

use crate::state::AppState;
use serde_json::Value;
use std::sync::Arc;

/// A contributor of private, node-local feed rows and a badge count.
#[async_trait::async_trait]
pub trait LocalFeedSource: Send + Sync {
    /// Dashboard-feed rows, each already shaped like a shared-feed row:
    /// `{ "type", "title", "body", "date_added" (unix seconds), "site",
    /// "feed_name" }`. Newest-first is not required — the caller re-sorts.
    async fn feed_rows(&self, limit: i64) -> Vec<Value>;

    /// A single notification entry `{ "site", "title", "name", "count",
    /// "last_seen" }`, or `None` when the source has nothing to report.
    async fn notification_entry(&self) -> Option<Value>;
}

impl AppState {
    /// Register a local feed/notification source (idempotent-ish: sources are
    /// simply appended; a plugin registers once at startup).
    pub async fn register_local_source(&self, source: Arc<dyn LocalFeedSource>) {
        self.local_sources_mut().await.push(source);
    }

    /// Fold every registered source's rows together (used by `feedQuery`).
    pub async fn local_feed_rows(&self, limit: i64) -> Vec<Value> {
        let sources = self.local_sources_snapshot().await;
        let mut rows = Vec::new();
        for s in sources {
            rows.extend(s.feed_rows(limit).await);
        }
        rows
    }

    /// Every registered source's notification entry (used by `notification_query`).
    pub async fn local_notification_entries(&self) -> Vec<Value> {
        let sources = self.local_sources_snapshot().await;
        let mut entries = Vec::new();
        for s in sources {
            if let Some(e) = s.notification_entry().await {
                entries.push(e);
            }
        }
        entries
    }
}
