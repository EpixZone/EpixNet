//! Owner-set pool retention prunes expired shards from disk while keeping recent
//! ones. Retention is configured per-xite in content.json (`retention_weeks`);
//! `0`/absent keeps everything forever.

use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;

const XITE: &str = "epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa";

fn descriptor(retention_weeks: i64) -> serde_json::Value {
    json!({ "address": XITE, "pool": { "channels": {
        "dir": "pool", "class": "epix-pool-1", "since_week": 0, "fanout": 4,
        "pow_bits": 6, "pad_buckets": [64], "max_record_bytes": 4096,
        "max_shard_bytes": 1_000_000, "retention_weeks": retention_weeks
    }}})
}

fn current_week() -> i64 {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    (now_ms / 86_400_000) / 7
}

/// Write an empty pool shard file for `week`.
fn write_shard(root: &std::path::Path, week: i64) -> std::path::PathBuf {
    let dir = root.join(format!("pool/w{week}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("00.json");
    std::fs::write(&path, r#"{"record_format":"epix-pool-1","env":[]}"#).unwrap();
    path
}

#[tokio::test]
async fn retention_prunes_expired_shards_keeps_recent() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("data").join(XITE);
    std::fs::create_dir_all(&root).unwrap();

    let cur = current_week();
    let old = cur - 5; // well outside a 2-week window
    let old_shard = write_shard(&root, old);
    let recent_shard = write_shard(&root, cur);

    // A 2-week retention pool.
    let state = AppState::with_data_dir("test", home.path());
    state
        .add_xite(
            XITE,
            XiteEntry { storage: XiteStorage::new(&root), content: Some(descriptor(2)) },
        )
        .await;

    state.prune_expired_pool_shards(XITE).await;
    assert!(!old_shard.exists(), "a shard past the retention window is pruned");
    assert!(recent_shard.exists(), "a shard inside the window is kept");
}

#[tokio::test]
async fn zero_retention_keeps_everything() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("data").join(XITE);
    std::fs::create_dir_all(&root).unwrap();

    let cur = current_week();
    let ancient = write_shard(&root, cur - 500);

    // retention_weeks: 0 => indefinite; nothing is pruned.
    let state = AppState::with_data_dir("test", home.path());
    state
        .add_xite(
            XITE,
            XiteEntry { storage: XiteStorage::new(&root), content: Some(descriptor(0)) },
        )
        .await;

    state.prune_expired_pool_shards(XITE).await;
    assert!(ancient.exists(), "with retention off, even an ancient shard is kept");
}
