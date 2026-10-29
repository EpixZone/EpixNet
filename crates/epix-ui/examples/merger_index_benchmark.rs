//! Signed, offline merger-index benchmark. See docs/merger-index-benchmark.md.
//! This deliberately uses the public node paths, not a pre-populated database.

use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const FORMAT: u32 = 1;
const MERGER_TYPE: &str = "IndexBenchmark";
const SEGMENT_SIZE: usize = 1024;
const ITEMS_PER_HUB: usize = 10_000;

// Keep this exact harness usable on baseline revisions without diagnostics.
// Rust prefers AppState's inherent method when the node provides it.
#[allow(dead_code)]
trait BaselineDiagnostics {
    fn merger_index_stats(&self) -> Value;
}
impl BaselineDiagnostics for AppState {
    fn merger_index_stats(&self) -> Value {
        Value::Null
    }
}

#[derive(Debug)]
struct Options {
    root: PathBuf,
    items: usize,
    queries: usize,
    updates: usize,
    label: String,
    output: Option<PathBuf>,
    phase: Option<String>,
    existing: bool,
    prepare_only: bool,
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self> {
        let mut out = Self {
            root: PathBuf::new(),
            items: 10_000,
            queries: 100,
            updates: 5,
            label: "unlabelled".into(),
            output: None,
            phase: None,
            existing: false,
            prepare_only: false,
        };
        let mut args = args;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--existing" => out.existing = true,
                "--prepare-only" => out.prepare_only = true,
                "--root" | "--items" | "--queries" | "--updates" | "--label" | "--output"
                | "--phase" => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("missing value for {arg}"))?;
                    match arg.as_str() {
                        "--root" => out.root = value.into(),
                        "--items" => out.items = value.parse()?,
                        "--queries" => out.queries = value.parse()?,
                        "--updates" => out.updates = value.parse()?,
                        "--label" => out.label = value,
                        "--output" => out.output = Some(value.into()),
                        "--phase" => out.phase = Some(value),
                        _ => unreachable!(),
                    }
                }
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }
        if out.root.as_os_str().is_empty() {
            return Err("--root is required".into());
        }
        if !(1..=10_000_000).contains(&out.items) {
            return Err("--items must be 1..=10000000".into());
        }
        if !(1..=10_000).contains(&out.queries) {
            return Err("--queries must be 1..=10000".into());
        }
        if !(1..=10_000).contains(&out.updates) {
            return Err("--updates must be 1..=10000".into());
        }
        if out.existing && out.prepare_only {
            return Err("--existing conflicts with --prepare-only".into());
        }
        if out
            .phase
            .as_deref()
            .is_some_and(|phase| phase != "initial" && phase != "restart")
        {
            return Err("--phase must be initial or restart".into());
        }
        Ok(out)
    }
}

#[derive(Serialize, Deserialize)]
struct Hub {
    address: String,
    key: String,
    first_ordinal: usize,
    items: usize,
}

#[derive(Serialize, Deserialize)]
struct Fixture {
    format: u32,
    items: usize,
    segment_size: usize,
    frontend: String,
    hubs: Vec<Hub>,
}

// Public synthetic keys make independently generated baseline/candidate fixtures
// byte-identical. Never fund or deploy these identities outside this fixture.
fn fixture_key(label: &str) -> String {
    blake3::hash(format!("epix-merger-index-fixture-v1/{label}").as_bytes())
        .to_hex()
        .to_string()
}

fn signed_record(hub: &Hub, local_id: usize, clock: i64) -> Result<Value> {
    let ordinal = hub.first_ordinal + local_id - 1;
    let mut record = json!({
        "post_id": local_id, "key": format!("item-{local_id}"),
        "author": hub.address, "date_added": 1_700_000_000_i64,
        "clock": clock, "supersedes": 0, "deleted": false,
        "ordinal": ordinal, "title": format!("Fixture item {ordinal:010}"),
        "file_type": (["image", "audio", "video", "document"][ordinal % 4]),
        "body": format!("Signed catalogue fixture {ordinal}; group {}", ordinal % 100),
    });
    sign_record(&mut record, &hub.key)?;
    Ok(record)
}

fn sign_record(record: &mut Value, key: &str) -> Result<()> {
    record["sign"] = json!(epix_crypt::sign(
        &epix_content::record_signed_data(record),
        key
    )?);
    Ok(())
}

fn schema() -> Value {
    json!({
        "db_name": "IndexBenchmark", "db_file": "catalogue.db", "version": 3,
        "maps": {
            ".+/data/segments/[0-9]+[.]json$": {
                "to_table": [{"node": "post", "table": "item"}], "fold_crdt": "post"
            }
        },
        "tables": {"item": {
            "cols": [["post_id", "INTEGER"], ["author", "TEXT"], ["ordinal", "INTEGER"],
                ["title", "TEXT"], ["file_type", "TEXT"], ["body", "TEXT"], ["json_id", "INTEGER"]],
            "indexes": ["CREATE INDEX item_ordinal ON item(ordinal)",
                "CREATE INDEX item_type_ordinal ON item(file_type, ordinal)"]
        }}
    })
}

fn storage(root: &Path, address: &str) -> XiteStorage {
    XiteStorage::new(root.join("data").join(address))
}

fn write_manifest(storage: &XiteStorage, mut manifest: Value, key: &str) -> Result<()> {
    epix_content::sign(&mut manifest, key)?;
    storage.write(
        "content.json",
        epix_content::dumps_content(&manifest).as_bytes(),
    )?;
    Ok(())
}

fn generate(
    root: &Path,
    items: usize,
    segment_size: usize,
    items_per_hub: usize,
) -> Result<Fixture> {
    if root.exists() && std::fs::read_dir(root)?.next().is_some() {
        return Err("fixture root must be empty; existing files are never overwritten".into());
    }
    std::fs::create_dir_all(root)?;
    let frontend_key = fixture_key("frontend");
    let frontend = epix_crypt::privatekey_to_address(&frontend_key)?;
    let mut fixture = Fixture {
        format: FORMAT,
        items,
        segment_size,
        frontend,
        hubs: Vec::new(),
    };
    for first in (1..=items).step_by(items_per_hub) {
        let key = fixture_key(&format!("hub-{}", fixture.hubs.len()));
        let hub = Hub {
            address: epix_crypt::privatekey_to_address(&key)?,
            key,
            first_ordinal: first,
            items: items_per_hub.min(items - first + 1),
        };
        let store = storage(root, &hub.address);
        let mut declarations = serde_json::Map::new();
        for (segment, start) in (1..=hub.items).step_by(segment_size).enumerate() {
            let records = (start..(start + segment_size).min(hub.items + 1))
                .map(|local_id| signed_record(&hub, local_id, 1))
                .collect::<Result<Vec<_>>>()?;
            let bytes = serde_json::to_vec(&epix_content::make_container(records))?;
            if bytes.len() > 1_048_576 {
                return Err("fixture segment exceeded 1 MiB".into());
            }
            let path = format!("data/segments/{segment:06}.json");
            store.write(&path, &bytes)?;
            declarations.insert(
                path,
                json!({"class": "epix-orset-1", "max_size": 1_048_576}),
            );
        }
        write_manifest(
            &store,
            json!({
                "address": hub.address, "modified": 1, "merged_type": MERGER_TYPE,
                "files": {}, "files_merged": declarations
            }),
            &hub.key,
        )?;
        fixture.hubs.push(hub);
        if fixture.hubs.len() % 10 == 0 {
            eprintln!(
                "Generated {} signed items",
                first + fixture.hubs.last().unwrap().items - 1
            );
        }
    }
    let store = storage(root, &fixture.frontend);
    let bytes = serde_json::to_vec(&schema())?;
    store.write("dbschema.json", &bytes)?;
    write_manifest(
        &store,
        json!({
            "address": fixture.frontend, "modified": 1,
            "files": {"dbschema.json": {"size": bytes.len(), "sha512": XiteStorage::hash_bytes(&bytes)}}
        }),
        &frontend_key,
    )?;
    std::fs::write(
        root.join("fixture.json"),
        serde_json::to_vec_pretty(&fixture)?,
    )?;
    Ok(fixture)
}

fn read_fixture(root: &Path) -> Result<Fixture> {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(root.join("fixture.json"))?)?;
    if fixture.format != FORMAT {
        return Err("unsupported fixture format".into());
    }
    Ok(fixture)
}

async fn register(state: &AppState, root: &Path, address: &str) -> Result<()> {
    let store = storage(root, address);
    let content = serde_json::from_slice(&store.read("content.json")?)?;
    state
        .add_xite(
            address,
            XiteEntry {
                storage: store,
                content: Some(content),
            },
        )
        .await;
    if !state.has_any_alias(address).await {
        return Err(format!("node rejected fixture {address}").into());
    }
    Ok(())
}

fn milliseconds(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn distribution(samples: &[f64]) -> Value {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let percentile = |fraction: f64| {
        sorted[((sorted.len() as f64 * fraction).ceil() as usize).saturating_sub(1)]
    };
    json!({"samples": sorted.len(), "min_ms": sorted[0], "p50_ms": percentile(0.50),
        "p95_ms": percentile(0.95), "p99_ms": percentile(0.99), "max_ms": sorted[sorted.len() - 1]})
}

fn counter_delta(before: &Value, after: &Value) -> Value {
    let (Some(before), Some(after)) = (before.as_object(), after.as_object()) else {
        return Value::Null;
    };
    Value::Object(
        after
            .iter()
            .map(|(key, value)| {
                let delta = value
                    .as_u64()
                    .zip(before.get(key).and_then(Value::as_u64))
                    .and_then(|(new, old)| new.checked_sub(old));
                (key.clone(), json!(delta))
            })
            .collect(),
    )
}

async fn count(state: &AppState, frontend: &str) -> Result<usize> {
    let rows = state
        .db_query(frontend, "SELECT COUNT(*) AS count FROM item", &Value::Null)
        .await?;
    Ok(rows[0]["count"].as_u64().ok_or("missing row count")? as usize)
}

async fn assert_count(state: &AppState, fixture: &Fixture, expected: usize) -> Result<()> {
    let actual = count(state, &fixture.frontend).await?;
    if actual != expected {
        return Err(format!("expected {expected} live items, got {actual}").into());
    }
    Ok(())
}

async fn timed_queries(state: &AppState, fixture: &Fixture, repetitions: usize) -> Result<Value> {
    let mut timings = serde_json::Map::new();
    for (name, sql) in [
        ("first_page", "SELECT ordinal, title, file_type FROM item ORDER BY ordinal LIMIT 40"),
        ("deep_keyset_page", "SELECT ordinal, title FROM item WHERE ordinal > ? ORDER BY ordinal LIMIT 40"),
        ("indexed_type_filter", "SELECT ordinal, title, file_type FROM item WHERE file_type = 'video' AND ordinal > ? ORDER BY ordinal LIMIT 40"),
        ("indexed_lookup", "SELECT ordinal, title FROM item WHERE ordinal = ?"),
    ] {
        let mut samples = Vec::with_capacity(repetitions);
        for index in 0..repetitions {
            let params = match name {
                "first_page" => Value::Null,
                "deep_keyset_page" => json!([fixture.items.saturating_sub(40)]),
                _ => json!([1 + index * 7919 % fixture.items]),
            };
            let start = Instant::now();
            let rows = state.db_query(&fixture.frontend, sql, &params).await?;
            samples.push(milliseconds(start));
            if rows.len() > 40 { return Err("query exceeded page bound".into()); }
            let expected: Vec<usize> = match name {
                "first_page" => (1..=fixture.items.min(40)).collect(),
                "deep_keyset_page" => (fixture.items.saturating_sub(40) + 1..=fixture.items).collect(),
                "indexed_lookup" => vec![params[0].as_u64().unwrap() as usize],
                _ => {
                    let after = params[0].as_u64().unwrap() as usize;
                    ((after + 1)..=fixture.items).filter(|ordinal| ordinal % 4 == 2).take(40).collect()
                }
            };
            let actual = rows.iter().map(|row| row["ordinal"].as_u64().map(|value| value as usize)).collect::<Option<Vec<_>>>();
            if actual.as_ref() != Some(&expected) {
                return Err(format!("{name}: incorrect ordered result page; expected {expected:?}, got {actual:?}").into());
            }
            for (row, ordinal) in rows.iter().zip(expected) {
                if row["title"] != json!(format!("Fixture item {ordinal:010}")) {
                    return Err(format!("{name}: wrong title for item {ordinal}").into());
                }
                if let Some(file_type) = row.get("file_type") {
                    if file_type.as_str() != Some(["image", "audio", "video", "document"][ordinal % 4]) {
                        return Err(format!("{name}: wrong file type for item {ordinal}").into());
                    }
                }
            }
        }
        timings.insert(name.into(), distribution(&samples));
    }
    let plans = state.db_query(&fixture.frontend,
        "EXPLAIN QUERY PLAN SELECT ordinal, title FROM item WHERE ordinal > ? ORDER BY ordinal LIMIT 40",
        &json!([fixture.items.saturating_sub(40)])).await?;
    Ok(json!({"latencies": timings, "deep_page_query_plan": plans}))
}

async fn exercise_updates(
    state: &AppState,
    root: &Path,
    fixture: &Fixture,
    updates: usize,
) -> Result<Value> {
    let hub = &fixture.hubs[0];
    let store = storage(root, &hub.address);
    let path = "data/segments/000000.json";
    let mut container: Value = serde_json::from_slice(&store.read(path)?)?;
    let records = container["post"]
        .as_array()
        .ok_or("fixture has no records")?;
    let mut record = records[0].clone();
    let start_clock = record["clock"]
        .as_i64()
        .ok_or("fixture record lacks clock")?;
    let mut samples = Vec::new();
    let mut work_deltas = Vec::new();
    for index in 0..updates {
        record["supersedes"] = record["clock"].clone();
        record["clock"] = json!(start_clock + index as i64 + 1);
        record["body"] = json!(format!("Updated fixture record {index}"));
        sign_record(&mut record, &hub.key)?;
        container["post"]
            .as_array_mut()
            .unwrap()
            .push(record.clone());
        let bytes = serde_json::to_vec(&container)?;
        // Time local accepted-file ingress, including verification and SQL.
        // Fixture signing is separately excluded, like a remotely signed update.
        store.write(path, &bytes)?;
        let before = state.merger_index_stats();
        let start = Instant::now();
        state.ingest_file(&hub.address, path).await;
        samples.push(milliseconds(start));
        let delta = counter_delta(&before, &state.merger_index_stats());
        if delta["replayed_sources"]
            .as_u64()
            .is_some_and(|count| count > 1)
            || delta["verified_input_files"]
                .as_u64()
                .is_some_and(|count| count > 1)
        {
            return Err(format!(
                "one independent segment update performed nonlocal index work: {delta}"
            )
            .into());
        }
        work_deltas.push(delta);
        let rows = state
            .db_query(
                &fixture.frontend,
                "SELECT body FROM item WHERE ordinal = 1",
                &Value::Null,
            )
            .await?;
        if rows.first().and_then(|row| row.get("body"))
            != Some(&json!(format!("Updated fixture record {index}")))
        {
            return Err("signed update did not reach the merger".into());
        }
        assert_count(state, fixture, fixture.items).await?;
    }
    // A valid signature from an unauthorized author must never enter SQL.
    let stranger = Hub {
        address: epix_crypt::privatekey_to_address(&fixture_key("stranger"))?,
        key: fixture_key("stranger"),
        first_ordinal: fixture.items + 1,
        items: 1,
    };
    let mut unauthorized = signed_record(&stranger, 1, 1)?;
    // A distinct local ID makes incorrect acceptance add a row, rather than
    // disappearing as a losing version during per-file CRDT folding.
    unauthorized["post_id"] = json!(hub.items + 1);
    sign_record(&mut unauthorized, &stranger.key)?;
    container["post"].as_array_mut().unwrap().push(unauthorized);
    store.write(path, &serde_json::to_vec(&container)?)?;
    state.ingest_file(&hub.address, path).await;
    assert_count(state, fixture, fixture.items).await?;
    container["post"].as_array_mut().unwrap().pop();
    record["supersedes"] = record["clock"].clone();
    record["clock"] = json!(start_clock + updates as i64 + 1);
    record["deleted"] = json!(true);
    record["body"] = json!("");
    sign_record(&mut record, &hub.key)?;
    container["post"]
        .as_array_mut()
        .unwrap()
        .push(record.clone());
    store.write(path, &serde_json::to_vec(&container)?)?;
    state.ingest_file(&hub.address, path).await;
    assert_count(state, fixture, fixture.items - 1).await?;
    record["supersedes"] = record["clock"].clone();
    record["clock"] = json!(start_clock + updates as i64 + 2);
    record["deleted"] = json!(false);
    record["body"] = json!("Reinstated fixture record");
    sign_record(&mut record, &hub.key)?;
    container["post"].as_array_mut().unwrap().push(record);
    store.write(path, &serde_json::to_vec(&container)?)?;
    state.ingest_file(&hub.address, path).await;
    assert_count(state, fixture, fixture.items).await?;
    Ok(
        json!({"signed_segment_ingest": distribution(&samples), "unauthorized_author_rejected": true,
        "signed_segment_index_work": work_deltas,
        "same_segment_withdrawal_and_reinstatement": true}),
    )
}

fn process_memory() -> Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let bytes = |field: &str| {
        status.lines().find_map(|line| {
            line.strip_prefix(field)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
                .map(|kib| kib * 1024)
        })
    };
    json!({"rss_bytes": bytes("VmRSS:"), "peak_rss_bytes": bytes("VmHWM:"),
        "source": if status.is_empty() { Value::Null } else { json!("Linux /proc/self/status") }})
}

fn directory_bytes(root: &Path) -> Result<u64> {
    if !root.exists() {
        return Ok(0);
    }
    let mut bytes = 0;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_dir() {
                pending.push(entry.path());
            } else if meta.is_file() {
                bytes += meta.len();
            }
        }
    }
    Ok(bytes)
}

async fn run_phase(options: &Options) -> Result<Value> {
    let fixture = read_fixture(&options.root)?;
    let phase = options.phase.as_deref().ok_or("missing phase")?;
    if phase == "initial" && options.root.join("private/xites.json").exists() {
        return Err(
            "initial phase requires a fresh node registry; use a fresh fixture root".into(),
        );
    }
    let started = Instant::now();
    let state = AppState::with_data_dir("merger-index-benchmark", &options.root);
    if phase == "initial" {
        // Sources first: no target aggregate is repeatedly populated during setup.
        for (index, hub) in fixture.hubs.iter().enumerate() {
            register(&state, &options.root, &hub.address).await?;
            if index % 10 == 9 {
                eprintln!("Registered {} hubs", index + 1);
            }
        }
        register(&state, &options.root, &fixture.frontend).await?;
        state
            .add_permission(&fixture.frontend, &format!("Merger:{MERGER_TYPE}"))
            .await;
    } else {
        let restored = state.restore_xites().await;
        if restored != fixture.hubs.len() + 1 {
            return Err(format!(
                "restored {restored} xites, expected {}",
                fixture.hubs.len() + 1
            )
            .into());
        }
    }
    let registration_ms = milliseconds(started);
    let index_stats_after_registration = state.merger_index_stats();
    let reconcile = Instant::now();
    state.rebuild_merger_dbs().await;
    let reconcile_ms = milliseconds(reconcile);
    let explicit_reconcile_index_work =
        counter_delta(&index_stats_after_registration, &state.merger_index_stats());
    assert_count(&state, &fixture, fixture.items).await?;
    let ready_ms = milliseconds(started);
    let index_stats_after_ready = state.merger_index_stats();
    if phase == "restart"
        && index_stats_after_ready["replayed_sources"]
            .as_u64()
            .is_some_and(|count| count != 0)
    {
        return Err(format!(
            "unchanged restart replayed persisted projections: {index_stats_after_ready}"
        )
        .into());
    }
    let query_results = timed_queries(&state, &fixture, options.queries).await?;
    let update_results = if phase == "initial" {
        exercise_updates(&state, &options.root, &fixture, options.updates).await?
    } else {
        let rows = state
            .db_query(
                &fixture.frontend,
                "SELECT body FROM item WHERE ordinal = 1",
                &Value::Null,
            )
            .await?;
        if rows.first().and_then(|row| row.get("body")) != Some(&json!("Reinstated fixture record"))
        {
            return Err("restart lost the final signed update".into());
        }
        Value::Null
    };
    let identity_count = state.db_query(&fixture.frontend,
        "SELECT COUNT(*) AS count FROM (SELECT json.site, item.author, item.post_id FROM item JOIN json USING(json_id) GROUP BY json.site, item.author, item.post_id)",
        &Value::Null).await?;
    if identity_count[0]["count"].as_u64() != Some(fixture.items as u64) {
        return Err("source identity collision or duplicate live item".into());
    }
    state.persist_xites().await;
    Ok(
        json!({"phase": phase, "registration_ms": registration_ms, "explicit_reconcile_ms": reconcile_ms,
        "ready_with_correct_count_ms": ready_ms, "elapsed_ms": milliseconds(started),
        "live_rows": fixture.items, "distinct_hub_author_item_ids": fixture.items,
        "index_stats_after_ready": index_stats_after_ready,
        "index_stats_after_registration": index_stats_after_registration,
        "explicit_reconcile_index_work": explicit_reconcile_index_work,
        "index_stats_final": state.merger_index_stats(),
        "queries": query_results, "updates": update_results, "process_memory": process_memory(),
        "disk": {"data_bytes": directory_bytes(&options.root.join("data"))?,
            "private_bytes": directory_bytes(&options.root.join("private"))?,
            "derived_index_v1_bytes": directory_bytes(&options.root.join("private/cache/merger-index-v1"))?,
            "total_bytes": directory_bytes(&options.root)?},
        "cache_state": "fresh process; operating-system filesystem cache was not cleared"}),
    )
}

fn child_phase(options: &Options, phase: &str) -> Result<Value> {
    let output = options.root.join(format!("benchmark-{phase}.json"));
    let status = Command::new(std::env::current_exe()?)
        .arg("--root")
        .arg(&options.root)
        .arg("--phase")
        .arg(phase)
        .arg("--queries")
        .arg(options.queries.to_string())
        .arg("--updates")
        .arg(options.updates.to_string())
        .arg("--output")
        .arg(&output)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err(format!("{phase} child failed: {status}").into());
    }
    Ok(serde_json::from_slice(&std::fs::read(output)?)?)
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn executable_digest() -> Result<String> {
    let mut file = std::fs::File::open(std::env::current_exe()?)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

async fn run(options: &Options) -> Result<Value> {
    if options.phase.is_some() {
        return run_phase(options).await;
    }
    let generation = Instant::now();
    let (fixture, generation_ms) = if options.existing {
        (read_fixture(&options.root)?, None)
    } else {
        let fixture = generate(&options.root, options.items, SEGMENT_SIZE, ITEMS_PER_HUB)?;
        (fixture, Some(milliseconds(generation)))
    };
    if options.prepare_only {
        return Ok(
            json!({"format": FORMAT, "prepared": true, "items": fixture.items, "generation_ms": generation_ms}),
        );
    }
    let initial = child_phase(options, "initial")?;
    let restart = child_phase(options, "restart")?;
    Ok(json!({
        "benchmark": "epix-signed-merger-index", "format": FORMAT, "label": options.label,
        "executable_blake3": executable_digest()?,
        "git_commit_at_run": git_output(&["rev-parse", "HEAD"]),
        "git_dirty_at_run": git_output(&["status", "--porcelain"]).map(|text| !text.is_empty()),
        "build_profile": if cfg!(debug_assertions) { "debug-assertions" } else { "release-assertions-disabled" },
        "environment": {"os": std::env::consts::OS, "architecture": std::env::consts::ARCH,
            "logical_cpus": std::thread::available_parallelism().ok().map(|count| count.get()),
            "cpu_model": std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|text| text.lines().find_map(|line| line.strip_prefix("model name\t: ").map(String::from))),
            "memory_total": std::fs::read_to_string("/proc/meminfo").ok().and_then(|text| text.lines().find(|line| line.starts_with("MemTotal:")).map(String::from))},
        "fixture": {"items": fixture.items, "hubs": fixture.hubs.len(), "records_per_segment": fixture.segment_size,
            "generation_ms": generation_ms, "signed_record_verification": true, "owner_signed_hubs": true,
            "media_bytes": 0, "full_trove_release_fixture": false},
        "initial": initial, "restart": restart
    }))
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        println!("merger_index_benchmark --root EMPTY_DIRECTORY [--items 10000|100000|1000000|10000000] [--queries 100] [--updates 5] [--label NAME] [--output JSON]\n  --prepare-only generates signed inputs without starting a node\n  --existing runs a previously prepared, unused fixture\nSee docs/merger-index-benchmark.md for scope and baseline comparison.");
        return Ok(());
    }
    let mut options = Options::parse(std::env::args().skip(1))?;
    if !options.existing && options.phase.is_none() {
        std::fs::create_dir_all(&options.root)?;
    }
    options.root = options.root.canonicalize()?;
    let result = run(&options).await?;
    let bytes = serde_json::to_vec_pretty(&result)?;
    if let Some(output) = &options.output {
        std::fs::write(output, &bytes)?;
    }
    if options.phase.is_none() {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_root_and_unbounded_work() {
        assert!(Options::parse(["--items", "10000"].map(String::from).into_iter()).is_err());
        assert!(Options::parse(
            ["--root", "/tmp/example", "--items", "10000001"]
                .map(String::from)
                .into_iter()
        )
        .is_err());
        assert!(Options::parse(
            ["--root", "/tmp/example", "--queries", "0"]
                .map(String::from)
                .into_iter()
        )
        .is_err());
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let values = (1..=100).map(f64::from).collect::<Vec<_>>();
        let result = distribution(&values);
        assert_eq!(result["p95_ms"], 95.0);
        assert_eq!(result["p99_ms"], 99.0);
    }

    #[tokio::test]
    async fn signed_fixture_roundtrip_through_node_ingest_and_restart() {
        let root = tempfile::tempdir().unwrap();
        generate(root.path(), 27, 4, 10).unwrap();
        assert!(
            generate(root.path(), 27, 4, 10).is_err(),
            "never overwrite existing inputs"
        );
        let mut options = Options::parse(
            [
                "--root".into(),
                root.path().display().to_string(),
                "--queries".into(),
                "3".into(),
                "--updates".into(),
                "2".into(),
                "--phase".into(),
                "initial".into(),
            ]
            .into_iter(),
        )
        .unwrap();
        let first = run_phase(&options).await.unwrap();
        assert_eq!(first["live_rows"], 27);
        assert_eq!(first["updates"]["unauthorized_author_rejected"], true);
        options.phase = Some("restart".into());
        let second = run_phase(&options).await.unwrap();
        assert_eq!(second["distinct_hub_author_item_ids"], 27);
    }
}
