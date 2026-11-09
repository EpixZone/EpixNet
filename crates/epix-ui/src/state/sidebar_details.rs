//! Read-only sidebar summaries from accepted manifests and the active database.
use super::*;
use std::collections::{BTreeMap, HashSet};

impl AppState {
    pub async fn sidebar_details(&self, address: &str) -> Value {
        let (storage, content, db, schema) = {
            let xites = self.xites.read().await;
            let Some(xite) = xites.get(address) else {
                return Value::Null;
            };
            (
                xite.storage.clone(),
                xite.content.clone(),
                xite.db.clone(),
                xite.db_schema.clone(),
            )
        };
        let canonical = canonical_address(content.as_ref(), address);
        let storage_summary = {
            let _tree = self.tree_mutation_lock(&canonical).lock_owned().await;
            self.accepted_db_authority_for_root_locked(&canonical, content.as_ref())
                .ok()
                .and_then(|authority| summarize_storage(&storage, &authority.manifests))
        };
        let database = db
            .as_ref()
            .map(|db| summarize_database(db, storage.root(), schema.as_ref()));
        let auth = self.user.read().await.auth_address(address).ok();
        // Do not use file_rules' generic fallback quota: only display a quota
        // when the current accepted user-content authority actually grants it.
        let quota = match auth {
            Some(auth) => self
                .user_content_rules(address, &format!("data/users/{auth}/content.json"))
                .await
                .filter(|rules| rules["max_size"].as_u64().is_some())
                .map(|rules| json!({"used": rules["current_size"], "limit": rules["max_size"]})),
            None => None,
        };
        json!({
            "storage": storage_summary,
            "free_bytes": disk_free_bytes(storage.root()),
            "database": database,
            "identity_quota": quota,
        })
    }
}

fn summarize_storage(storage: &XiteStorage, manifests: &[VerifiedManifestUnit]) -> Option<Value> {
    let by_path: BTreeMap<_, _> = manifests
        .iter()
        .map(|unit| (unit.inner_path.as_str(), &unit.content))
        .collect();
    let mut site_manifests = HashSet::new();
    let mut pending = vec!["content.json".to_string()];
    while let Some(path) = pending.pop() {
        if !site_manifests.insert(path.clone()) {
            continue;
        }
        let content = by_path.get(path.as_str())?;
        let directory = path
            .rsplit_once('/')
            .map(|(dir, _)| format!("{dir}/"))
            .unwrap_or_default();
        if let Some(includes) = content["includes"].as_object() {
            for relative in includes.keys() {
                let child = format!("{directory}{relative}");
                // A declared include can still be awaiting download.
                if by_path.contains_key(child.as_str()) {
                    pending.push(child);
                }
            }
        }
    }
    let mut sizes = BTreeMap::<&str, u64>::new();
    let mut seen = HashSet::new();
    for unit in manifests {
        let user_data = !site_manifests.contains(&unit.inner_path);
        let category = if user_data { "User data" } else { "JSON" };
        // The original signed bytes are counted, including formatting/signatures.
        let bytes = manifest_size(storage, &unit.inner_path)?;
        *sizes.entry(category).or_default() += bytes;
        let directory = unit
            .inner_path
            .rsplit_once('/')
            .map(|(dir, _)| format!("{dir}/"))
            .unwrap_or_default();
        if let Some(files) = unit.content["files"].as_object() {
            for (path, entry) in files {
                let full_path = format!("{directory}{path}");
                if !seen.insert(full_path) {
                    continue;
                }
                let bytes = epix_content::verify::exact_nonnegative_size(&entry["size"])
                    .and_then(|size| u64::try_from(size).ok())?;
                let category = if user_data {
                    "User data"
                } else {
                    file_category(path)
                };
                let size = sizes.entry(category).or_default();
                *size = size.checked_add(bytes)?;
            }
        }
    }
    let total = sizes
        .values()
        .try_fold(0u64, |total, n| total.checked_add(*n))?;
    let types: Vec<_> = [
        "HTML",
        "CSS",
        "JavaScript",
        "Images",
        "JSON",
        "User data",
        "Other",
    ]
    .iter()
    .map(|name| json!({"name": name, "bytes": sizes.get(name).copied().unwrap_or(0)}))
    .collect();
    Some(json!({"types": types, "total": total, "files": seen.len()}))
}

fn file_category(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "HTML",
        "css" => "CSS",
        "js" | "mjs" => "JavaScript",
        "jpg" | "jpeg" | "png" | "gif" | "svg" | "webp" | "avif" | "ico" => "Images",
        "json" => "JSON",
        _ => "Other",
    }
}

// Read metadata through pinned directory handles, without following links or
// rereading every manifest's contents on each sidebar progress refresh.
fn manifest_size(storage: &XiteStorage, path: &str) -> Option<u64> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};
        use std::path::Component;
        let mut directory = rustix::fs::open(
            storage.root(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?;
        let mut parts: Vec<_> = std::path::Path::new(path).components().collect();
        let Component::Normal(name) = parts.pop()? else {
            return None;
        };
        for component in parts {
            let Component::Normal(part) = component else {
                return None;
            };
            directory = rustix::fs::openat(
                &directory,
                part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .ok()?;
        }
        std::fs::File::from(
            rustix::fs::openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .ok()?,
        )
    };
    #[cfg(windows)]
    let file =
        epix_fs::open_regular_file_beneath(storage.root(), std::path::Path::new(path)).ok()?;
    #[cfg(any(unix, windows))]
    {
        let metadata = file.metadata().ok()?;
        metadata.is_file().then_some(metadata.len())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (storage, path);
        None
    }
}

fn summarize_database(db: &Database, root: &std::path::Path, schema: Option<&DbSchema>) -> Value {
    let path = db.query("PRAGMA database_list", &[]).ok().and_then(|rows| {
        rows.into_iter()
            .find(|row| row["name"] == "main")
            .and_then(|row| row["file"].as_str().map(str::to_string))
    });
    let path = path.map(|path| {
        if path.is_empty() {
            return "In-memory database".to_string();
        }
        std::path::Path::new(&path)
            .strip_prefix(root)
            .ok()
            .map(|relative| relative.to_string_lossy().into_owned())
            .unwrap_or(path)
    });
    let number = |sql, key: &str| {
        db.query(sql, &[])
            .ok()
            .and_then(|rows| rows.first().and_then(|row| row[key].as_u64()))
    };
    let bytes = number("PRAGMA page_count", "page_count")
        .zip(number("PRAGMA page_size", "page_size"))
        .and_then(|(count, size)| count.checked_mul(size));
    json!({"path": path, "bytes": bytes, "feeds": schema.map(|schema| schema.feeds.len())})
}

fn disk_free_bytes(path: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        rustix::fs::statvfs(path)
            .ok()
            .map(|stat| stat.f_bavail.saturating_mul(stat.f_frsize))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut available = 0;
        // SAFETY: wide is terminated and available is writable for the call.
        (unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } != 0)
            .then_some(available)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn summary_reads_a_registered_xites_accepted_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage.write("index.html", b"<h1>Hello</h1>").unwrap();
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let data = storage.read("index.html").unwrap();
        let mut content = json!({"address": address, "modified": 1, "files": {
            "index.html": {"size": data.len(), "sha512": XiteStorage::hash_bytes(&data)}
        }});
        epix_content::sign(&mut content, &key).unwrap();
        storage
            .write("content.json", &serde_json::to_vec(&content).unwrap())
            .unwrap();
        let state = AppState::new("sidebar-test");
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage,
                    content: Some(content),
                },
            )
            .await;
        let details = state.sidebar_details(&address).await;
        assert_eq!(details["storage"]["files"], 1);
        assert!(details["storage"]["total"].as_u64().unwrap() > data.len() as u64);
        assert!(details["database"].is_null());
        assert!(
            details["identity_quota"].is_null(),
            "no invented generic quota"
        );
        #[cfg(any(unix, windows))]
        assert!(details["free_bytes"].as_u64().is_some());
        assert!(state.sidebar_details("missing").await.is_null());
    }

    #[test]
    fn storage_separates_delegated_site_files_from_user_data_and_optional_files() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let values = [
            (
                "content.json",
                json!({"includes": {"data/users/content.json": {}}, "files": {"index.html": {"size": 100}, "logo.SVG": {"size": 50}}, "files_optional": {"video.mp4": {"size": 9000}}}),
            ),
            (
                "data/users/content.json",
                json!({"files": {"index.js": {"size": 40}}, "user_contents": {}}),
            ),
            (
                "data/users/alice/content.json",
                json!({"files": {"profile.json": {"size": 70}}}),
            ),
        ];
        let mut units = Vec::new();
        for (path, content) in values {
            storage
                .write(path, &serde_json::to_vec(&content).unwrap())
                .unwrap();
            units.push(VerifiedManifestUnit {
                inner_path: path.into(),
                content,
            });
        }
        let summary = summarize_storage(&storage, &units).unwrap();
        let size = |name| {
            summary["types"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == name)
                .unwrap()["bytes"]
                .as_u64()
                .unwrap()
        };
        assert_eq!(size("HTML"), 100);
        assert_eq!(size("Images"), 50);
        assert_eq!(size("JavaScript"), 40);
        assert_eq!(
            size("User data"),
            70 + storage.read("data/users/alice/content.json").unwrap().len() as u64
        );
        assert_eq!(summary["files"], 4);
        assert!(
            summary["total"].as_u64().unwrap() < 9000,
            "optional bytes excluded"
        );
        std::fs::remove_file(dir.path().join("content.json")).unwrap();
        assert!(
            summarize_storage(&storage, &units).is_none(),
            "unavailable bytes never become fabricated zeros"
        );
    }

    #[test]
    fn database_reports_live_pages_and_declared_feeds() {
        let db = Database::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE item(value TEXT); INSERT INTO item VALUES ('example');")
            .unwrap();
        let mut schema = DbSchema::default();
        schema
            .feeds
            .insert("posts".into(), "SELECT * FROM item".into());
        let info = summarize_database(&db, std::path::Path::new("/unused"), Some(&schema));
        assert_eq!(info["path"], "In-memory database");
        assert_eq!(info["feeds"], 1);
        assert!(info["bytes"].as_u64().unwrap() >= 4096);
    }

    #[cfg(unix)]
    #[test]
    fn manifest_metadata_rejects_links_and_non_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        std::fs::write(outside.path().join("content.json"), b"private").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("content.json"),
            dir.path().join("content.json"),
        )
        .unwrap();
        assert_eq!(manifest_size(&storage, "linked/content.json"), None);
        assert_eq!(manifest_size(&storage, "content.json"), None);
        assert_eq!(manifest_size(&storage, "../content.json"), None);
        std::fs::create_dir(dir.path().join("directory")).unwrap();
        assert_eq!(manifest_size(&storage, "directory"), None);
    }
}
