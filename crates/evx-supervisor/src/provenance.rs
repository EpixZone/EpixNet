//! Host-owned read provenance. Namespace/link-count checks cannot establish
//! origin when another process can replace entries concurrently.
//!
//! This metadata lives outside the helper's workspace and is never enrolled
//! from file contents. Only an authorized write request supplies a digest.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use evx_api::{Denied, Request, Response, MAX_ENTRIES, MAX_FILE};
use evx_workspace::sys::{file_privacy, path_bytes};
use evx_workspace::{Dir, Kind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DIRECTORY: &str = ".evx-provenance";
const MAX_REGISTRY: usize = 128 * 1024;
static STAGING_ID: AtomicU64 = AtomicU64::new(1);

fn denied() -> Denied {
    Denied::new("workspace provenance unavailable")
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    committed: Option<String>,
    pending: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    xite: String,
    root_path: String,
    root_device: u64,
    root_inode: u64,
    entries: BTreeMap<String, Entry>,
}

pub(crate) struct Provenance {
    directory: Dir,
    name: String,
    xite: String,
    root_path: String,
    root_device: u64,
    root_inode: u64,
}

impl Provenance {
    pub(crate) fn new(workspace: &Path, root: &Dir, xite: &str) -> Result<Self, Denied> {
        evx_api::validate_identifier(xite)?;
        let parent = workspace.parent().ok_or_else(denied)?;
        // Never grant a workspace whose own root contains its authority store.
        if parent.join(DIRECTORY).starts_with(workspace) {
            return Err(denied());
        }
        let parent = Dir::open_root(parent)?;
        if parent
            .create_private_dir(DIRECTORY)
            .map_err(|_| denied())?
        {
            parent.sync().map_err(|_| denied())?;
        }
        let directory = parent.open_dir(DIRECTORY).map_err(|_| denied())?;
        let privacy = directory.privacy().map_err(|_| denied())?;
        if !privacy.owned || privacy.shared {
            return Err(denied());
        }
        let root_identity = root.identity().map_err(|_| denied())?;
        let root_path = digest(&path_bytes(workspace).map_err(|_| denied())?);
        Ok(Self {
            directory,
            name: format!("{root_path}.json"),
            xite: xite.into(),
            root_path,
            root_device: root_identity.0[0],
            root_inode: root_identity.0[1],
        })
    }

    fn load(&self) -> Result<Record, Denied> {
        let (mut file, stat) = match self.directory.open_read(&self.name) {
            Ok(Some(opened)) => opened,
            Ok(None) => {
                return Ok(Record {
                    version: 1,
                    xite: self.xite.clone(),
                    root_path: self.root_path.clone(),
                    root_device: self.root_device,
                    root_inode: self.root_inode,
                    entries: BTreeMap::new(),
                })
            }
            Err(_) => return Err(denied()),
        };
        let privacy = file_privacy(&file).map_err(|_| denied())?;
        if stat.kind != Kind::Regular
            || stat.links != 1
            || stat.size > MAX_REGISTRY as u64
            || !privacy.owned
            || privacy.shared
        {
            return Err(denied());
        }
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(MAX_REGISTRY as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| denied())?;
        if bytes.len() > MAX_REGISTRY {
            return Err(denied());
        }
        let record: Record = evx_api::strict::parse_typed(&bytes).map_err(|_| denied())?;
        if record.version != 1
            || record.xite != self.xite
            || record.root_path != self.root_path
            || record.root_device != self.root_device
            || record.root_inode != self.root_inode
            || record.entries.len() > MAX_ENTRIES
        {
            return Err(denied());
        }
        for (path, entry) in &record.entries {
            evx_api::validate_relative_path(path).map_err(|_| denied())?;
            if entry.committed.is_none() && entry.pending.is_none()
                || entry
                    .committed
                    .iter()
                    .chain(entry.pending.iter())
                    .any(|value| !valid_digest(value))
            {
                return Err(denied());
            }
        }
        Ok(record)
    }

    fn persist(&self, record: &Record) -> Result<(), Denied> {
        let data = serde_json::to_vec(record).map_err(|_| denied())?;
        if data.len() > MAX_REGISTRY || record.entries.len() > MAX_ENTRIES {
            return Err(denied());
        }
        let name = format!(
            ".pending-{}-{}",
            std::process::id(),
            STAGING_ID.fetch_add(1, Ordering::Relaxed)
        );
        let mut file = self.directory.create_new(&name).map_err(|_| denied())?;
        let result = (|| {
            file.write_all(&data).map_err(|_| denied())?;
            file.sync_all().map_err(|_| denied())?;
            drop(file);
            self.directory
                .rename(&name, &self.name)
                .map_err(|_| denied())?;
            self.directory.sync().map_err(|_| denied())
        })();
        let _ = self.directory.unlink(&name);
        result
    }

    /// Must run with the workspace lease before a helper receives Commit.
    pub(crate) fn prepare(&self, path: &str, text: &str) -> Result<(), Denied> {
        evx_api::validate_relative_path(path)?;
        if text.len() > MAX_FILE {
            return Err(denied());
        }
        let mut record = self.load()?;
        let next = digest(text.as_bytes());
        let entry = record.entries.entry(path.into()).or_insert(Entry {
            committed: None,
            pending: None,
        });
        if entry.pending.as_ref().is_some_and(|value| value != &next) {
            return Err(Denied::new("workspace write needs reconciliation"));
        }
        entry.pending = Some(next);
        self.persist(&record)
    }

    /// Only a clean write-helper completion collapses an uncertain pair.
    pub(crate) fn complete(&self, path: &str, text: &str) -> Result<(), Denied> {
        let mut record = self.load()?;
        let next = digest(text.as_bytes());
        let entry = record.entries.get_mut(path).ok_or_else(denied)?;
        if entry.pending.as_ref() != Some(&next) {
            return Err(denied());
        }
        entry.committed = entry.pending.take();
        self.persist(&record)
    }

    pub(crate) fn pending_paths(&self) -> Result<Vec<String>, Denied> {
        Ok(self
            .load()?
            .entries
            .into_iter()
            .filter_map(|(path, entry)| entry.pending.map(|_| path))
            .collect())
    }

    pub(crate) fn reconcile(&self, path: &str, response: Response) -> Result<(), Denied> {
        if matches!(&response, Response::Error { ok: false, error } if error == "workspace file absent")
        {
            // An explicit host action may accept observed absence. This does
            // not enroll any bytes and permits a new first write after a
            // helper died between authorization and its initial rename.
            let mut record = self.load()?;
            if record
                .entries
                .get(path)
                .is_none_or(|entry| entry.pending.is_none())
            {
                return Err(denied());
            }
            record.entries.remove(path);
            return self.persist(&record);
        }
        let request = Request::WorkspaceRead { path: path.into() };
        let Response::Read { data_b64, .. } = self.validate_response(&request, response, false)?
        else {
            return Err(Denied::new(
                "workspace reconciliation requires an authorized file version",
            ));
        };
        let bytes = B64.decode(data_b64).map_err(|_| denied())?;
        let mut record = self.load()?;
        let entry = record.entries.get_mut(path).ok_or_else(denied)?;
        entry.committed = Some(digest(&bytes));
        entry.pending = None;
        self.persist(&record)
    }

    /// Replace every invalid or unregistered read with a fixed denial before
    /// it reaches the guest or the host's returned response diagnostics.
    pub(crate) fn validate_response(
        &self,
        request: &Request,
        response: Response,
        commit_sent: bool,
    ) -> Result<Response, Denied> {
        match (request, response) {
            (_, response @ Response::Error { ok: false, .. }) => Ok(response),
            (
                Request::WorkspaceRead { path },
                Response::Read {
                    ok: true,
                    data_b64,
                    bytes,
                },
            ) => {
                let checked = (|| {
                    if bytes > MAX_FILE || data_b64.len() > MAX_FILE.div_ceil(3) * 4 {
                        return Err(denied());
                    }
                    let data = B64.decode(&data_b64).map_err(|_| denied())?;
                    if data.len() != bytes || B64.encode(&data) != data_b64 {
                        return Err(denied());
                    }
                    let record = self.load()?;
                    let entry = record.entries.get(path).ok_or_else(denied)?;
                    let actual = digest(&data);
                    if entry.committed.as_ref() != Some(&actual)
                        && entry.pending.as_ref() != Some(&actual)
                    {
                        return Err(denied());
                    }
                    Ok(Response::Read {
                        ok: true,
                        data_b64,
                        bytes,
                    })
                })();
                Ok(checked.unwrap_or_else(|_| Response::error("workspace read provenance denied")))
            }
            (
                Request::WorkspaceWrite { text, .. },
                response @ Response::Write { ok: true, bytes },
            ) if commit_sent && bytes == text.len() => Ok(response),
            _ => Err(Denied::new("file helper response does not match request")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Provenance) {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("game");
        std::fs::create_dir(&workspace).unwrap();
        let workspace = std::fs::canonicalize(workspace).unwrap();
        let root = evx_workspace::open_root(&workspace).unwrap();
        let authority = Provenance::new(&workspace, &root, "game").unwrap();
        (dir, authority)
    }

    fn response(bytes: &[u8]) -> Response {
        Response::Read {
            ok: true,
            data_b64: B64.encode(bytes),
            bytes: bytes.len(),
        }
    }

    #[test]
    fn exact_path_and_content_with_bounded_read_shape() {
        let (_dir, authority) = fixture();
        authority.prepare("score", "42").unwrap();
        authority.complete("score", "42").unwrap();
        let request = Request::WorkspaceRead {
            path: "score".into(),
        };
        assert!(authority
            .validate_response(&request, response(b"42"), false)
            .unwrap()
            .is_ok());
        for bad in [
            response(b"outside"),
            Response::Read {
                ok: true,
                data_b64: "NDI=".into(),
                bytes: 1,
            },
            Response::Read {
                ok: true,
                data_b64: "NDI".into(),
                bytes: 2,
            },
            Response::Read {
                ok: true,
                data_b64: "!".into(),
                bytes: 2,
            },
            response(&vec![0; MAX_FILE + 1]),
        ] {
            assert!(!authority
                .validate_response(&request, bad, false)
                .unwrap()
                .is_ok());
        }
        for bad in [
            Response::Read {
                ok: false,
                data_b64: "NDI=".into(),
                bytes: 2,
            },
            Response::Write { ok: true, bytes: 2 },
            Response::Score {
                ok: true,
                score: 42,
            },
            Response::Error {
                ok: true,
                error: "pretend".into(),
            },
        ] {
            assert!(authority.validate_response(&request, bad, false).is_err());
        }
        let other = Request::WorkspaceRead {
            path: "other".into(),
        };
        assert!(!authority
            .validate_response(&other, response(b"42"), false)
            .unwrap()
            .is_ok());
    }

    #[test]
    fn uncertainty_retains_only_authorized_versions_until_reconciled() {
        let (_dir, authority) = fixture();
        authority.prepare("score", "old").unwrap();
        authority.complete("score", "old").unwrap();
        authority.prepare("score", "new").unwrap();
        assert!(authority.prepare("score", "third").is_err());
        let request = Request::WorkspaceRead {
            path: "score".into(),
        };
        for accepted in [b"old", b"new"] {
            assert!(authority
                .validate_response(&request, response(accepted), false)
                .unwrap()
                .is_ok());
        }
        assert!(authority.reconcile("score", response(b"unknown")).is_err());
        assert_eq!(authority.pending_paths().unwrap(), ["score"]);
        authority.reconcile("score", response(b"old")).unwrap();
        assert!(authority.pending_paths().unwrap().is_empty());
        assert!(!authority
            .validate_response(&request, response(b"new"), false)
            .unwrap()
            .is_ok());
        authority.prepare("score", "third").unwrap();
    }

    #[test]
    fn registry_binds_xite_and_root_identity() {
        let (dir, authority) = fixture();
        authority.prepare("score", "42").unwrap();
        let workspace = std::fs::canonicalize(dir.path().join("game")).unwrap();
        let root = evx_workspace::open_root(&workspace).unwrap();
        let other = Provenance::new(&workspace, &root, "other").unwrap();
        assert!(other.pending_paths().is_err());
        drop(root);
        std::fs::rename(&workspace, dir.path().join("old-game")).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        let root = evx_workspace::open_root(&workspace).unwrap();
        let replacement = Provenance::new(&workspace, &root, "game").unwrap();
        assert!(replacement.pending_paths().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn registry_rejects_a_linked_authority_directory() {
        use std::os::unix::fs::symlink;
        let (dir, authority) = fixture();
        authority.prepare("score", "42").unwrap();
        let workspace = std::fs::canonicalize(dir.path().join("game")).unwrap();
        let root = evx_workspace::open_root(&workspace).unwrap();
        drop(authority);
        std::fs::rename(
            dir.path().join(DIRECTORY),
            dir.path().join("saved-authority"),
        )
        .unwrap();
        symlink(
            dir.path().join("saved-authority"),
            dir.path().join(DIRECTORY),
        )
        .unwrap();
        assert!(Provenance::new(&workspace, &root, "game").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn registry_rejects_a_junctioned_authority_directory() {
        let (dir, authority) = fixture();
        authority.prepare("score", "42").unwrap();
        let workspace = std::fs::canonicalize(dir.path().join("game")).unwrap();
        let root = evx_workspace::open_root(&workspace).unwrap();
        drop(authority);
        std::fs::rename(
            dir.path().join(DIRECTORY),
            dir.path().join("saved-authority"),
        )
        .unwrap();
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(dir.path().join(DIRECTORY))
            .arg(dir.path().join("saved-authority"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(Provenance::new(&workspace, &root, "game").is_err());
    }

    #[test]
    fn registry_and_version_sets_are_bounded() {
        let (_dir, authority) = fixture();
        for i in 0..MAX_ENTRIES {
            authority.prepare(&format!("score-{i}"), "42").unwrap();
        }
        assert!(authority.prepare("too-many", "42").is_err());
        assert_eq!(authority.pending_paths().unwrap().len(), MAX_ENTRIES);
        assert!(authority.prepare("score-0", "different").is_err());
    }
}
