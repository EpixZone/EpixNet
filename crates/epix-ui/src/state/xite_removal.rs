use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum XiteRemovalFileProgress {
    Counting { files: usize },
    Deleting { deleted: usize, total: usize },
}

struct Progress<'a> {
    callback: &'a mut (dyn FnMut(XiteRemovalFileProgress) + Send),
    total: usize,
    deleted: usize,
    since_report: usize,
    last_report: Instant,
}

impl Progress<'_> {
    fn report(&mut self, event: XiteRemovalFileProgress) {
        (self.callback)(event);
        self.since_report = 0;
        self.last_report = Instant::now();
    }

    fn update_due(&mut self) -> bool {
        self.since_report = self.since_report.saturating_add(1);
        let elapsed = self.last_report.elapsed();
        // Batch fast operations, but keep slow disks responsive even when
        // fewer than one hundred files finish in half a second.
        (self.since_report >= 100 && elapsed >= Duration::from_millis(100))
            || elapsed >= Duration::from_millis(500)
    }

    fn counted(&mut self) {
        self.total = self.total.saturating_add(1);
        if self.update_due() {
            self.report(XiteRemovalFileProgress::Counting { files: self.total });
        }
    }

    fn removed(&mut self) {
        self.deleted = self.deleted.saturating_add(1);
        // Counting is advisory. Files can appear during the walk, or an
        // unreadable directory can become accessible before removal.
        self.total = self.total.max(self.deleted);
        if self.update_due() {
            self.report(XiteRemovalFileProgress::Deleting {
                deleted: self.deleted,
                total: self.total,
            });
        }
    }
}

pub(super) fn remove_xite_directories_with_progress(
    roots: &[PathBuf],
    on_progress: &mut (dyn FnMut(XiteRemovalFileProgress) + Send),
) -> Vec<String> {
    let mut progress = Progress {
        callback: on_progress,
        total: 0,
        deleted: 0,
        since_report: 0,
        last_report: Instant::now(),
    };
    progress.report(XiteRemovalFileProgress::Counting { files: 0 });
    for root in roots {
        // Counting must never prevent the original durable removal attempt.
        // Only that attempt decides whether its intent needs to be retried.
        #[cfg(windows)]
        if let (Some(parent), Some(name)) = (root.parent(), root.file_name()) {
            if let Some(name) = name.to_str() {
                let quarantine = parent.join(format!(".{name}.epix-remove"));
                let _ = count_xite_directory(&quarantine, &mut || progress.counted());
            }
        }
        let _ = count_xite_directory(root, &mut || progress.counted());
    }
    progress.report(XiteRemovalFileProgress::Counting {
        files: progress.total,
    });
    progress.report(XiteRemovalFileProgress::Deleting {
        deleted: 0,
        total: progress.total,
    });
    let mut errors = Vec::new();
    for root in roots {
        if let Err(error) =
            super::remove_xite_directory_durable_with_progress(root, &mut || progress.removed())
        {
            errors.push(format!("{}: {error}", root.display()));
        }
    }
    progress.report(XiteRemovalFileProgress::Deleting {
        deleted: progress.deleted,
        total: progress.total,
    });
    errors
}

#[cfg(unix)]
fn count_xite_directory(path: &Path, on_file: &mut dyn FnMut()) -> Result<(), String> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let parent_path = path
        .parent()
        .ok_or_else(|| format!("xite root has no parent: {}", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| format!("xite root has no name: {}", path.display()))?;
    let parent = rustix::fs::open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("could not open {}: {error}", parent_path.display()))?;
    match rustix::fs::openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(root) => {
            let mut visited = 1usize;
            count_xite_directory_contents_at(&std::fs::File::from(root), &mut visited, on_file)
        }
        Err(open_error) => match rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) != FileType::Directory => {
                on_file();
                Ok(())
            }
            Ok(_) => Err(format!("could not open {}: {open_error}", path.display())),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(format!("could not inspect {}: {error}", path.display())),
        },
    }
}

#[cfg(unix)]
fn count_xite_directory_contents_at(
    directory: &std::fs::File,
    visited: &mut usize,
    on_file: &mut dyn FnMut(),
) -> Result<(), String> {
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

    const MAX_REMOVAL_ENTRIES: usize = 1_000_000;
    let entries = Dir::read_from(directory)
        .map_err(|error| format!("could not open removal directory: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("could not list removal directory: {error}"))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *visited = visited.saturating_add(1);
        if *visited > MAX_REMOVAL_ENTRIES {
            return Err(format!(
                "refusing to count more than {MAX_REMOVAL_ENTRIES} xite entries"
            ));
        }
        match rustix::fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(child) => {
                count_xite_directory_contents_at(&std::fs::File::from(child), visited, on_file)?;
            }
            Err(open_error) => {
                // Inspect only the endpoint. An inaccessible directory is
                // not a file and must not cause us to follow a replacement.
                match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(stat) if FileType::from_raw_mode(stat.st_mode) != FileType::Directory => {
                        on_file();
                    }
                    Ok(_) => return Err(format!("could not open removal directory: {open_error}")),
                    Err(error) if error == rustix::io::Errno::NOENT => {}
                    Err(error) => return Err(format!("could not inspect removal entry: {error}")),
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn count_xite_directory(path: &Path, on_file: &mut dyn FnMut()) -> Result<(), String> {
    const MAX_REMOVAL_ENTRIES: usize = 1_000_000;

    enum Frame {
        Entry(PathBuf),
        Children(PathBuf, std::fs::ReadDir),
    }
    let mut stack = vec![Frame::Entry(path.to_path_buf())];
    let mut visited = 0usize;
    while let Some(frame) = stack.pop() {
        let current = match frame {
            Frame::Entry(path) => path,
            Frame::Children(path, mut entries) => match entries.next() {
                Some(entry) => {
                    let entry = entry
                        .map_err(|error| format!("could not list {}: {error}", path.display()))?;
                    stack.push(Frame::Children(path, entries));
                    entry.path()
                }
                None => continue,
            },
        };
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("could not inspect {}: {error}", current.display())),
        };
        visited = visited.saturating_add(1);
        if visited > MAX_REMOVAL_ENTRIES {
            return Err(format!(
                "refusing to count more than {MAX_REMOVAL_ENTRIES} entries below {}",
                path.display()
            ));
        }
        if super::db_path_component_is_link(&metadata) || !metadata.is_dir() {
            on_file();
        } else {
            let entries = std::fs::read_dir(&current)
                .map_err(|error| format!("could not list {}: {error}", current.display()))?;
            stack.push(Frame::Children(current, entries));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xite_removal_progress_counts_actual_files_across_roots() {
        let temp = tempfile::tempdir().unwrap();
        let roots = [temp.path().join("first"), temp.path().join("second")];
        std::fs::create_dir_all(roots[0].join("data/empty")).unwrap();
        std::fs::create_dir_all(roots[1].join("optional")).unwrap();
        for path in [
            roots[0].join("content.json"),
            roots[0].join("data/untracked.txt"),
            roots[1].join("optional/video.mp4"),
            roots[1].join("local.db"),
        ] {
            std::fs::write(path, b"file").unwrap();
        }
        let mut events = Vec::new();
        let errors = remove_xite_directories_with_progress(&roots, &mut |event| events.push(event));
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(events[0], XiteRemovalFileProgress::Counting { files: 0 });
        assert!(events.contains(&XiteRemovalFileProgress::Counting { files: 4 }));
        assert!(events.contains(&XiteRemovalFileProgress::Deleting {
            deleted: 0,
            total: 4,
        }));
        assert_eq!(
            events.last(),
            Some(&XiteRemovalFileProgress::Deleting {
                deleted: 4,
                total: 4,
            })
        );
        assert!(roots.iter().all(|root| !root.exists()));
    }

    #[test]
    fn xite_removal_progress_handles_empty_and_missing_roots() {
        let temp = tempfile::tempdir().unwrap();
        let roots = [temp.path().join("empty"), temp.path().join("missing")];
        std::fs::create_dir(&roots[0]).unwrap();
        let mut events = Vec::new();
        let errors = remove_xite_directories_with_progress(&roots, &mut |event| events.push(event));
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            events.last(),
            Some(&XiteRemovalFileProgress::Deleting {
                deleted: 0,
                total: 0,
            })
        );
        assert!(roots.iter().all(|root| !root.exists()));
    }

    #[test]
    fn xite_removal_progress_retries_after_counting_failure() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("missing-parent/root");
        let mut events = Vec::new();
        let errors = remove_xite_directories_with_progress(&[root.clone()], &mut |event| {
            if event
                == (XiteRemovalFileProgress::Deleting {
                    deleted: 0,
                    total: 0,
                })
            {
                // The parent was missing during counting. The durable
                // attempt must still run if the filesystem becomes usable.
                std::fs::create_dir_all(&root).unwrap();
                std::fs::write(root.join("late.txt"), b"late file").unwrap();
            }
            events.push(event);
        });
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            events.last(),
            Some(&XiteRemovalFileProgress::Deleting {
                deleted: 1,
                total: 1
            })
        );
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn xite_removal_progress_attempts_other_roots_after_failure() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("file.txt"), b"file").unwrap();
        let mut events = Vec::new();
        let errors = remove_xite_directories_with_progress(
            &[temp.path().join("missing-parent/root"), root.clone()],
            &mut |event| events.push(event),
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(
            events.last(),
            Some(&XiteRemovalFileProgress::Deleting {
                deleted: 1,
                total: 1
            })
        );
        assert!(!root.exists());
    }

    #[test]
    fn xite_removal_progress_limits_update_frequency() {
        let mut events = Vec::new();
        let mut callback = |event| events.push(event);
        let mut progress = Progress {
            callback: &mut callback,
            total: 0,
            deleted: 0,
            since_report: 0,
            last_report: Instant::now(),
        };
        for _ in 0..10_000 {
            progress.counted();
        }
        // The check does not sleep, so force elapsed time for a
        // deterministic slow-disk update after a small batch.
        progress.since_report = 0;
        progress.last_report = Instant::now() - Duration::from_secs(1);
        progress.removed();
        drop(progress);
        assert!(events.len() < 100);
        assert_eq!(
            events.last(),
            Some(&XiteRemovalFileProgress::Deleting {
                deleted: 1,
                total: 10_000,
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn xite_removal_progress_counts_symlinks_without_following_them() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        let root = temp.path().join("root");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), b"untouched").unwrap();
        std::fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("linked-directory")).unwrap();
        std::os::unix::fs::symlink(outside.join("keep.txt"), root.join("linked-file")).unwrap();
        std::os::unix::fs::symlink(outside.join("missing"), root.join("dangling")).unwrap();
        let linked_root = temp.path().join("linked-root");
        std::os::unix::fs::symlink(&outside, &linked_root).unwrap();
        let mut events = Vec::new();
        let errors = remove_xite_directories_with_progress(
            &[root.clone(), linked_root.clone()],
            &mut |event| events.push(event),
        );
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            events.last(),
            Some(&XiteRemovalFileProgress::Deleting {
                deleted: 4,
                total: 4,
            })
        );
        assert!(!root.exists());
        assert!(std::fs::symlink_metadata(linked_root).is_err());
        assert_eq!(
            std::fs::read(outside.join("keep.txt")).unwrap(),
            b"untouched"
        );
    }

    #[cfg(windows)]
    #[test]
    fn xite_removal_progress_counts_pending_quarantine() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let quarantine = temp.path().join(".root.epix-remove");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&quarantine).unwrap();
        std::fs::write(root.join("new.txt"), b"new").unwrap();
        std::fs::write(quarantine.join("pending.txt"), b"old").unwrap();
        let mut events = Vec::new();
        let errors = remove_xite_directories_with_progress(&[root.clone()], &mut |event| {
            events.push(event);
        });
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            events.last(),
            Some(&XiteRemovalFileProgress::Deleting {
                deleted: 2,
                total: 2,
            })
        );
        assert!(!root.exists());
        assert!(!quarantine.exists());
    }
}
