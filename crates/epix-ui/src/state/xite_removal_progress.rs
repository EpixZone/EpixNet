use super::{AppState, XiteRemovalFileProgress};
use serde_json::json;
use std::sync::Arc;

pub(super) enum XiteRemovalOutcome {
    Unknown,
    Complete,
    Pending,
}

/// One notification survives removal of the xite's registry entry. Commands
/// route it to their originating socket, including a dashboard or merger.
#[derive(Clone)]
pub(super) struct XiteRemovalProgress {
    state: Arc<AppState>,
    address: String,
    heading: String,
    origin: Option<u64>,
}

impl XiteRemovalProgress {
    pub(super) fn new(
        state: Arc<AppState>,
        address: &str,
        title: &str,
        origin: Option<u64>,
    ) -> Self {
        Self {
            state,
            address: address.to_string(),
            heading: format!("Deleting site {title}...\n"),
            origin,
        }
    }

    pub(super) fn report(&self, detail: &str, percent: i64) {
        self.state.push_event_routed(
            "progress",
            json!([
                format!("delete-{}", self.address),
                format!("{}{}", self.heading, detail),
                percent,
                true,
            ]),
            None,
            Some(self.address.clone()),
            None,
            self.origin,
        );
    }

    pub(super) fn files(&self, progress: XiteRemovalFileProgress) {
        match progress {
            XiteRemovalFileProgress::Counting { files } => {
                self.report(&format!("Collected {files} files"), 25);
            }
            XiteRemovalFileProgress::Deleting { deleted, total } => {
                // Leave room for directory syncs, shared-object handover and
                // metadata cleanup. Only a settled removal reaches 100%.
                let percent = 25 + deleted.saturating_mul(60) / total.max(1);
                self.report(
                    &format!("Deleting file {deleted}/{total}"),
                    percent.min(85) as i64,
                );
            }
        }
    }

    pub(super) fn finish(&self, outcome: &Result<XiteRemovalOutcome, String>) {
        match outcome {
            Ok(XiteRemovalOutcome::Complete) => {
                self.report("All files deleted successfully", 100);
            }
            Ok(XiteRemovalOutcome::Pending) => {
                self.report("Site deletion is pending and will retry.", -1);
            }
            Ok(XiteRemovalOutcome::Unknown) => {
                self.report(
                    &format!("Site deletion failed: Unknown xite: {}", self.address),
                    -1,
                );
            }
            Err(error) => self.report(&format!("Site deletion failed: {error}"), -1),
        }
    }
}
