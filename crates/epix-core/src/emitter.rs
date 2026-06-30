//! The `Emitter` trait — the seam that keeps the runtime UI/platform-agnostic.
//!
//! Mirrors Ratspeak's design: core logic emits named events with a JSON payload;
//! each shell (Tauri, GeckoView/JNI, WKWebView/Swift, or a test harness) provides
//! its own `Emitter`. The engine never depends on any UI framework.

use serde_json::Value;
use std::sync::Mutex;

pub trait Emitter: Send + Sync {
    fn emit(&self, event: &str, payload: Value);
}

/// Drops every event. For headless and test use.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEmitter;

impl Emitter for NoopEmitter {
    fn emit(&self, _event: &str, _payload: Value) {}
}

/// Records every event for assertions in tests.
#[derive(Default)]
pub struct CollectingEmitter {
    events: Mutex<Vec<(String, Value)>>,
}

impl CollectingEmitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<(String, Value)> {
        self.events.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Emitter for CollectingEmitter {
    fn emit(&self, event: &str, payload: Value) {
        self.events.lock().unwrap().push((event.to_string(), payload));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn noop_emitter_is_object_safe_and_silent() {
        let e: &dyn Emitter = &NoopEmitter;
        e.emit("anything", json!({"x": 1}));
    }

    #[test]
    fn collecting_emitter_records_events() {
        let e = CollectingEmitter::new();
        assert!(e.is_empty());
        e.emit("siteChanged", json!({"address": "epix1abc"}));
        e.emit("peerFound", json!({"n": 3}));
        let events = e.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, "siteChanged");
        assert_eq!(events[1].1["n"], 3);
    }
}
