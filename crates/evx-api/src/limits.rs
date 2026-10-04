//! Per-invocation resource limits.
//!
//! Values are host policy snapshots. The supervisor pairs every snapshot with a
//! `limits_generation` so a change made while a file helper is running cannot
//! be applied to a commit that was authorized under the older values.

use serde::{Deserialize, Serialize};

use crate::Denied;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum Wasm linear memory in bytes, enforced by the store limiter.
    pub memory_bytes: u64,
    /// Instruction fuel for one invocation.
    pub fuel: u64,
    /// Maximum broker calls per invocation.
    pub host_calls: u32,
    /// Workspace storage quota in bytes, including staging copies.
    pub storage_bytes: u64,
    /// Supervisor wall-clock deadline for the whole invocation, in seconds.
    pub wall_seconds: f64,
    /// Deadline for one native broker operation, in seconds.
    pub host_call_seconds: f64,
    /// Aggregate CPU seconds across worker and helper processes.
    pub process_cpu_seconds: f64,
    /// Aggregate resident-set bytes across live worker and helper processes.
    pub process_rss_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            memory_bytes: 1024 * 1024,
            fuel: 100_000,
            host_calls: 16,
            storage_bytes: 4096,
            wall_seconds: 2.0,
            host_call_seconds: 0.8,
            process_cpu_seconds: 2.0,
            process_rss_bytes: 128 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Reject values outside the supported envelope. Ranges are deliberately
    /// generous upper bounds for a desktop host; production policy narrows them.
    pub fn validate(&self) -> Result<(), Denied> {
        fn range_u64(name: &str, value: u64, low: u64, high: u64) -> Result<(), Denied> {
            if value < low || value > high {
                return Err(Denied::new(format!("invalid limit: {name}")));
            }
            Ok(())
        }
        fn range_f64(name: &str, value: f64, low: f64, high: f64) -> Result<(), Denied> {
            if !value.is_finite() || value < low || value > high {
                return Err(Denied::new(format!("invalid deadline: {name}")));
            }
            Ok(())
        }
        range_u64("memory_bytes", self.memory_bytes, 65_536, 256 * 1024 * 1024)?;
        range_u64("fuel", self.fuel, 1, 1_000_000_000_000)?;
        range_u64("host_calls", u64::from(self.host_calls), 1, 1024)?;
        range_u64("storage_bytes", self.storage_bytes, 0, 1024 * 1024 * 1024)?;
        range_u64(
            "process_rss_bytes",
            self.process_rss_bytes,
            16 * 1024 * 1024,
            4 * 1024 * 1024 * 1024,
        )?;
        range_f64("wall_seconds", self.wall_seconds, 0.1, 600.0)?;
        range_f64("host_call_seconds", self.host_call_seconds, 0.05, 60.0)?;
        range_f64("process_cpu_seconds", self.process_cpu_seconds, 0.05, 300.0)?;
        if self.host_call_seconds > self.wall_seconds {
            return Err(Denied::new(
                "invalid deadline: host_call_seconds exceeds wall_seconds",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_and_ranges_fail_closed() {
        Limits::default().validate().unwrap();
        let mut l = Limits::default();
        l.memory_bytes = 1;
        assert!(l.validate().is_err());
        let mut l = Limits::default();
        l.wall_seconds = f64::NAN;
        assert!(l.validate().is_err());
        let mut l = Limits::default();
        l.host_call_seconds = 5.0;
        l.wall_seconds = 1.0;
        assert!(l.validate().is_err());
    }
}
