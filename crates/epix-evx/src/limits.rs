//! Host policy for per-invocation limits.
//!
//! A declaration *requests* limits and the wrapper may *propose* them; what a
//! grant stores and a broker enforces is the host's own ceiling applied on
//! top. The ceiling is a constant of this crate rather than a configuration
//! value so that no command, page or stored row can raise it: the only way
//! to run a xite with more than [`HOST_CEILING`] allows is a new build of the
//! node. Within the ceiling the publisher's request is honoured as asked,
//! because a program tuned for a 2 MiB heap does not become safer by being
//! given 64 MiB it never touches.
//!
//! `evx_api::Limits::validate` bounds what any limits object may say at all
//! (it is what the declaration parser and the durable state apply); the
//! ceiling here is narrower and is the production policy the `evx-api`
//! comment leaves to the host.

use evx_api::Limits;

/// The most any effective limit may be on this host. Each field caps the
/// same field of a requested [`Limits`]; see [`clamp`].
///
/// The values are a desktop node's: a worker may hold 64 MiB of linear
/// memory, burn a billion fuel units, make 256 broker calls, keep 16 MiB in
/// its workspace, run for 30 wall seconds with 5 seconds per broker call,
/// and the worker and helper together may use 30 CPU seconds and 512 MiB
/// resident. `host_call_seconds` is below `wall_seconds` so the clamped
/// result always satisfies `Limits::validate`'s ordering rule.
pub const HOST_CEILING: Limits = Limits {
    memory_bytes: 64 * 1024 * 1024,
    fuel: 1_000_000_000,
    host_calls: 256,
    storage_bytes: 16 * 1024 * 1024,
    wall_seconds: 30.0,
    host_call_seconds: 5.0,
    process_cpu_seconds: 30.0,
    process_rss_bytes: 512 * 1024 * 1024,
};

/// The limits a grant stores for `requested`: every field is the smaller of
/// the request and [`HOST_CEILING`].
///
/// A request that does not pass `Limits::validate` is refused, not repaired:
/// a `wall_seconds` of zero or a NaN deadline is not a request for the
/// ceiling, it is a malformed request, and clamping it would turn garbage
/// into a grant. The result is validated again because the ceiling is host
/// policy that must itself be a legal limits object; a build whose ceiling
/// is not would refuse every grant rather than store one it cannot enforce.
pub fn clamp(requested: &Limits) -> Result<Limits, String> {
    requested
        .validate()
        .map_err(|denied| format!("requested limits refused: {denied}"))?;
    let clamped = Limits {
        memory_bytes: requested.memory_bytes.min(HOST_CEILING.memory_bytes),
        fuel: requested.fuel.min(HOST_CEILING.fuel),
        host_calls: requested.host_calls.min(HOST_CEILING.host_calls),
        storage_bytes: requested.storage_bytes.min(HOST_CEILING.storage_bytes),
        wall_seconds: requested.wall_seconds.min(HOST_CEILING.wall_seconds),
        host_call_seconds: requested
            .host_call_seconds
            .min(HOST_CEILING.host_call_seconds),
        process_cpu_seconds: requested
            .process_cpu_seconds
            .min(HOST_CEILING.process_cpu_seconds),
        process_rss_bytes: requested
            .process_rss_bytes
            .min(HOST_CEILING.process_rss_bytes),
    };
    clamped
        .validate()
        .map_err(|denied| format!("host limit ceiling is not a valid limits object: {denied}"))?;
    Ok(clamped)
}

/// The field-wise largest of several requests: what a whole xite asks for
/// when its programs ask for different things. One grant covers every
/// program of a xite, so its limits must let the most demanding declared
/// program run; a program is never given less than it declared just because
/// a sibling declared less. `None` when there is nothing to combine, since
/// a xite with no usable program has no request to honour.
pub fn combine<'a>(requests: impl IntoIterator<Item = &'a Limits>) -> Option<Limits> {
    let mut combined: Option<Limits> = None;
    for request in requests {
        combined = Some(match combined {
            None => request.clone(),
            Some(current) => Limits {
                memory_bytes: current.memory_bytes.max(request.memory_bytes),
                fuel: current.fuel.max(request.fuel),
                host_calls: current.host_calls.max(request.host_calls),
                storage_bytes: current.storage_bytes.max(request.storage_bytes),
                wall_seconds: current.wall_seconds.max(request.wall_seconds),
                host_call_seconds: current.host_call_seconds.max(request.host_call_seconds),
                process_cpu_seconds: current.process_cpu_seconds.max(request.process_cpu_seconds),
                process_rss_bytes: current.process_rss_bytes.max(request.process_rss_bytes),
            },
        });
    }
    combined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ceiling_is_itself_a_valid_limits_object() {
        HOST_CEILING.validate().unwrap();
        assert_eq!(clamp(&HOST_CEILING).unwrap(), HOST_CEILING);
    }

    #[test]
    fn a_request_within_the_ceiling_is_kept_as_asked() {
        let requested = Limits::default();
        assert_eq!(clamp(&requested).unwrap(), requested);
    }

    #[test]
    fn a_request_beyond_the_ceiling_is_cut_to_it_field_by_field() {
        let requested = Limits {
            memory_bytes: 256 * 1024 * 1024,
            fuel: 1_000_000_000_000,
            host_calls: 1024,
            storage_bytes: 1024 * 1024 * 1024,
            wall_seconds: 600.0,
            host_call_seconds: 60.0,
            process_cpu_seconds: 300.0,
            process_rss_bytes: 4 * 1024 * 1024 * 1024,
        };
        requested.validate().unwrap();
        assert_eq!(clamp(&requested).unwrap(), HOST_CEILING);
        // One field over, the rest untouched.
        let one = Limits { wall_seconds: 120.0, ..Limits::default() };
        let clamped = clamp(&one).unwrap();
        assert_eq!(clamped.wall_seconds, HOST_CEILING.wall_seconds);
        assert_eq!(clamped.memory_bytes, one.memory_bytes);
    }

    #[test]
    fn a_malformed_request_is_refused_rather_than_repaired() {
        assert!(clamp(&Limits { wall_seconds: 0.0, ..Limits::default() }).is_err());
        assert!(clamp(&Limits { wall_seconds: f64::NAN, ..Limits::default() }).is_err());
        let inverted = Limits { host_call_seconds: 1.5, wall_seconds: 1.0, ..Limits::default() };
        assert!(clamp(&inverted).is_err());
    }

    #[test]
    fn combining_requests_takes_the_largest_of_each_field() {
        let a = Limits { fuel: 5, wall_seconds: 3.0, ..Limits::default() };
        let b = Limits { fuel: 7, memory_bytes: 2 * 1024 * 1024, ..Limits::default() };
        let combined = combine([&a, &b]).unwrap();
        assert_eq!(combined.fuel, 7);
        assert_eq!(combined.wall_seconds, 3.0);
        assert_eq!(combined.memory_bytes, 2 * 1024 * 1024);
        assert!(combine(std::iter::empty::<&Limits>()).is_none());
    }
}
