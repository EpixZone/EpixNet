//! UTC timestamps shared by the persistent log and backup filenames.

/// (year, month, day) from days since the Unix epoch (Howard Hinnant's
/// civil_from_days).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A complete timestamp with an explicit UTC suffix, independent of the
/// machine's locale and timezone so logs from multiple nodes can be compared.
pub(crate) fn format_utc(seconds: i64) -> String {
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let tod = seconds.rem_euclid(86_400);
    let (hour, minute, second) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::format_utc;

    #[test]
    fn utc_timestamps_cover_epoch_leap_days_and_the_reported_log() {
        for (seconds, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (-1, "1969-12-31T23:59:59Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (4_107_542_400, "2100-03-01T00:00:00Z"),
            (1_793_903_799, "2026-11-05T18:36:39Z"),
        ] {
            assert_eq!(format_utc(seconds), expected);
        }
    }
}
