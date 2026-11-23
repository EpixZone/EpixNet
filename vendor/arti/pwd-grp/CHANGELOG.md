# Release Documentation - changelog

## Changelog

### 1.0.2

#### Improved

 * Build fix: disable getresuid on `tvos`.

### 1.0.1

#### Improved

 * Dependencies on `thiserror` and `derive-deftly` relaxed upwards.

### 1.0.0

#### Breaking

 * Declare version to be 1.0.0.  No breaking API changes.
 * MSRV increased from 1.54 to 1.56 (2021 edition).

#### Fixed

 * Fixed build on NetBSD. ([#4], [!25])

#### Internal

 * Improved testing and updated CI image
 * Update formatting for new rustfmt

### 0.1.1

#### Fixed

 * Fixed build on MacOS and arm64.
 * Minor docs changes

#### Internal

 * Improve portability testing
 * No longer implement get\*id in terms of getres\*id

### 0.1.0

 * Initial release to crates.io.


[#4]: https://gitlab.torproject.org/tpo/core/rust-pwd-grp/-/issues/4
[!25]: https://gitlab.torproject.org/tpo/core/rust-pwd-grp/-/merge_requests/25
