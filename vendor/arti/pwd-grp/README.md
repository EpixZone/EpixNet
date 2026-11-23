# Safe interface to Unix `<pwd.h>` and `<grp.h>`

This crate presents a simple, safe, flexible wrapper around the
standard Unix functions used to read information about users and
groups.

## Example

```
let pwent = pwd_grp::getpwnam("root").unwrap().unwrap();
assert_eq!(pwent.uid, 0);
```

## Thread safety

This library is thread-safe.  It uses `getpwuid_r` and friends.

There is no interface for *iterating* over entries, unfortunately.
This is because `getpwent_r` and `getgrent_r`
are almost completely useless:
they still involve a global cursor into the database!

## Unicode and character set handling

The free functions in this library insist that the password
and group entries contain only valid UTF-8.
When this is not the case, they return an error.

For faithful handling of the *bytes*
found in the passwd and group databases,
on systems where those aren't always valid UTF-8,
use the methods on [`PwdGrp`] (via [`PwdGrpProvider`]).

## Cargo features

The following cargo features are available:

 * `full`: Metafeature.
   Enable all reasonable, non-experimental, features.
 * `serde`: implements `Serialize` and `Deserialize` for `Passwd` and `Group`
 * `minimal-1`: Minimal feature set.  Must be enabled.

The `test-with-lmock` feature is internal.
It only has any effect with `cfg(test)`,
i.e. during testing of this crate.
It requires Nightly Rust and is used for testing with miri.

## MSRV and MSRV policy

The Minimum Supported Rust Version for rust-pwd-grp is 1.56.

We expect to increase it cautiously.
(However, MSRV increase would be a minor version bump.)

## Alternatives to this library

You might also be considering:

 * [`nix::unistd::User`](https://docs.rs/nix/latest/nix/unistd/struct.User.html) etc:
   Part of the substantial and generally helpful `nix` library.
   `nix` makes some different decisions about data validity,
   and representation,
   and lacks `pwd-grp`s mocking facility.

 * [`sysinfo`](https://docs.rs/sysinfo/latest/sysinfo/):
   Much larger crate;
   strange API that requires manually pre-populating information.

 * [`users`](https://docs.rs/users/latest/users/):
   Doesn't give access to all passwd fields.
   No convenient UTF-8 API.
   (At the time of writing) unmaintained.
   However, it does have a built-in caching mechanism.

 * [`pwd`](https://docs.rs/pwd/latest/pwd/):
   Not threadsafe (uses `getpwnam`, not `getpwnam_r`).
   No way to access non-UTF-8 data.
   Suboptimal error handling.

 * [`libc::getpwuid_r`](https://docs.rs/libc/latest/libc/fn.getpwuid_r.html)
   etc:
   These low-level unsafe functions require you to manage buffers
   and allocation, and convert types to and from Rust structures.
   This can be tricky to do correctly and efficiently.
