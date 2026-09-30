# rdrand Android ARM64 capability detection patch

Based on crates.io `rdrand` 0.9.0, upstream
<https://github.com/nagisa/rust_rdrand>, commit
`e5585f6313b1071b9595a0aed061c3aff0072d9e`.
The registry archive SHA-256 is
`84448986e59427c795b929d8dbe12d176275c7d0887ee48098c35b7206f51bae`.
The upstream ISC license, source, tests and commit provenance are retained.

On Android ARM64, upstream detects RNDR support by executing
`mrs ID_AA64ISAR0_EL1`. This register access requires kernel or native bridge
support. The Android emulator's ARM64 translation rejects it, terminating the
process during Arti's `CautiousRng::try_fill_bytes` call. The 0.5.20 APK contains
the rejected instruction at `libepix_ffi.so` address `0x6c7a71c`.

The patch changes only Android ARM64 feature detection:

- Query `getauxval(AT_HWCAP2)` and test `HWCAP2_RNG`, following the
  [kernel capability ABI](https://docs.kernel.org/arch/arm64/elf_hwcaps.html).
- Add Android ARM64 to the existing `libc` dependency's target condition.
- Return unsupported when the capability is absent, including when the
  auxiliary vector has no `AT_HWCAP2` entry.

The RNDR and RNDRRS implementations, public API, retry behavior and other
platforms are unchanged. Supported Android devices still contribute hardware
entropy. Arti's mandatory system RNG, thread RNG, backup RNG and entropy
combination are unchanged. The Android minimum API is 26, above the
[`getauxval` availability requirement](https://developer.android.com/ndk/guides/cpu-features).

The root workspace patch applies this copy to every consumer. Its unused
upstream `Cargo.lock` is omitted; the application's root lockfile continues to
resolve dependencies. Remove this patch after adopting an upstream release
with equivalent safe Android capability detection.

Validation uses the upstream RNG tests
(`cargo test --manifest-path vendor/rdrand/Cargo.toml`) and an Android ARM64
build. Discard the vendor lockfile created by this standalone test command.
Startup must also be exercised on an x86_64 Android
emulator running the ARM64 APK through its native bridge, because a host-only
test cannot reproduce the rejected register instruction.

The upstream and patched ARM64 unit test binaries were also run through
`/system/bin/ndk_translation_program_runner_arm64` on the API 37 x86_64
emulator with 16 KiB pages. The upstream `test::rdrand_works` terminates with
SIGILL (exit 132), logging the same rejected `0xd5380608` instruction as the
app. The patched binary passes all eight upstream tests; `RdRand::new`
returns `UnsupportedInstruction` on this emulator. Its generated Android
assembly calls `getauxval` and tests bit 16, without the feature-register probe.

The rebuilt ARM64 debug APK also passed all 17 packaged native-library checks
and ran for more than seven minutes on the same emulator without the original
native crash. The requested browser page rendered successfully. Wallet camera
testing is separate: this translated debug build subsequently hit a JavaScript
startup timeout in elliptic initialization, so native startup success alone
does not establish that the QR import flow works.
