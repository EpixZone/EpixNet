# Android EVX isolation fixture

Product EVX remains disabled on Android. The standalone fixture in
`packaging/android/evx-fixture` implements a fixed game calculation through an
Android isolated service. It loads no Wasm, native library, downloaded code,
wallet or xite data. It does not change the production Android application.

The service is bundled, non-exported and declares `isolatedProcess=true`, with
no app zygote, permissions or shared containers. The host uses an explicit
component and a fresh `bindIsolatedService` instance name. Android documents
that isolated services have no permissions of their own and communicate through
the service binding interface. This is a candidate native isolation boundary,
not evidence of all EVX guarantees.

The service checks the Binder caller against the installed application's UID,
transaction code, synchronous mode, exact 32-byte scalar frame and absence of
file descriptors before reading fields. The frame accepts only a versioned
nonce and bounded game inputs. One valid request consumes the service instance;
replays cannot run another calculation. The host bounds and validates the
24-byte response and nonce. Binder's own transaction decoding still precedes
these checks; these are application bounds, not a native-allocation proof.

The host writes and syncs an admission marker before binding. It never clears
that marker or reuses this fixture installation. A valid result does not release
process ownership. Disconnect, binding death, unbind and elapsed time are
separate from `IBinder.DeathRecipient`, whose documented meaning is that the
process hosting the Binder died. The deadline closes the host binding and
preserves uncertainty. A blocked transaction may retain the one worker thread
until Binder returns; thread interruption is not presented as termination.
Even a Binder death observation does not establish descendant-process cleanup,
resource accounting or safe native engine admission.

## Verified locally

On the 2026-10-04 review host, the dependency-free Java core passed 32 protocol
and lifecycle assertions. All five Android Java files compiled with warnings
as errors against Google's API 36 `android.jar` using JDK 11. This is an actual
API typecheck, not device execution or a Java stub mock.

```sh
python3 packaging/android/evx-fixture/check.py --android-jar /path/to/android.jar
python3 packaging/android/evx-fixture/build.py --sdk /path/to/sdk --build-tools 36.0.0 --output /tmp/evx-android-apk
```

The package command requires installed build tools and creates an unsigned APK
in a new output directory. It neither installs an SDK nor signs, installs or
publishes an app. That packaging path has not run on this host because build
tools and a device/emulator are absent. SDK provenance is recorded in
`packaging/android/evx-fixture/sdk-provenance.json`. The archive and extracted
jar were kept only in temporary task storage; global SDK/JDK settings were not
changed. No private app data or account was accessed.

## Gates before product integration

1. Build and sign the standalone fixture with Android build tools. On a
   disposable device or emulator, verify the actual isolated UID, one-shot
   Binder exchange, replay/malformed-input refusal, retained admission after
   host death and death-recipient ordering. Check the packaged manifest.
2. Test native denial of parent files, other xites, sockets, Binder services,
   process creation and inherited handles. Establish fresh-process and
   descendant cleanup rules. Java-only success is not native confinement proof.
3. Establish OS-trusted CPU/memory accounting, hard ceilings and bounded forced
   termination. Service self-reports are insufficient. Unbinding is not a
   synchronous kill API and cannot by itself authorize reuse.
4. Choose the isolated Wasm compiler/runtime profile and integrate the existing
   host broker, consent, durable invocation records, effect commit protocol,
   provenance and cancellation. Never deserialize publisher-supplied Pulley
   artifacts or move compilation/execution into the node on failure.
5. Verify permitted Android background opportunities and expiration on actual
   devices, including battery restrictions. A job scheduler is not an exact
   30-minute timer or an isolation boundary.

The public Android APIs support a concrete separately isolated candidate.
Native containment, budgets and lifecycle acceptance remain unproved here;
there is no production backend, automatic state reset or in-process fallback.

Sources: [service isolation](https://developer.android.com/guide/topics/manifest/service-element#isolated),
[Context service binding](https://developer.android.com/reference/android/content/Context),
[Binder death notification](https://developer.android.com/reference/android/os/IBinder.DeathRecipient),
[background work](https://developer.android.com/develop/background-work/background-tasks).

The synchronous transaction gate rejects `FLAG_ONEWAY` and permits native
transport flags. A regression reproduces and fixes the former exact-zero test,
which would reject normal Binder calls carrying `TF_ACCEPT_FDS`. This is checked
against the [AOSP Binder transport](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/libs/binder/IPCThreadState.cpp)
and covered by the portable suite; device acceptance remains pending.

## Generic Wasm adapter added after the fixed fixture

`evx-android` and `packaging/android/evx-runtime/` now contain a real binary-Wasm
runtime/JNI/Binder adapter. The service uses the existing validator and Pulley
compiler/executor. It accepts at most 64 KiB of raw Wasm and a bounded EVX limit
snapshot. It never accepts serialized engine artifacts, imports WASI, loads the
node's JNA library, or exposes direct files/network to Wasm. Compiler output stays
in the same isolated service until execution. Compilation remains susceptible to
native CPU/memory exhaustion and therefore requires independent OS enforcement.

The single host import keeps the existing EVX `Request` JSON and framed
`FromWorker::Result` format. JNI preserves byte bounds and turns callback
exceptions into fixed failures. JNI and the service each consume one invocation
per process. The trusted host adapter binds a fresh nonshared isolated service
and a private callback. Before compilation it captures the service UID from
Binder's kernel credentials. Calls must retain that UID and nonce, remain within
the host call count and pass current-consent checks. A production broker must
still decode/authorize requests independently and retain the existing atomic
revocation/commit rules. Service validation cannot substitute for host authority.

This adapter requires API34 for public `Process.isIsolatedUid`, while the existing
shell still has minSdk26. It is not added to the product manifest, node plugin or
scheduler. `startForConformance` is an explicit development entry point. It
persists an exclusive host-private admission record before binding and keeps that
record even after a result, unbind or Binder-owner death. There is no reset API.
Native descendant death, independent CPU/RSS limits, interrupted compilation,
workspace/provenance helpers and the host's consent/activation state integration
remain unfinished. The code cannot currently provide production Android EVX.

Verified on macOS: six real Pulley/Wasm tests, five actual JVM/JNI executions
(including an EVX capability callback, exhausted fuel, callback exception,
oversized callback reply, and process reuse refusal), strict Rust Clippy, and
Java API36 typechecking. These executions test the actual adapter/runtime but
are not Android OS containment evidence. The test command is:

```sh
python3 packaging/android/evx-runtime/check.py --offline --android-jar /tmp/evx-android-platform-36/android.jar
CARGO_TARGET_DIR=target/evx-android-runtime cargo clippy -p evx-android --all-targets --locked --offline -- -D warnings
```

Official NDK r28c, build-tools36, platform-tools37.0.1, stable ARM64 emulator37.2.12
and the AOSP API36 ARM64 image were downloaded into
`/tmp/evx-android-native-tools/`. Expected archive lengths and official SHA1 values
were verified; SHA256 and expanded sizes are recorded in the adjacent provenance
JSON files. Extracted tools occupy about 6.1 GiB. Archive copies were deleted.
No global SDK/JDK path was changed, no emulator or adb daemon was started, and no
Android native library or APK was built before work was frozen for the PR.
See `packaging/android/evx-runtime/README.md` for the next native steps.
