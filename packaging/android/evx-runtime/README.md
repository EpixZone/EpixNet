# Android generic EVX runtime adapter

This is development integration code, not an enabled Android node backend.
`NativeBridge` belongs only to `RuntimeService` in an isolated process. Never
load `libevx_android` into the trusted node, browser or ordinary app process.
The standalone JVM test intentionally loads it in a disposable test process;
that is API/runtime verification, not an alternative production profile.

Run the portable and actual JNI checks from the repository root:

```sh
python3 packaging/android/evx-runtime/check.py --android-jar /path/to/android.jar
```

Use `--offline` when locked dependencies are already cached. The script selects
`target/evx-android-runtime` unless `CARGO_TARGET_DIR` is explicitly set. It runs
six real Wasm tests and five separate Java processes, checks one-shot JNI reuse
refusal, then typechecks all Java adapters against the supplied official API jar.

The included manifest is a library/test overlay only. No build merges it into
the shipping Android shell. The generic `IsolatedRuntime.startForConformance`
accepts raw module bytes and a host-owned limit snapshot, and requires a
`BoundBroker` supplied by trusted host code. Its callback must enforce signed
activation, consent, grant generation and capability-specific commit rules.
There is no guest-selected caller, host path or IPC endpoint.

## Continue native acceptance

The task-local tooling at `/tmp/evx-android-native-tools/` contains verified
NDK r28c, build-tools36, platform-tools37.0.1, stable ARM64 emulator37.2.12 and
AOSP API36 ARM64 system image. Five `*-provenance.json` files record official
URLs, exact bytes, SHA1 and SHA256. No native tool was executed and no AVD was
created. Those temporary files are optional local setup, not project inputs.
Recreate the same tooling from those official URLs if it is removed.

The next steps require a real Android build and emulator/device evidence:

1. Add Rust target `aarch64-linux-android` if absent. Point only this build's
   target linker and C compiler at the task-local NDK's
   `aarch64-linux-android34-clang`. Build `evx-android` as a separate library.
   Use the repository's 16 KiB ELF checker on the output. Do not alter the
   default compiler or SDK/JDK configuration.
2. Package the library in a disposable test APK with this manifest, the Java
   adapters and a trusted test activity. A user action must start the test.
   The test broker may use synthetic data only. Do not reuse product app data.
3. Create an AOSP ARM64 AVD under a task-private `ANDROID_AVD_HOME` and
   `ANDROID_USER_HOME`, with no accounts or network-dependent tests. Bind a new
   service instance, verify the kernel isolated UID, run real Wasm and inspect
   the bounded EVX capability/result exchange.
4. Verify no inherited parent files or Internet permission, process/UID death,
   descendant restrictions, crash/restart quarantine, host cancellation and
   independent aggregate CPU/RSS enforcement. The current Java deadline only
   unbinds. It does not establish hard termination of compromised native code.
5. Integrate the existing host activation/grant/provenance/commit journal only
   after that profile is accepted. Kernel accounting and confirmed lifecycle
   handling are required before any production admission switch exists.

API37 native services may later avoid ART overhead but are not required by this
adapter. API34 is required for public isolated-UID classification; older Android
versions must remain unavailable rather than selecting an in-process fallback.
See [Process API](https://developer.android.com/reference/android/os/Process)
and [isolated services](https://developer.android.com/guide/topics/manifest/service-element#isolated).
