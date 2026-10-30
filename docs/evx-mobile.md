# EVX mobile boundary

Mobile EVX admission remains disabled. The Pulley runtime can now be built
without its compiler, but a usable iOS host still needs an accepted isolation
profile, capability broker, lifecycle integration and device validation.
The iOS and Android FFI products continue to exclude EVX dependencies.

## Implemented runtime boundary

`evx-runtime` enables the `compiler` feature by default for existing desktop
workers. A runtime-only consumer uses:

```sh
cargo check -p evx-runtime --lib --locked --no-default-features --features pulley
python3 scripts/test-evx-pulley-runtime.py
```

The normal/build dependency graph excludes Cranelift's code generator and
compiler integration, Winch, WAT and WAST. Wasmtime still uses the independent
`cranelift-bitset`, `cranelift-entity` and `cranelift-bforest` collection crates.
This build exposes no `precompile` API. The `text` feature explicitly requires
the compiler, so it cannot silently add text parsing to the runtime-only build.

The compatibility test runs two separate Cargo builds. The compiler creates
four fixed game fixtures in a private temporary directory. A compiler-free
consumer checks the exact artifacts, score output, fuel exhaustion, epoch
deadline, guest memory growth denial and the existing broker ABI. The driver
removes the directory afterward. This tests trusted local artifact portability
between the feature profiles, not a publisher artifact admission scheme.

The raw-artifact `run` API is now `unsafe`. The caller must establish that the
bytes are unchanged output from the trusted EVX compiler. Previously a safe
caller could supply arbitrary serialized bytes and its own matching hash,
which did not meet Wasmtime's deserialization contract. A compile-fail doctest
reproduced that API defect before the fix and now enforces the explicit safety
boundary. The desktop worker documents its private supervisor/compiler channel
at the call site.

[Wasmtime's deserialization contract](https://docs.wasmtime.dev/api/wasmtime/struct.Module.html#method.deserialize)
requires real compiler output. A hash or publisher signature authenticates
bytes but does not establish that they are valid serialized runtime code.
[Pulley](https://docs.wasmtime.dev/examples-pulley.html) is an interpreter for
Wasmtime's compiled bytecode. Selecting it removes the native-code execution
requirement, not the compilation step, unsafe artifact-loading contract or
need to confine native failures.

## Security profile decision

The current desktop model contains a native runtime or compiler compromise in
an independently confined process. A WebAssembly interpreter inside the mobile
node instead shares the app's memory, native capabilities and failure domain.
Valid guest code still receives only its explicitly registered imports, but a
native engine vulnerability or unbounded allocation can affect the whole app.
The app's own OS sandbox does not separate its wallet, node and xite data.
A background task expiration callback cannot safely kill a Rust thread.

There are two honest product choices:

| Profile | Execution and limits | Additional work |
| --- | --- | --- |
| Keep the current independent process boundary | Mobile EVX stays unavailable until a supported, separately confined execution mechanism meets the same containment and termination gates. | Prove platform process isolation, native accounting, lifecycle and broker integration. Desktop Pulley tests do not provide this. |
| Add a separately reviewed in-process mobile profile | Binary Wasm enters a validating interpreter with bounded modules, guest memory, stack, execution fuel and mediated host calls. Native failure may terminate or compromise the app. | Explicitly accept this different failure model, select and pin the interpreter, test resource amplification and cancellation, integrate durable admission and effects, and validate on devices before enabling it. |

The first choice now has a concrete iOS 26 candidate. It has not passed EVX's
acceptance gates. The in-process choice has not been approved and is not a
fallback when an extension fails to launch.

For the second choice, Wasmi is a concrete candidate to evaluate rather than
feeding downloaded Pulley artifacts to Wasmtime. Its
[configuration API](https://docs.rs/wasmi/latest/wasmi/struct.Config.html)
provides module limits, stack limits, fuel and lazy translation whose cost can
be charged to fuel. Start with binary Wasm only, EVX's exact proposal/ABI rules,
no WASI, no engine extensions, one active invocation, and the existing durable
consent and effect protocol. Parsing and allocation still need separate
resource-abuse analysis; a fuel counter is not a total native-memory limit.
Cancellation must be cooperative, and blocking native host calls must never
run on the interpreter thread. Engine fuel and floating-point behavior require
cross-engine conformance tests and an explicit profile identity.

Wasmi's [published audit history](https://wasmi-labs.github.io/blog/posts/wasmi-v1.0/)
is useful selection evidence, not an audit of the latest release or this host
integration. No Wasmi dependency or alternate production backend is enabled by
these changes.

A WebKit-managed page is not a completed substitute: it introduces a separate
bridge and scheduling model, and page cancellation is not proof of native
process termination. A publisher-signed Pulley artifact is also not a substitute
for validating untrusted Wasm. Neither approach is enabled as a fallback.

## iOS 26 separate-process candidate

Apple documents [Enhanced Security helper extensions](https://developer.apple.com/documentation/xcode/creating-enhanced-security-helper-extensions)
for isolating untrusted input on iOS and iPadOS. They use a restrictive sandbox
and communicate with the host using `XPCSession`. This is a viable mechanism
to investigate, not evidence that iOS EVX already works. It does not require
accepting an interpreter inside the node process.

The public [`AppExtensionProcess`](https://developer.apple.com/documentation/extensionfoundation/appextensionprocess)
API is available on iOS 26 and later. It launches an extension or connects to
an existing instance. Keep the extension bundle fixed and shipped with the app;
xite publishers supply Wasm data, never native extension code. Use a data-only
extension point with `EnhancedSecurity(true)` and the default
[bundle-only scope](https://developer.apple.com/documentation/extensionfoundation/appextensionpoint/scope).
Select the expected extension identity, not the first arbitrary discovered
extension. The older iOS 17 library build target remains useful, but cannot
establish availability of these iOS 26 host APIs.

Apple's [`invalidate()` contract](https://developer.apple.com/documentation/extensionfoundation/appextensionprocess/invalidate())
says that closing the last connection terminates the extension process. The
[host integration guide](https://developer.apple.com/documentation/extensionfoundation/adding-support-for-app-extensions-to-your-app)
also warns that other active connections keep it alive. Neither page specifies
a maximum termination latency or a synchronous death acknowledgement.
The [`onInterruption` callback](https://developer.apple.com/documentation/extensionfoundation/appextensionprocess/configuration/oninterruption)
is documented for unexpected exits. Treating connection invalidation as proof
of process death would therefore be an unsupported assumption. This is a
narrow lifecycle gap to resolve with an SDK/device fixture and a supported
OS-observed completion mechanism, not a reason to claim all separate-process
iOS execution is impossible.

The initial fixture must stay disconnected from the node's real data. Use a
fixed game-score message, bounded raw bytes and one connection. No app groups,
shared keychain, file bookmarks, network exceptions, wallet access or host
filesystem paths are necessary. Inspect the signed entitlements generated by
Xcode rather than copying macOS XPC entitlements. Test native denial directly;
the absence of Wasm imports does not demonstrate native process confinement.

| Acceptance case | Required observation before production integration |
| --- | --- |
| Identity and input boundary | Only the bundled extension and original host connect. Oversized, malformed, repeated and stale messages are rejected before work or allocation. Host policy supplies xite and invocation identity. |
| Native authority | Sacrificial native probes cannot read host secrets, another xite's files, shared keychain, arbitrary network or forbidden services. Record exact signed entitlements and OS build. |
| Fresh invocation | Run A plants memory and container markers; after confirmed termination, run B cannot obtain A's data. A reused process is never accepted as fresh. A persistent extension container must be absent, reset with OS-backed guarantees, or assigned permanently to one xite through a reviewed bounded design. |
| Forced stop | A native busy loop and blocked handler stop within the cleanup budget after the last connection closes. Observe actual death independently of extension replies. Extra connections, lost host connections and invalidation before launch completes cannot evade shutdown. Failure retains quarantine and blocks further admissions. |
| Native budgets | Run compiler expansion, allocation pressure and CPU-loop fixtures while observing the host's survival and responsiveness. Establish trustworthy accounting and distinguish hard limits from sampled detection on the device. Self-reported guest counters are insufficient. |
| Broker and effects | Raw artifact deserialization remains restricted to trusted compiler output. Keep compilation confined. Preserve the existing bounded broker ABI, provenance, durable admission, commit uncertainty and host-only reconciliation through crashes. |
| Background expiration | Expiration immediately revokes authority and stops new admissions. Do not mark a run safely stopped or release its workspace before death is confirmed. Restart preserves an admitted uncertain effect and never replays it automatically. |

Pulley still needs a compiler. The compiler may only process untrusted Wasm
inside an accepted isolated boundary with native resource controls. A Wasmi
evaluation inside this same extension would be a distinct engine/profile
decision, with conformance tests; it is not permission to move execution into
the node or to accept publisher-precompiled Pulley artifacts.

The smallest next gate is full Xcode with the iOS 26 SDK and a signed,
disposable extension fixture on a physical iOS 26 device. Simulator tests can
check framing and state transitions, but cannot close resource, entitlement
or background gates. First establish death, native authority and fresh-run
isolation, then integrate the broker. If the public mechanism cannot meet a
gate, keep the profile disabled and request a specific revised requirement;
do not silently weaken it. Older iOS versions remain unsupported for EVX.

## Platform validation

CI is configured to check `evx-runtime` as a compiler-free library for both
`aarch64-apple-ios` and `aarch64-apple-ios-sim` using the Apple SDKs, then verifies
that mobile products still omit EVX. Library checks do not link the app, execute
on a device, prove App Store acceptance or enable background jobs.

An enabled host must persist admission before execution and retain uncertain
effects across expiration, suspension, termination and restart. It must stop
admitting new work when its foreground/background execution allowance ends,
revoke broker authority immediately, and avoid claiming a clean stop while a
native call remains active. Apple's
[background scheduling availability](https://developer.apple.com/documentation/backgroundtasks/bgtaskscheduler/error/code/unavailable)
is platform-controlled, and the simulator does not establish background
processing behavior. A manual run uses the same authorization and lifecycle
path; it cannot bypass a failed platform gate.

[`BGProcessingTask`](https://developer.apple.com/documentation/backgroundtasks/bgprocessingtask)
provides an interruptible execution opportunity, not an exact 30-minute timer
or a worker isolation boundary. Whether iOS permits launching this extension
within that opportunity must be tested. Foreground manual execution remains
subject to the same extension and cleanup gates.

On the 2026-10-03 review host, the compiler-free native library, its real
artifact compatibility test and strict Clippy checks passed. The iOS library
check reached Wasmtime's C helper build and failed because `xcrun` could not
find the `iphoneos` SDK. This machine has Command Line Tools, not full Xcode.
Device and simulator checks are therefore pending on the configured CI runner;
no local SDK path was substituted and no iOS execution result is claimed.
The follow-up SDK inspection found macOS SDK 15.5 and no `iphoneos` or
`iphonesimulator` SDK. `xcodebuild -showsdks` refuses the active Command Line
Tools directory. The installed macOS headers predate the iOS 26 enhanced
extension API, so even that fixture's type check remains outstanding here.

## Standalone mobile fixtures

The 2026-10-04 follow-up adds two disconnected, fixed-game fixtures. Neither
changes mobile FFI features or admits a xite program.

`packaging/ios/evx-fixture` contains shared scalar protocol and one-shot state,
a host source, an Enhanced Security helper source, target `.xcconfig` files
and a required-SDK typecheck command. The host persists admission before launch,
selects the exact bundled helper, bounds game inputs, rejects a stale reply and
invalidates on foreground loss or timeout. The marker is never cleared based on
an XPC reply, invalidation or callback. There is no automatic reuse or fallback.

The portable Swift6 core passed 20 assertions, including concurrent one-shot
admission. Host and helper source syntax was parsed locally, but their API
typecheck is **not completed**. `check.py --require-sdk` fails because `iphoneos`
is absent. Packaging uses Apple's Generic Extension / Enhanced Security template
and generated entitlement metadata; the template and signed package have not
been produced on this machine. The [fixture instructions](../packaging/ios/evx-fixture/README.md)
separate source checking, packaging and device observations.

The new mobile-fixture workflow requires real iOS26 device and simulator SDK
checks. It does not silently skip them or replace Apple APIs with local mocks.
CI execution is pending. Public documentation still does not establish a
bounded synchronous death acknowledgement, a native CPU/memory accounting
interface or freshness of a reused extension container. These are platform
acceptance questions, separate from the missing local SDK.

The Android fixture is further along in API compilation: its five Java sources
compile with warnings as errors against the pinned official API36 jar, and
28 portable assertions pass. It uses a non-exported isolated service and a
fresh named binding, without native code or EVX runtime integration. Its APK
packaging and device execution remain untested. See [Android EVX isolation](evx-android.md)
for the Binder lifecycle distinction, provenance and exact integration gates.
