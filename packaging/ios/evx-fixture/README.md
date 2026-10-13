# iOS 26 helper fixture scaffold

This is a standalone fixed-game experiment, disconnected from the browser,
Rust FFI, wallet and EVX runtime. It does not load Wasm or downloaded code. The
portable Swift core is locally tested. The iOS host/helper adapters are source
scaffolding: their SDK typecheck, generated extension metadata, signed package
and device execution have not run on the current machine.

Run the local core and required SDK checks separately:

```sh
python3 packaging/ios/evx-fixture/check.py
python3 packaging/ios/evx-fixture/check.py --require-sdk
```

The second command requires real iPhoneOS and iPhoneSimulator SDKs version 26
or later and a matching Swift compiler. Missing SDKs fail the command; they are
not replaced with stubs or silently skipped. It typechecks both targets but
does not generate extension metadata, package, sign or run the app.

## Package with Apple's supported template

1. In full Xcode 26 or later, create a disposable iOS app target with bundle ID
   `zone.epix.evxfixture`, deployment target 26, and the sources in `Host` and
   `Shared`. Apply `Host.xcconfig` to that target.
2. Add a Generic Extension target, choosing **Enhanced Security Extension**.
   Set its bundle ID to `zone.epix.evxfixture.helper`, include `Helper` and
   `Shared`, and apply `Helper.xcconfig`. Embed it in the fixture app using the
   template's normal embedding phase. Remove the extension's explicit
   `Info.plist`/`INFOPLIST_FILE` as Apple directs for generated bindings.
3. Keep Xcode's generated Enhanced Security entitlements and compiler/runtime
   protections. Do not copy macOS XPC entitlements. Add no app group, keychain
   group, filesystem bookmark, network exception or external extension scope.
4. Build the two targets and inspect the generated extension-point metadata,
   embedded helper identity and signed entitlements. Sign only this disposable
   fixture with a development identity, then test on an iOS 26 device.

The project-generation and entitlement template are deliberately supplied by
Xcode, whose current template is not installed here. The `.xcconfig` files are
not a replacement for that template or evidence of valid signed containment.
Apple's [helper-extension guide](https://developer.apple.com/documentation/xcode/creating-enhanced-security-helper-extensions)
describes this packaging contract.

## What the fixture establishes and leaves open

The host selects the single expected bundled extension identity. Both sides
exchange a versioned scalar game message with a nonce and bounded inputs. A
process accepts one connection and one successful request. A second request
or stale reply is refused. XPC's own decoding precedes these application checks;
no total native-allocation bound is claimed.

The host persists an exclusive admission marker before discovery or launch.
Timeout and leaving the foreground close the session and invalidate the process
reference. A launch that finishes after cancellation is invalidated before any
request is sent. Neither a reply nor invalidation clears the marker. The public
interruption callback is recorded separately, without claiming bounded cleanup
or resource accounting. The fixture cannot run again in the same app state;
there is no reset endpoint or hidden in-process fallback.

A fixed helper cannot prove containment of a compromised native engine.
The device gate still needs independent process-death observations, native
permission probes, process/container freshness, descendant behavior, trusted
resource accounting, background expiration and host-crash tests. See
[the mobile boundary](../../../docs/evx-mobile.md) for the complete gate list.
