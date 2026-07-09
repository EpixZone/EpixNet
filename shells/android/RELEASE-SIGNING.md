# Signing the Android release APK

The Epix Android app can be distributed as a signed APK for direct download,
without the Play Store. Android does not need a central authority to sign an
app: you generate your own key, sign with it, and users sideload the result.
The one rule that matters forever: **every future update must be signed with
the same key**, so guard the keystore like a production secret and back it up.
Lose it and users can only upgrade by uninstalling and reinstalling, which for
a wallet means wiping their keys.

Debug builds (`assembleDebug`) are unaffected by any of this and keep using the
throwaway debug key.

## 1. Generate the keystore (once)

Run this yourself so the password is never stored or seen by anyone else. Keep
the keystore file **outside the repo**. `keytool` prompts for the password
interactively (it is not passed on the command line):

```sh
mkdir -p ~/.epix
keytool -genkeypair -v \
  -keystore ~/.epix/epix-release.jks \
  -alias epix-release \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=Epix, O=EpixZone, C=US"
```

- `-validity 10000` (~27 years) outlives the app; Play requires a key valid
  well past 2033.
- The default keystore type is PKCS12, where the key password equals the store
  password. When prompted "Enter key password (RETURN if same as keystore
  password)", press RETURN.
- Back up `~/.epix/epix-release.jks` and the password somewhere safe and
  offline. This file is the app's identity.

## 2. Point the build at it (once)

```sh
cp keystore.properties.example keystore.properties
# edit keystore.properties: set storeFile to the absolute path and fill in the
# password you chose. keystore.properties is gitignored.
```

CI alternative: instead of the file, set `EPIX_KEYSTORE_FILE`,
`EPIX_KEYSTORE_PASSWORD`, `EPIX_KEY_ALIAS`, `EPIX_KEY_PASSWORD` in the
environment. If neither the file nor the env vars are present, `assembleRelease`
still runs but the APK is left unsigned.

## 3. Build the signed APK

The release build needs the same prerequisites as debug (the prebuilt Rust core
in `app/src/main/jniLibs/` and the staged wallet extension). Then:

```sh
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" \
  ./gradlew assembleRelease
```

Output: `app/build/outputs/apk/release/app-release.apk`.

Confirm it is signed with the right key:

```sh
"$ANDROID_HOME"/build-tools/*/apksigner verify --print-certs \
  app/build/outputs/apk/release/app-release.apk
```

## 4. Publish the fingerprint

So people can verify a direct download is genuinely yours, publish the key's
SHA-256 certificate fingerprint (on the site and the GitHub release):

```sh
keytool -list -v -keystore ~/.epix/epix-release.jks -alias epix-release \
  | grep -A1 "SHA256:"
```

Anyone can then run the `apksigner verify --print-certs` command above on their
download and match the fingerprint before installing.

## Automated builds (GitHub Actions)

Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds the signed
APK (alongside the macOS/Linux/Windows artifacts) and attaches it to the GitHub
Release as `epix-android-<version>.apk`. The Android job cross-compiles the Rust
core with `cargo ndk`, generates the Kotlin bindings, then runs
`assembleRelease` with the signing key supplied through the `EPIX_KEYSTORE_*`
env vars (the same ones `build.gradle.kts` reads locally).

You only need the **two required** secrets below (Settings -> Secrets and
variables -> Actions). Because your keystore is PKCS12 with the standard
`epix-release` alias, the workflow defaults the alias and reuses the keystore
password as the key password, so the last two are optional overrides you can
skip. Without `ANDROID_KEYSTORE_BASE64` the job still runs but produces an
unsigned, non-installable APK, so you can dry-run the pipeline first via the
Actions tab ("Release" -> Run workflow).

| Secret | Required? | Value |
|---|---|---|
| `ANDROID_KEYSTORE_BASE64` | required | `base64 -i ~/.epix/epix-release.jks \| pbcopy`, then paste |
| `ANDROID_KEYSTORE_PASSWORD` | required | the keystore password |
| `ANDROID_KEY_ALIAS` | optional | only to override the default `epix-release` |
| `ANDROID_KEY_PASSWORD` | optional | only if your key password differs from the keystore password (it doesn't for PKCS12) |

The base64 secret is your signing key; treat the GitHub secret store as holding
the master key and keep your own offline backup regardless.

## Play Store and direct download together

You have a verified Play developer account, so you can ship on Play too. There
is one permanent decision when you enroll the app in **Play App Signing**:

- **If you want a user to move between the Play version and a direct-download
  APK without reinstalling** (recommended for a wallet, since reinstalling can
  wipe data): when enrolling, choose to **upload your own app signing key** and
  give Play the key from step 1 - the same key that signs the direct APK. Then
  both channels share one signature and updates cross over. Google keeps a copy
  of the key (which also serves as an offsite backup), and you keep the master.

- **If you let Google generate the app signing key** (the default), Play
  re-signs uploads with a Google-held key you never see. That is lower
  key-management risk, but the Play build and your direct APK then have
  different signatures: a user cannot switch channels without uninstalling.

This choice is effectively locked in after your first Play upload, so decide
before you publish. For a wallet distributed first-class through both channels,
uploading your own key is usually the right call.
