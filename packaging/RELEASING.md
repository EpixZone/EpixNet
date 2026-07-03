# Releasing Epix

Official builds are produced by `.github/workflows/release.yml` when you push a
version tag:

```
git tag v0.2.0
git push origin v0.2.0
```

The workflow builds a signed macOS `.dmg`, a Linux tarball, and a signed Windows
installer, bundling Firefox ESR, and attaches them to a GitHub Release.

## Test builds without tagging

To just get an artifact to test - no tag, no signing, no Release - use the
**Build** workflow: Actions tab -> **Build** -> **Run workflow**. Pick `all` or a
single platform (faster). It needs no secrets and attaches the unsigned
artifacts to the run for download. Use this while iterating; tag only when you
want a real signed release.

## One-time: set up the macOS signing secrets

You need an Apple Developer account ($99/yr). In
**Settings -> Secrets and variables -> Actions**, add:

| Secret | What it is | How to get it |
|---|---|---|
| `APPLE_CERT_P12` | base64 of your Developer ID Application cert | see below |
| `APPLE_CERT_PASSWORD` | the password you set when exporting the .p12 | you choose it on export |
| `APPLE_SIGN_IDENTITY` | `Developer ID Application: Your Name (TEAMID)` | shown in Keychain / `security find-identity -p codesigning` |
| `APPLE_ID` | your Apple ID email | your account |
| `APPLE_TEAM_ID` | 10-char team id | developer.apple.com -> Membership |
| `APPLE_APP_PASSWORD` | app-specific password for notarization | appleid.apple.com -> Sign-In and Security -> App-Specific Passwords |

### Creating `APPLE_CERT_P12`

1. In Xcode or the Apple Developer portal, create a **Developer ID Application**
   certificate and install it in your login keychain.
2. In Keychain Access, right-click the certificate (with its private key) ->
   **Export** -> save as `epix.p12`, set a password (that's
   `APPLE_CERT_PASSWORD`).
3. base64-encode it for the secret:
   ```
   base64 -i epix.p12 | pbcopy   # paste into APPLE_CERT_P12
   ```

That's it - push a `v*` tag and the Release appears with a signed, notarized DMG.

## Windows signing (Azure Trusted Signing)

The Windows job builds a signed NSIS installer. Signing uses **Azure Trusted
Signing** (~$10/month, cloud HSM - no cert file or token to manage). Without the
secrets the installer is still built, just unsigned.

One-time setup:
1. Create a **Trusted Signing account** + a **certificate profile** in the Azure
   portal, and complete identity validation.
2. Create an **Entra ID app registration** (service principal) and give it the
   *Trusted Signing Certificate Profile Signer* role on the account.
3. Add these repo secrets:

| Secret | What it is |
|---|---|
| `AZURE_TENANT_ID` | your Entra tenant id |
| `AZURE_CLIENT_ID` | the app registration's client id |
| `AZURE_CLIENT_SECRET` | a client secret for that app |
| `AZURE_TS_ENDPOINT` | the account's region endpoint, e.g. `https://eus.codesigning.azure.net` |
| `AZURE_TS_ACCOUNT` | the Trusted Signing account name |
| `AZURE_TS_PROFILE` | the certificate profile name |

Push a `v*` tag and the installer is built, signed, and attached to the Release.

Note: a fresh certificate builds Microsoft SmartScreen reputation over time, so
the first downloads may still show a warning until reputation accrues - this is
normal and not something signing fixes immediately.

## Linux

The Linux tarball builds in CI (unsigned; distribute the checksum, or GPG-sign
the tarball as a follow-up).

## Notes

- The version comes from the tag (`v0.2.0` -> `0.2.0`), threaded to the build
  scripts via `EPIX_VERSION`.
- Bundling Mozilla's already-signed Firefox means we re-sign it with our
  Developer ID inside `build-app.sh` so the outer notarization passes.
- Alternative to the app-specific password: an App Store Connect API key
  (`--key`/`--key-id`/`--issuer` for notarytool). Swap those into the notarize
  step if you prefer key-based auth.
