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

### One-time Azure setup

1. **Register the provider.** Azure portal -> your Subscription ->
   *Resource providers* -> search `Microsoft.CodeSigning` -> **Register**.

2. **Create a Trusted Signing account.** Search *Trusted Signing accounts* ->
   **Create**. Pick a resource group and a **region** (this decides your
   endpoint - see the table below). The Basic tier is ~$9.99/month. The name you
   give it is `AZURE_TS_ACCOUNT`.

3. **Validate your identity.** In the account -> *Identity validations* -> **New**.
   Choose Organization or Individual and complete it. This is the slow step
   (hours to days, may need documents) and it gates everything - you can't issue
   a public-trust cert without it.

4. **Create a certificate profile.** In the account -> *Certificate profiles* ->
   **Create** -> type **Public Trust** (for publicly distributed apps) -> select
   the approved identity validation. The name you give it is `AZURE_TS_PROFILE`.

5. **Create a service principal.** Microsoft Entra ID -> *App registrations* ->
   **New registration** (name it e.g. `epix-signing`). From its Overview copy
   the **Application (client) ID** (`AZURE_CLIENT_ID`) and **Directory (tenant)
   ID** (`AZURE_TENANT_ID`). Then *Certificates & secrets* -> **New client
   secret** -> copy the secret **Value** immediately (`AZURE_CLIENT_SECRET`; it's
   shown once).

6. **Grant it the signer role.** Trusted Signing account -> *Access control
   (IAM)* -> **Add role assignment** -> role **Trusted Signing Certificate
   Profile Signer** -> assign to the `epix-signing` app registration.

### The six repo secrets

Repo -> Settings -> Secrets and variables -> Actions -> New repository secret:

| Secret | Where to get it |
|---|---|
| `AZURE_TENANT_ID` | app registration Overview -> Directory (tenant) ID |
| `AZURE_CLIENT_ID` | app registration Overview -> Application (client) ID |
| `AZURE_CLIENT_SECRET` | the client secret Value from step 5 |
| `AZURE_TS_ENDPOINT` | your region endpoint (table below) |
| `AZURE_TS_ACCOUNT` | the Trusted Signing account name |
| `AZURE_TS_PROFILE` | the certificate profile name |

Region endpoints (`AZURE_TS_ENDPOINT`): East US `https://eus.codesigning.azure.net`,
West US 3 `https://wus3.codesigning.azure.net`, West Central US
`https://wcus.codesigning.azure.net`, North Europe `https://neu.codesigning.azure.net`,
West Europe `https://weu.codesigning.azure.net`. If unsure, the account Overview
in the portal shows the endpoint.

### Test it

Run the **Release** workflow by hand (Actions -> Release -> Run workflow) - the
Windows job builds *and signs* and uploads the installer as a run artifact,
without publishing a Release. (The **Build** workflow is intentionally unsigned,
so use Release to test signing.) Once it's green, push a `v*` tag for the real
thing.

### SmartScreen: getting from "unrecognized app" to no warning

Signing alone does not remove the orange "Windows protected your PC" banner -
SmartScreen is a *reputation* system layered on top of the signature. What it
weighs, per Microsoft's [developer guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation):

- **Publisher reputation** (the signing identity) and **file-hash reputation**
  (each released binary). A young certificate + a brand-new installer = the
  warning, even with a valid Trusted Signing signature.
- Reputation carries across releases only when every release is signed with the
  **same identity** - keep using the same certificate profile forever; never
  ship an unsigned build in between.
- **EV certificates no longer bypass SmartScreen** (Microsoft removed that
  behavior) - don't pay for one hoping to fix this.
- It typically takes **several weeks and hundreds of clean installs** for the
  warning to fade. There is no consumer-facing form to expedite it; the
  [Security Intelligence submission portal](https://www.microsoft.com/en-us/wdsi/filesubmission)
  exists for wrong *malware* detections and enterprise scenarios.

Known 2026 wrinkle: Trusted Signing rotated its intermediate CAs on
2026-03-26 ("Microsoft ID Verified CS EOC/AOC CA 0x"), and reputation did not
propagate to chains under the new intermediates - every signed build showed the
warning again. Microsoft fixed the propagation on 2026-06-18; builds signed
after that date accrue (and inherit) reputation normally, with no account or
workflow change needed. Releases signed inside that window (0.3.3 was) benefit
from simply being re-released.

Guaranteed no-warning channels, if/when wanted:

- **Microsoft Store**: Store-distributed apps are re-signed by Microsoft and
  never see SmartScreen.
- **winget** (`winget install`): no browser download prompt and no orange
  dialog UX; a manifest PR to microsoft/winget-pkgs pointing at the signed
  GitHub-Release installer is enough.

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
