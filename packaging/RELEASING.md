# Releasing Epix

Official builds are produced by `.github/workflows/release.yml` when you push a
version tag:

```
git tag v0.2.0
git push origin v0.2.0
```

The workflow builds a signed + notarized macOS `.dmg` and a Linux tarball,
bundling Firefox ESR, and attaches them to a GitHub Release. You can also run it
by hand from the Actions tab (workflow_dispatch) for a dry run - without the
signing secrets it still produces an ad-hoc-signed (unnotarized) app so you can
test the pipeline.

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

## Windows / Linux

The Linux tarball builds in CI. Windows is a scaffold (see
`packaging/windows/README.md`): once the NSIS installer + registry steps are
finished, add a `windows` job mirroring the others (Authenticode signing needs a
code-signing cert in a secret, similar to the macOS flow).

## Notes

- The version comes from the tag (`v0.2.0` -> `0.2.0`), threaded to the build
  scripts via `EPIX_VERSION`.
- Bundling Mozilla's already-signed Firefox means we re-sign it with our
  Developer ID inside `build-app.sh` so the outer notarization passes.
- Alternative to the app-specific password: an App Store Connect API key
  (`--key`/`--key-id`/`--issuer` for notarytool). Swap those into the notarize
  step if you prefer key-based auth.
