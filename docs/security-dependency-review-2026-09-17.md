# Dependency and code-scanning review, 2026-09-17

Based on main commit `1a7621021cd60bccfa6b38f12c48e6bd31a421c0` after the
September 17 Dependabot merges. No package versions were downgraded.

## Dependency compatibility

The intermediate builds failed because `muda` 0.20 menu values were passed to
`tray-icon` 0.24, which used a different `muda` version. The subsequent
`tray-icon` 0.25 merge restored compatibility. EpixNet now imports menu types
from `tray_icon::menu` and removes its independently versioned `muda` dependency,
so the tray always uses the menu API paired with its installed version.
The new MaxMind lookup/decode API was already supported by `GeoIp::locate`.

## Dependabot alert 2

[Alert 2](https://github.com/EpixZone/EpixNet/security/dependabot/2) concerns
`tracing-subscriber` below 0.3.20. The node's logger already used 0.3.23, but
RLN's `ark-relations` 0.5.1 dependency still brought in 0.2.25.

The documented patch in `vendor/ark-relations/EPIXNET_PATCH.md` adapts its
diagnostic layer to subscriber 0.3, including `Layer::on_new_span` and explicit
registry support. The workspace now resolves only subscriber 0.3.23. The
constraint arithmetic and serialized proof formats are unchanged. The unused
upstream `vendor/rln/Cargo.lock` is removed; application dependencies are
resolved by the root lockfile. RustSec/OSV exceptions for RUSTSEC-2025-0055
are removed, so the advisory is checked normally again.

## CodeQL review

- [153](https://github.com/EpixZone/EpixNet/security/code-scanning/153):
  reviewed and dismissed as a false positive. `Bitcoin seed` is the public
  BIP32/sslcrypto master-derivation label; the caller supplies the secret seed.
  Changing that label would change existing identities. The code now explains
  this and links the specification. The crypto compatibility vectors remain.
- [154–157](https://github.com/EpixZone/EpixNet/security/code-scanning/154):
  reviewed and dismissed individually as used in tests. These are fixed
  known-answer inputs inside `#[cfg(test)] mod prod_vectors`, excluded from
  production builds. Randomizing them would remove protocol compatibility
  checks. No scanning rules or production source paths are disabled.
- [152](https://github.com/EpixZone/EpixNet/security/code-scanning/152):
  the data-directory relocation feature intentionally accepts an absolute
  directory selected by the operator. HTTP configuration writes have same-origin
  and CSRF checks; WebSocket `configSet` is an administrative command. The path
  handling is additionally hardened: reject relative paths, parent traversal,
  and control characters; canonicalize existing ancestors before overlap
  checks; reject linked destination identities, source/destination symlinks and
  special files during copying; never overwrite an existing destination file.
  Tests cover legitimate relocation, aliases, configuration injection,
  overlapping roots, existing files, and linked identities.

Reviewing that path also exposed an authorization gap: `/Config` was treated as
a public route on every xite origin, so a xite could fetch the node's CSRF token
and make a same-origin settings POST. A regression test reproduced the token
disclosure before the fix. Settings now redirect from xite hosts to the node's
own loopback origin, refuse xite-origin writes even with a valid token, and
reject xite subresource reads regardless of the general CORS setting. Settings
responses cannot be framed or cached, and restricted gateways refuse them.
Tests also preserve normal settings navigation and submission on the node origin.

The new diagnostic-layer regression captures nested constraint spans through
subscriber 0.3. Existing crypto, pairwise known-answer, RLN identity, proof and
pool-admission tests verify compatibility. Exact validation results are recorded
in the associated pull request. The dependency alert clears on the default
branch after the fixed lockfile is merged and GitHub refreshes its analysis.
