# Mobile submission package

Updated 2026-09-16. **The wallet is published and pinned; signed Android packages and an unsigned iOS Release archive are built. Release gates remain open. Do not submit the current artifacts.**
Apple and Google organization enrollment is confirmed by the owner. No store
forms have been submitted. The owner has signed and published the dashboard
changes; the iPad simulator node has downloaded the updated files.

## Decisions preserved

- Dashboard remains the homepage on iOS, Android and desktop. Neither store
  requires users to find it through a search engine.
- iOS excludes BitTorrent media and tracker discovery at compile time.
  Android and desktop retain those features.
- The DeFlix dashboard tile removal and empty-feed mobile **Discover** label
  are merged in [EpixDash PR #37](https://github.com/EpixZone/EpixDash-Xite/pull/37)
  and published. Its community search listing remains available. No infringement
  finding is implied; catalog labels do not substitute for rights evidence.
- The company website must not lead visitors to EpixNet. Its app policies and
  support use unlisted public `/epixnet/…` URLs, linked from the app and store
  records after publication; the pages remain identical for all visitors.
- Reviewers must see the same product behavior as other users.

## Prepared materials

| File | Use |
| --- | --- |
| [Engineering review](engineering-review.md) | Cross-repository changes and security boundaries |
| [Listing and reviewer notes](store-listing.md) | Copy-ready product text and a review walkthrough, with unresolved fields marked |
| [Privacy/data inventory](privacy-data-inventory.md) | Evidence for privacy policy, App Privacy and Data safety answers |
| [Policy drafts](policy-drafts.md) | Privacy, support, deletion and terms text for the operator to finalize and publish |
| [Moderation runbook](moderation-runbook.md) | Report handling, ownership and publication requirements |
| [Rights ledger](deflix-rights-ledger.json) | All 1,142 catalog entries, each requiring evidence and territory review |
| [Release validation](release-validation.md) | Local test evidence, reproduction and gaps |
| [Release decisions](release-decisions.md) | Wallet, payment, deletion, encryption and audience decisions |
| [Configuration worksheet](submission-config.example.json) | Missing business details, URLs and distribution choices |

## Release blockers

1. Legal operator confirmed: **TechSonix, Inc.** Confirm public support/abuse
   contact and release countries. The redesigned TechSonix website and policy
   pages from [TechSonix PR #1](https://github.com/TechSonix/techsonix.com/pull/1)
   are deployed. Live HTML matches the validated export, app pages retain
   noindex and are omitted from company navigation, and HTTP redirects to HTTPS.
   Wallet CI now has the published terms/privacy URLs and store-build mode.
   Confirm the contact inbox and actual operational practices before submission.
2. Wallet [PR #18](https://github.com/EpixZone/epix-wallet/pull/18) is merged and
   its immutable `wallet-c31832e1aabd` release is published and pinned, with live
   policy URLs and analytics disabled. Signed Android APK/AAB packages and an
   unsigned iOS Release archive were built from `829c6536e29f4fb18f52bdef46acc415afbcc956`.
   Review [EpixNet PR #490](https://github.com/EpixZone/EpixNet/pull/490) and
   finish iOS distribution signing. See the validation record for artifact hashes.
3. Publish signed Epix Sites changes through its normal signing workflow.
   Validate reporting, blocking, filtering and private complaints across all
   promoted social xites; designate the people operating those controls.
4. Resolve content-rights evidence, paid xID classification, age/audience,
   countries and encryption/export declarations. Determine whether the integrated
   xID/profile flows constitute app accounts under store rules; no separate
   TechSonix account or blockchain-erasure capability has been established.
5. Complete signed physical-device testing, wallet approve/reject/sign/recovery,
   iPad layout and permission-denial checks. Produce exact release screenshots.
6. Supply iOS App Store signing/access and inspect the store records. Run
   TestFlight and Play internal testing, complete declarations from evidence,
   then submit the actual validated builds.

The engineering guards intentionally fail for missing policy configuration or
an uncommitted wallet. Do not bypass them to label a QA artifact submission-ready.
