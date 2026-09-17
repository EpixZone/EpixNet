# Decisions needed before submission

Research date: 2026-09-16. These are unresolved product/legal/store decisions,
not findings that the app violates a rule. Organization enrollment is confirmed.

## Wallet and payments

The owner confirms that the embedded wallet is **non-custodial**. It stores keys
locally; users control their keys and authorize wallet activity. TechSonix
publishes the software and does not operate custodial wallet accounts. Validate
every enabled exchange/swap/on-ramp integration for the release countries
separately from the wallet's confirmed custody model. Google's published policy expressly
places non-custodial wallets outside its **Cryptocurrency Exchanges and Software
Wallets** policy; this does not remove the Financial Features declaration or
other applicable requirements. Do not apply the listed custodial licensing
requirements automatically to a self-custody wallet.

Sources: [wallet scope](https://support.google.com/googleplay/android-developer/answer/16329703?hl=en),
[financial declarations](https://support.google.com/googleplay/android-developer/answer/13849271?hl=en).

xID exposes EPIX-denominated registration fees and says fees are burned. Record
what a paid name buys, whether it unlocks in-app digital functions, the operator's
role and affected storefronts. Assess those facts against store payment rules.
No bypass, purchase concealment, universal IAP exemption or blanket prohibition
has been assumed. Provide reviewers a legitimate test path without requiring
their own funds.

## DeFlix and curated content

The ledger includes 1,142 entries: 1,025 public-domain claims and 117 Creative
Commons labels. All remain `needs_rights_review`. Eleven have no source URL;
115 explicitly versioned CC entries have no license URL. Two generic Creative
Commons labels also need an exact license/version. Fifty-five entries include
NC and 48 include ND conditions that require scope review.

For each item record the rights holder/source of authority, exact media edition,
license/version and attribution, evidence URL, allowed distribution/download
uses, territory and reviewer/date. A public-domain assertion may depend on
territory and edition. A link to an archive is evidence to investigate, not
automatic permission. Prioritize missing sources and unclear license versions.

The owner requested removal of the dashboard tile. That change is merged in
[EpixDash PR #37](https://github.com/EpixZone/EpixDash-Xite/pull/37), signed and
published by the owner. The community search listing remains. Retain this ledger for any
future promotion or distribution assessment; no catalog entries were removed
and no rights verification is claimed. A community directory listing does not
settle the rights question.

References: [Apple review rules](https://developer.apple.com/app-store/review/guidelines/),
[Google intellectual property](https://support.google.com/googleplay/android-developer/answer/9888072?hl=en).

## Accounts and deletion

Browsing the dashboard does not create an operator account. The app can create
local wallet/identity material and interact with public xID/profile services.
Inventory each account/profile-creation path, data controller and delete API.
`identityRemove` currently unlinks an identity but explicitly keeps its key in
`users.json`; it is not an account-deletion implementation.

If the shipped experience creates app accounts, implement a usable in-app
deletion initiation path and the required public web request resource. Include
deletion of associated operator-controlled data, reauthentication where needed,
retained-data reasons and distributed-record limitations. Do not label local
unlink, logout or wallet removal as deletion of network records. No irreversible
deletion has been tested against the owner's data.

References: [Apple account deletion](https://developer.apple.com/support/offering-account-deletion-in-your-app/),
[Google deletion requirements](https://support.google.com/googleplay/android-developer/answer/13327111?hl=en).

## Encryption, audience and store classification

Inventory includes wallet/transaction cryptography, Rust TLS, Tor/I2P and
encrypted network protocols. Determine the applicable export classification,
territories and documentation from the exact artifact. Do not automatically set
`ITSAppUsesNonExemptEncryption=false` merely because transport includes HTTPS.
[Apple export process](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance).

Answer the age/audience questionnaires for unrestricted web access, community
content, social functions, wallet activity and the actual content controls.
Do not assume a child audience or enter the lowest rating by default.
[Apple age ratings](https://developer.apple.com/help/app-store-connect/reference/app-information/age-ratings-values-and-definitions).

Assess integrated software/native bridges under Apple's 4.7 where applicable.
Ordinary navigation links alone do not establish that every destination is a
mini-app. Review actual capabilities and describe them transparently.
