# Privacy and data inventory

Source inspection and local QA: 2026-09-16. This is input to the declarations,
not a submitted App Privacy/Data safety form. **Do not select “no data collected”
without evaluating the actual release and service relationships.**

| Flow | Data and destination | Local retention / user control | Evidence and unresolved work |
| --- | --- | --- | --- |
| Peer networking and xite sync | Requested xite addresses, content and connection metadata reach peers/bootstrap/transport services; direct peers can observe source IP | Downloaded xites and peer state persist in the app data directory | Embedded `epix-node`/runtime. Audit direct/Tor/I2P and optional mesh behavior in the signed build |
| Browsing | URLs and requests reach visited services; web storage may persist | Browser website-data stores, history/session state | Native browser shell; private namespace gets separate origins on iOS |
| Signed posts, directories, reports and profiles | Contributor identifiers and published content are replicated | Local removal cannot erase independent replicas | Xite repositories and signed user-data schemas. Do not solicit sensitive material in public report text |
| xID | Public addresses, names, registration/transfer transactions and fees reach chain services | Chain records persist independently of the app | `EpixNet-xAuth`; local identity unlink does not erase a registration |
| Wallet | Encrypted vault/preferences locally; public addresses, balance queries, unsigned/signed transaction data go to selected RPC/services as needed | iOS stores JSON values with complete file protection; wallet document is discarded on background; export/recovery is the user's responsibility | `mobile-shim.ts`, native store, existing wallet background/router. Full recovery/upgrade tests remain |
| Wallet services | Chain RPC endpoints, CoinGecko prices and phishing-list services; other integrations depend on enabled flows | Provider retention is not controlled by local vault deletion | Wallet `config.ts`, `config.ui.ts`, background. Inventory endpoints and contracts for the immutable release |
| Analytics | Source includes an install-event path and analytics SDKs; credentials/endpoints are configurable | Configuration-specific | Default analytics credentials are empty. `epix-mobile-build.json` records a boolean, never secrets. Verify the pinned artifact and network traffic before declaring collection/tracking |
| Diagnostics | `epix.log` and `native-stderr.log` under app data; may contain network/error details | Local files; retention/rotation must be checked | No automatic support-log upload was added. Do not request vault/seed data in support |
| Camera | Hardware-wallet QR frames processed by the wallet scanning flow | Permission can be denied/revoked | Active iOS plist has a purpose string; native wallet frame restriction; physical-device grant/deny QA pending |
| Nearby networking | Optional LAN discovery; Android also declares Bluetooth scan/connect/advertise | OS permissions and feature settings | Test actual support and denied permissions; declarations do not prove every feature works |

## Apple privacy manifest

The bundled manifest currently declares app-scoped UserDefaults (`CA92.1`),
file timestamps for app-container files (`C617.1`) and elapsed-time/boot-time
APIs (`35F9.1`), plus free-space-based cache limits/eviction (`E174.1`) and
user-visible storage statistics (`85F4.1`). These entries cover required-reason APIs; they are not the
store's collection disclosures. Generate the archive privacy report and verify
linked native dependencies, including any additional categories, before upload.

## Form preparation

For each data type record whether it leaves the device, who receives it,
whether the developer/partner retains it, purpose, whether linked to a person,
whether optional, retention and deletion behavior. Distinguish a user's explicit
public publication from analytics or developer collection. Do not assume that
decentralization, encryption or self-custody automatically exempts a transfer.

Review addresses/identifiers, user content, browsing activity, financial data,
diagnostics and IP/network metadata against the actual form definitions. Verify
whether any recipient uses data for cross-app tracking; empty analytics keys
alone do not answer that question for every third party.

Sources: [Apple privacy details](https://developer.apple.com/app-store/app-privacy-details/),
[Google Data safety](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en),
[required-reason APIs](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitypereasons).
