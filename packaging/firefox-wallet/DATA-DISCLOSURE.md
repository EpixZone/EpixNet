# Epix Wallet data disclosure

This review covers the desktop Firefox signing candidate for `wallet@epix.zone`,
version `0.13.41.1`, with wallet source `39d6afd0e243` and the EpixNet packaging
and native bridge in PR #778. Wallet PR #40 updates local JavaScript dependency helpers for Firefox.
We reviewed the wallet permissions, data recipients and analytics configuration for this build.
The signing manifest requires the four data types below. Individual site connections, signature requests and
transactions still have their own controls. The wallet offers no separate
Firefox data permission for these flows. [Machine-readable declaration](data-disclosure.json) ·
[Mozilla data definitions](https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/)

## What the wallet shares

| Mozilla data type | What leaves the wallet and who receives it |
| --- | --- |
| Financial and payment information | Selected blockchain nodes and indexers receive public addresses to retrieve balances and history. Gas estimation can send unsigned transaction details, including a Cosmos memo, before the user approves a transfer. The network receives the signed transaction on broadcast. An approved transaction can create a permanent public record. Bitcoin inscriptions lookups send the public address to the relevant inscriptions provider. |
| Browsing activity | The wallet checks visited addresses against a downloaded phishing list locally. A match automatically opens `blocklist.keplr.app` with the full matched URL, including its path, query string, and any fragment present in the supplied URL. Google receives the requesting site's hostname to load its icon on some signature and account-switch prompts, even if the user later declines. A selected EVM node can receive the requesting site's origin in the `request-source` header with a blockchain query, transaction broadcast or receipt lookup. |
| Personally identifying information | A connected site with account permission can receive the user-chosen wallet name, public key and address. With the relevant permission it can also receive persistent wallet identifiers and account names. Some Bitcoin requests include a key fingerprint and derivation path. Some token scans send the profile-specific extension origin with the address to a node or token service. |
| Authentication information | A site can receive a user-approved signature proving control of an account, including for sign-in. A permitted app can request an existing Secret Network token viewing key for an account and contract. A private balance query can send that viewing key encrypted to the contract. The wallet unlock password and software spending keys stay local during those operations. |

Account queries can run in the background. Declining a signature prevents that
signature from being returned. It cannot recall a previous balance lookup,
fee simulation or icon request. These flows also apply in private windows if
the user grants the wallet private-window access. Disconnecting a site limits
future access. Recipients determine their own retention.

The desktop native bridge requests local node status, changes the selected Tor
routing setting, and opens node configuration. Ledger operations send device
selection and signing commands through the local host to the attached device.
The user can also export an encrypted wallet transfer QR code locally. Prices
can be fetched from CoinGecko by asset ID. This release has wallet usage
analytics disabled in its build metadata and reporting clients.

The [published privacy policy](https://techsonix.com/epixnet/privacy/) describes
wallet connections, independent providers and public records. The table gives
the release-specific details for publisher and reviewer use, including the
phishing URL, Google icon lookup, EVM origin, and viewing credentials.

## Sources for this release

- [Phishing redirect](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/apps/extension/src/background/background.ts#L202-L234), [content-script URL](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/apps/extension/src/content-scripts/content-scripts.ts#L120-L132), [Google icon URL](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/apps/extension/src/utils/favicon.ts), [signature prompt](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/apps/extension/src/pages/sign/components/arbitrary-message/arbitrary-message-origin.tsx), [account-switch prompt](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/apps/extension/src/pages/switch-account/index.tsx#L162).
- [Transaction simulation](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/packages/background/src/keyring-cosmos/service.ts#L1317-L1368), [EVM queries](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/packages/background/src/keyring-ethereum/service.ts#L1292-L1360), [EVM broadcast](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/packages/background/src/tx-ethereum/service.ts#L48-L69), [token scans](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/packages/background/src/token-scan/service.ts#L436-L465), [Bitcoin account and lookup data](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/packages/background/src/keyring-bitcoin/service.ts).
- [Connected wallet accounts](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/packages/background/src/keyring/handler.ts#L503-L575), [site challenge signatures](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/packages/background/src/keyring-ethereum/service.ts#L758-L800), [viewing key access](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/packages/background/src/token-cw20/handler.ts#L131), [private balance query](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/packages/stores/src/query/secret-wasm/secret20-balance.ts#L49).
- [Native commands](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/apps/extension/src/background/epix-native.ts#L512-L569), [local wallet transfer](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/apps/extension/src/pages/setting/general/link-keplr-mobile/index.tsx), [release configuration](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/.github/workflows/build-dist.yml#L57-L63), [analytics configuration](https://github.com/EpixZone/epix-wallet/blob/39d6afd0e243/apps/extension/src/config.ui.ts#L134-L147).
