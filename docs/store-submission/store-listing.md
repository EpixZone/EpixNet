# Store text and review walkthrough

Draft. Replace bracketed fields, resolve release blockers and verify against
the exact signed build before copying into either console.

## Listing text

**Name:** EpixNet

**Apple subtitle:** Browse the Epix network

**Google short description:** Browse Epix xites and the web with an integrated, self-custody wallet.

**Description:**

EpixNet brings the Epix network to your phone. Open the dashboard, visit xites
by name, discover community destinations, and browse the web in tabs.

Use the integrated Epix Wallet to manage supported blockchain accounts and
review connection and signing requests. Explore xID names and the communities
built around them. Browsing the dashboard does not require a wallet.

EpixNet runs a network node on your device. Downloaded xite data can be stored
locally and shared with peers. Network availability and routing settings affect
how quickly content loads. Community content is published by its contributors.

Wallet recovery information is important: keep a secure backup before removing
a wallet or uninstalling the app. Blockchain transactions and public records
can remain visible after local data is removed.

Privacy: [PUBLIC PRIVACY URL]
Support and content reports: [PUBLIC SUPPORT URL]

**Platform-specific addition, Android only:** This version includes BitTorrent
transport support. Only access or share content you are authorized to use.

Do not advertise guaranteed anonymity, guaranteed content availability,
investment returns, universal device support, verified rights for the entire
catalog, or wallet features not exercised in release QA.

## Reviewer notes

EpixNet embeds a peer-network node and browser. iOS uses WKWebView; Android
uses GeckoView. The dashboard is the normal homepage for all users. It contains
a local xite list and links to community destinations in Discovery.

1. Launch with an internet connection. Wait for node startup and dashboard
   acquisition. The first network download can take longer than later launches.
2. Open Dashboard. On narrow screens choose Xites for the local list. The other
   toggle reads Discover when the feed has no entries and Feed when it does.
   Discover shows the curated destination links. Browsing needs no account.
3. Open xID, or enter `epix://xid.epix` only after verifying that alias resolves
   in the release environment. The verified direct xID address in local QA is
   `epix1xauthduuyn63k6kj54jzgp4l8nnjlhrsyaku8c.epix`.
4. Choose Connect Wallet, then Epix Wallet. On a fresh install the wallet opens
   its setup screen. Use [REVIEW ACCESS / DISPOSABLE TEST WALLET INSTRUCTIONS].
   Never supply a production seed phrase. A review path requiring cryptocurrency
   funding must be arranged and tested before submission.
5. Test connection approval, rejection and cancellation. Requests retain their
   website origin; a connection is not permission to silently sign transactions.
6. Visit [VERIFIED REPORT/BLOCK WALKTHROUGH] and [VERIFIED DELETION WALKTHROUGH].
   Those workflows must be tested on the signed build before these notes are final.

iOS excludes the BitTorrent media engine and tracker discovery from the binary.
The same iOS build is delivered to reviewers and users. Android retains those
features. Content permissions still apply regardless of transport.

The iOS browser handles the private `.epix` namespace through an in-process
loopback proxy and per-install CA. Trust is restricted to the app's `.epix`
browser requests, with hostname, expiry and chain validation. The CA is not
installed as a device root. The namespace has a scoped ATS exception; public
HTTPS sites retain ordinary system certificate validation.

Camera access is requested for supported hardware-wallet QR scanning. Local
network discovery is optional and starts disabled. [CONFIRM EACH SHIPPED
PERMISSION AND THE RELEASE BUILD'S ROUTING DEFAULTS].

Review contact: [NAME, BUSINESS EMAIL, PHONE]. Support stays staffed and
bootstrap infrastructure stays available throughout review.

## Store assets to capture from the signed candidate

- iPhone: dashboard, Discovery, xID browse/search, wallet connection approval.
- iPad: the same core screens at a supported iPad size if iPad support is retained.
- Android: dashboard, Discovery, xID and wallet on a supported phone.
- Show only disposable identities; never show seed phrases, balances or private
  conversations belonging to the owner. Screenshots must match actual features.
- Confirm icon appearance, small-text legibility and screenshot dimensions in
  the current console. Debug simulator frames are not final store screenshots.
