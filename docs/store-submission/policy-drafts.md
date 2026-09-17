# Public policy drafts

The expanded website policy drafts are now in [TechSonix website PR #1](https://github.com/TechSonix/techsonix.com/pull/1). The legal publisher is **TechSonix, Inc.**, supplied by the owner. The proposed public URLs are `/epixnet/privacy/`, `/epixnet/terms/`, `/epixnet/support/`, `/epixnet/community/`, and `/epixnet/delete-data/` on `https://techsonix.com`. These pages are not yet deployed; contact routing and operational facts remain to be confirmed. The earlier drafting notes below are retained for traceability.

**Not published or approved.** The operator must replace every bracketed field,
confirm actual practices and publish separate accessible HTTPS pages. These
drafts deliberately make no unsupported promises about retention, jurisdiction,
moderator coverage or the ability to erase distributed records.

## Privacy page draft

EpixNet is provided by [LEGAL COMPANY NAME]. Contact [PRIVACY CONTACT] about
this policy. Effective date: [DATE].

EpixNet stores browser, network-node and wallet data on your device. It connects
to peers, visited websites, blockchain RPC services and services used by enabled
wallet features. Those recipients can receive the requests and connection
metadata needed to provide the service. Direct connections can reveal your IP
address. Routing settings affect which services see that address; they do not
guarantee anonymity.

Downloaded xite data may be stored and shared with peers. Content you publish,
including signed posts and directory reports, may be public and independently
replicated. Names, addresses and transactions recorded on a blockchain can
remain public after you remove local data. Avoid publishing private information.

Your wallet's encrypted data is stored locally. Supported operations send public
account information and transaction requests to network services. Keep your
recovery information private and backed up. [CONFIRM CUSTODY MODEL AND ALL
ENABLED THIRD-PARTY WALLET SERVICES].

Optional permissions include camera access for supported hardware-wallet QR
flows and nearby networking for enabled discovery/mesh functions. You can deny
or revoke permissions in device settings; the related feature may then be unavailable.

[INSERT AUDITED ANALYTICS/DIAGNOSTIC COLLECTION, RECIPIENTS, PURPOSES, RETENTION,
INTERNATIONAL TRANSFERS AND USER RIGHTS. DO NOT INSERT “WE COLLECT NOTHING”
WITHOUT VERIFYING THE EXACT BUILD AND SERVICE PRACTICES.]

For deletion or privacy requests use [DELETION URL / CONTACT]. We can act on
[SPECIFIC OPERATOR-CONTROLLED RECORDS]. We cannot erase blockchain history or
copies independently retained by other network participants. [DESCRIBE VERIFIED
IN-APP REMOVAL PATHS AND THE HANDLING OF LEGALLY RETAINED DATA].

## Community terms draft

Do not publish or promote child sexual exploitation, non-consensual intimate
content, targeted harassment or threats, scams, malware, private information
without permission, or material you are not authorized to distribute. Follow
applicable law and the rights and licenses of creators.

Community contributions are attributable to their authors and may be publicly
replicated. Report suspected violations through [PRIVATE REPORT URL] or the
in-app reporting controls. Never include illegal material itself in a report;
provide the address/identifier and a concise description.

[LEGAL COMPANY NAME] operates [DEFINED MODERATED SURFACES] and may restrict
content or accounts within those surfaces under these rules. Independent peers
and third-party websites are not all controlled by the operator. Appeals:
[APPEALS CONTACT AND VERIFIED PROCESS].

[ADD THE OPERATOR'S APPROVED SERVICE TERMS, AGE ELIGIBILITY AND REQUIRED LOCAL
CONSUMER INFORMATION. NO GOVERNING JURISDICTION HAS BEEN CHOSEN IN THIS DRAFT.]

## Support / deletion page draft

For help using EpixNet contact [SUPPORT EMAIL]. For content-safety or copyright
complaints contact [ABUSE EMAIL / FORM]. Include the xite/content identifier,
the problem and a way to reply. Do not send seed phrases, private keys or wallet
passwords. You do not need to acquire EPIX or purchase an xID to contact support.

To request removal of operator-controlled account/profile data, use [REQUEST
FORM OR EMAIL] and identify [MINIMUM VERIFICATION DETAILS]. We will [ACTUAL
RESPONSE/VERIFICATION PROCESS]. Public blockchain records and independent
replicas may persist; the response will explain what was removed and what remains.

Unlinking an identity in Config currently retains its key and previously
published content. Do not describe that action as account deletion. Removing a
local wallet is also different from deleting published profiles or chain records.

## Build configuration after publication

Set `EPIX_TERMS_URL` and `EPIX_PRIVACY_URL` in the wallet build environment.
For store artifacts set `EPIX_MOBILE_STORE_BUILD=1`. The wallet About screen uses
the separate links. The core release check verifies configuration and immutable
source provenance; a person must still verify page availability and accuracy.
