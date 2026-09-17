# Moderation release runbook

Draft operations plan. A source change is not a staffed moderation service.
The operator must assign owners, confirm response coverage and publish the
signed xite updates before checking this off.

## Implemented locally in Epix Sites

- Versioned community-rules acceptance before creating/editing a directory
  entry; cancelling does not publish. Deletion is not blocked by new terms.
- Local blocking of a contributor or claimed owner, persistent across reloads;
  blocked entries are removed from browsing/search/Flagged views. Unblock is
  available in the filter menu.
- Flagged audit rows no longer render the original title, destination link,
  description or free-text report note. They retain aggregate status/reasons.
- Regression tests exercise cancellation, acceptance and blocking/filtering.

These changes are in the local `EpixSites-Xite` checkout. `content.json` has not
been re-signed and the network version has not been changed. EpixTalk has existing
report queues and moderator actions; those were inspected, not fully exercised.

## Required operator setup

| Responsibility | Required entry before release |
| --- | --- |
| Primary and backup moderator | [NAMES / COVERAGE] |
| Private public complaint channel | [HTTPS FORM OR EMAIL], accessible without xID/payment |
| Urgent safety escalation | [CONTACT, COVERAGE AND APPLICABLE REPORTING PROCESS] |
| Copyright contact and rights reviewer | [CONTACT / OWNER] |
| Appeal handling | [CONTACT / PROCESS] |
| Scope of control | List dashboard curation, directory records, hosted services and social communities actually operated |

## Handling a report

1. Record a case identifier, timestamp, content address/record ID, category and
   reporter contact if supplied. Avoid collecting copies of abusive material.
   Do not paste private complaint details into a public signed report.
2. Triage immediate danger/child exploitation/non-consensual content urgently
   through the designated process. Community stake/vote thresholds must not
   prevent a responsible operator from acting on substantiated serious reports.
3. Assess the content against the rules and evidence. Separate directory removal,
   blocking a contributor, removing operator-hosted content and global erasure;
   the last is not under the operator's control on a replicated network.
4. Apply and verify controls on the surfaces the operator controls. Confirm the
   item is absent from browse, search, recommendations and audit previews where
   required. Preserve only necessary restricted case metadata.
5. Notify the reporter when appropriate, provide an appeal route, and record
   action/reason. Follow the operator's defined retention and access policy.

## Acceptance checks before publishing

- Publish a disposable benign test entry; test report, owner/contributor block,
  unblock, rules decline, rules accept and moderator action on phone layouts.
- Verify untrusted user HTML and dangerous URL schemes never become executable.
- Verify public and private reports, logged-out support, default filtering and
  any applicable age restrictions in each promoted social xite.
- Republish through the normal signed-content workflow; verify a fresh mobile
  node acquires the new version and that updates are not limited to reviewers.
- Keep the complaint channel available and exercise the escalation path with
  a harmless test case. Record owner-approved response targets.

References: [Apple UGC review rules](https://developer.apple.com/app-store/review/guidelines/),
[Google UGC policy](https://support.google.com/googleplay/android-developer/answer/9876937?hl=en).
