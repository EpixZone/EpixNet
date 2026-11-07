# Local profiles for offline xites

Local profiles let a xite create a signing identity and exchange public or private messages without registering an xID or contacting the chain. A local profile belongs to one canonical xite address and one EpixNet user. Different xites get different identities and encryption keys. The scope comes from the verified registration and accepted root, so an unsigned manifest edit cannot redirect it. Changing the selected xID does not change the local profile.

The keys remain in EpixNet. They are derived from the user's master seed with separate signing and encryption domains. Restoring the same `users.json` or master seed restores those keys. Restore the xite data too, or obtain its signed data from peers, to recover the saved profile and message history. A seed alone cannot reconstruct messages that no peer or backup retains.

## Consent and API

The xite must request `LOCAL_PROFILE` through the trusted wrapper:

```javascript
frame.cmd("wrapperPermissionAdd", "LOCAL_PROFILE", onResult);
```

Pass a string to that wrapper command. Every native command below takes an object, including `{}` for commands with no arguments. Check `localProfileInfo` first; an older node may not implement the command. Errors use the existing EpixFrame `{error: "message"}` response. Public gateways do not offer local profiles, and `as` cannot rebind these commands to another xite.

| Command | Parameters | Result |
| --- | --- | --- |
| `localProfileInfo` | `{}` | Availability, permission state, own profile, optional xID-link availability, limits |
| `localProfileCreate` | `{display_name}` | Create or rename the local profile |
| `localProfilePublicPost` | `{room, text}` | Append a public signed message |
| `localProfileGroupCreate` | `{title, profiles}` | Create a private group from verified `signed_profile` objects, including self |
| `localProfileSeal` | `{group_id, text}` | Append a message to a known private group |
| `localProfileOpen` | `{envelope}` | Verify and open a private envelope for this identity |
| `localProfileVerify` | `{record}` | Verify a profile/public record, or verify and open a private envelope |
| `localProfileList` | `{}` | Verified profiles, readable messages and private groups, plus truncation/rejection indicators |
| `localProfileLinkXid` | `{}` | Add a signed proof from the currently selected linked xID |

Mutation results contain `record` and `publish`. `publish.status` is `accepted_by_peers` when a peer accepted the signed update, or `local_only` when it is saved locally without such an acknowledgement. Peer acceptance is not proof that another person read a message. The API does not promise a durable delivery queue.

Profile results contain `author`, `display_name`, `encryption_key`, `own`, `signed_profile`, and optional `xid`. Treat `signed_profile` as opaque input for group creation. Public messages contain `id`, `author`, `display_name`, `room`, `text`, `sent_at`, and `own`. Private messages instead carry `group_id`, `title`, `members`, and `kind` (`invitation` or `message`). Group membership is immutable. Create a new group to add or remove members.

An xID link is optional and binds the xite, local signing identity, and encryption key. Its status is `verified`, `stale`, `revoked`, or `unknown`, depending on the chain-backed resolution available to this node. A signed link alone is not proof of current name ownership. Offline or unresolved links never prevent local profile messaging.

## Signed xite storage

The native implementation writes only its own `data/users/<local-author>/data.json` and signs that directory's child `content.json`. The xite must have an owner-signed `data/users/content.json` included by the root, with rules permitting ordinary signed user data without a certificate requirement. For example:

```json
{
  "user_contents": {
    "cert_signers": {},
    "permissions": {},
    "permission_rules": {
      ".*": {
        "max_size": 1048576,
        "files_allowed": "data\\.json"
      }
    }
  }
}
```

The node stages the new file and signed manifest together and uses the existing child verification, publication, Store receipts, and rollback path. Reads accept only current verified manifest chains and exact file hashes. Loose files, unsigned profiles, changed parent manifests, and invalid message signatures do not become chat records. User switching and permission revocation wait for accepted native profile operations to finish, including writes whose requesting page has disconnected.

## Privacy and limits

Public profiles, public messages, and signed child metadata are public xite data. Private message bodies, group titles, and member lists are inside authenticated ECIES ciphertext. Each member gets an independently encrypted copy, including the sender for history. The outer envelope still exposes the sender, timestamp, message ID, ciphertext sizes, and number of copies. It does not list recipient identities.

The protocol uses the existing native ECIES implementation and xite-bound signed records. It does not provide forward secrecy. A compromised master seed can decrypt retained history, and a recipient can copy or disclose plaintext. Use a new group for membership changes; that does not revoke copies already held by former members.

Groups support up to eight members, including self. Message text is limited to 4096 UTF-8 bytes. Each user document keeps at most 128 public and 32 private records and 512 KiB total; the oldest records are removed when a limit is reached. This is bounded chat history, not permanent archival storage. Back up data you need to retain.

One list operation attempts at most 128 user documents, accepts at most 64 and reads at most 8 MiB, verifies at most 512 messages, and performs at most 256 private-box decrypt attempts. The result reports `truncated` when a limit is reached and `rejected` for invalid inputs. The native API does not expose private keys, arbitrary signing, arbitrary decryption, or an arbitrary file-write command.
