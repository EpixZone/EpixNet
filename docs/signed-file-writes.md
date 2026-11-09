# Signed file writes

Use `fileWriteSign` for a settings edit that must become visible only after its
signature is verified. Ordinary `fileWrite` still writes a draft. Combining a
separate `fileWrite` and `siteSign` does not make a transaction.

The command accepts an object:

```json
{
  "inner_path": "data/admin/admin-settings.json",
  "content_base64": "<new UTF-8 file bytes, base64 encoded>",
  "expected_base64": "<exact bytes previously read, base64 encoded>",
  "privatekey": "stored"
}
```

`expected_base64` is required. If another writer changed the file after the
caller read it, the command rejects the edit. Read the current file again and
apply the intended change to that version. Do not retry a stale replacement
without checking the newer settings.

Use `privatekey: "stored"` for the saved xite owner key. Omit it to use the
selected identity. The signer must satisfy the governing manifest's verified
permissions. Normal gateway, CORS, merger, and write restrictions still apply.

The target must already be a required hashed file declared by a child
`content.json`. This command does not create files, replace manifests, or edit
root-governed, optional, sharded, or merged files. It is intended for settings
such as EpixTalk's admin configuration.

The node checks the expected bytes while holding the manifest and tree mutation
locks. It prepares and verifies the new signature with the proposed file bytes
in memory, then stages the file and manifest in the existing durable promotion
transaction. A rejected signature or stale edit leaves the live file, accepted
manifest, and database inputs unchanged. JSON publication snapshots are staged
in that transaction too. The first snapshot is kept until the publisher
consumes it to prepare a diff; it is not retained until peer delivery succeeds.

`"ok"` means the signed local commit completed. Publication is separate:

```json
{"inner_path":"data/admin/content.json","sign":false}
```

Pass that object to `sitePublish`. A publication error does not undo the accepted
local edit. A lost connection can leave the caller unsure whether a command
completed; read current settings before retrying. A later Store maintenance
failure is logged separately from the signed commit.

Older nodes may return `null` or an unknown-command error. Clients must report that an
EpixNet update is required instead of falling back to a draft write followed by
signing. The runtime clone fix and `fileWriteSign` support are both required for
the updated EpixTalk admin flow.
