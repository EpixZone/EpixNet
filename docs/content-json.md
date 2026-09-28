# Editing content.json

A xite's root `content.json` holds its metadata and signed file inventory.
Creating, cloning, or signing a xite adds the fields below when they are missing.
Existing values are kept. Unset fields contain `""`, so you can edit them without
finding another xite to use as a reference.

| Field | Purpose | Example value |
| --- | --- | --- |
| `title` | Xite title. Blank titles fall back to the requested name or address. | `"My xite"` |
| `description` | Description shown in xite information. | `"Notes and photos"` |
| `domain` | A domain claim, checked against the xID record. Setting this does not register a name. | `"my-xite.epix"` |
| `favicon` | Icon path relative to the xite root. | `"img/icon.png"` |
| `background-color` | Background behind the page's iframe. | `"#ffffff"` |
| `background-color-light` | Background override for the light theme. | `"#ffffff"` |
| `background-color-dark` | Background override for the dark theme. | `"#101418"` |
| `viewport` | Wrapper viewport settings. | `"width=device-width, initial-scale=1"` |
| `ignore` | Regular expression for files to omit when signing. | `"drafts/"` |
| `optional` | Regular expression for files to sign as optional downloads. | `"media/"` |
| `shard` | Regular expression for files to self-encrypt. | `"private/"` |

Blank page settings leave the wrapper defaults in place. A blank theme color
falls back to `background-color`. Blank file patterns match nothing. Patterns
match from the start of the path relative to the manifest's directory.

Edit these fields in the root `content.json`, then run
`epix-server siteSign <address>` to sign your changes. An existing owned xite
receives any missing fields the next time you sign it.

Generated fields such as `address`, `inner_path`, `modified`, `files`, and `signs`
are maintained by the signer. Feature-specific fields, such as `merged_type`
or clone bookkeeping, are added only when those features need them. Downloaded
manifests and child manifests are not backfilled with root authoring defaults.
