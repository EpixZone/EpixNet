# Multiuser Plugin

Turns an EpixNet instance into a multi-user proxy gateway. Each visitor is
assigned a cookie-backed identity automatically; admins log in with their
existing master seed.

By default this plugin is **disabled** (the directory is named
`disabled-Multiuser`). Enable it only if you are deliberately running a
public gateway. For normal desktop use, leave it disabled.

## Enabling the plugin

Rename the directory so the plugin manager loads it:

```bash
mv plugins/disabled-Multiuser plugins/Multiuser
```

Restart EpixNet. The plugin will register two new CLI flags
(`--multiuser-local`, `--multiuser-no-new-sites`).

To disable again, rename back to `plugins/disabled-Multiuser`.

## Operating modes

The plugin's behaviour for any given request depends on whether the visitor
is a **proxy user** (cookie-backed anonymous identity) or an **admin**.
Admin status is granted to:

- Any visitor whose `master_address` cookie matches an entry in
  `<data-dir>/private/users.json` (the local user file, populated by your
  own client), **or**
- All visitors, if `--multiuser-local` is passed.

Proxy users have access to most browsing features but are blocked from
admin-only actions (decorated with `@flag.no_multiuser` in the source).
Attempts produce the notification:

```text
This function (<cmd>) is disabled on this proxy!
```

## CLI flags

### `--multiuser-local`

Run the plugin in **local mode**: every visitor is treated as an admin and
user objects are persisted to disk. Use this when you want the multi-user
UI features (login form, user-switching, master-seed prompts) on your own
machine without locking yourself out of admin functions.

```bash
python3 epixnet.py --multiuser-local
```

Do not use this in production. The flag's own help text describes it as
"unsafe Ui functions".

### `--multiuser-no-new-sites`

Block proxy users from adding sites the gateway hasn't already loaded.
Admins (per the rules above) can still add sites.

```bash
python3 epixnet.py --multiuser-no-new-sites
```

The flag is a boolean (`store_true`). It is **off by default** — adding
new sites is allowed unless you pass this flag. Passing the flag without a
value is correct; do not pass `enabled`, `true`, `1`, etc.

When the flag is on and a proxy user visits an unknown site address, the
gateway returns:

```text
Not Found
Adding new sites disabled on this proxy
```

The flag can also be set persistently in `epixnet.conf`:

```ini
[global]
multiuser_no_new_sites = True
```

### Combining the flags

For a public gateway where you (the operator) want to keep admin rights:

```bash
python3 epixnet.py --multiuser-local --multiuser-no-new-sites
```

This locks down site-adding for anonymous visitors while letting you add
and manage sites normally.

## Logging in as an existing master address

If you want to use your existing master seed (so you appear as admin via
`users.json` rather than via `--multiuser-local`), Multiuser exposes a
`userLoginForm` websocket action. The simplest way to invoke it from a
clean session:

1. Clear the `master_address` cookie for your EpixNet origin, or open the
   dashboard in a private window.
2. In the browser's JavaScript console (with the dashboard frame focused),
   run:
   ```js
   epixframe.cmd("userLoginForm")
   ```
3. Paste the master seed from `<data-dir>/private/users.json` into the
   prompt and submit. The cookie is updated and the page reloads.

Some site UIs (e.g. Epix Talk) surface a "Connect xID" / Login button
that calls the same action — once that flow is invoked you can paste the
seed there instead of using the console.

## Related

- `NoNewSites` plugin (`plugins/disabled-NoNewSites/`) is a newer, simpler
  way to lock down a public gateway. It also injects a "Public gateway —
  read-only" banner. If you only need to block site additions and don't
  want the full multi-user account system, enable `NoNewSites` instead.
