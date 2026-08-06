//! Authoring + diagnostics CLI actions, the EpixNet `epixnet.py <action>`
//! surface: siteCreate / siteSign / siteVerify / dbRebuild / dbQuery /
//! importBundle work offline against the data dir; crypt* are pure key
//! operations; peerPing measures an EDX link's round-trip to a running node;
//! siteCmd runs any WS command against a running node's admin socket.
//!
//! Kept clap-free on purpose: the action name is the first argument, exactly
//! like the Python CLI, and everything else stays positional.

use std::sync::Arc;

use epix_ui::state::AppState;

/// True when `name` is a CLI action (vs a xite target to open).
pub fn is_action(name: &str) -> bool {
    matches!(
        name,
        "siteCreate"
            | "siteSign"
            | "sitePublish"
            | "siteVerify"
            | "siteList"
            | "siteDelete"
            | "siteDownload"
            | "dbRebuild"
            | "dbQuery"
            | "importBundle"
            | "cryptSign"
            | "cryptVerify"
            | "cryptGetPrivatekey"
            | "cryptPrivatekeyToAddress"
            | "peerPing"
            | "siteCmd"
    )
}

/// Run `action` with the remaining CLI `args`. Returns the process exit code.
pub async fn run(action: &str, args: &[String], data_root: &std::path::Path, version: &str) -> i32 {
    match dispatch(action, args, data_root, version).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{action}: {e}");
            1
        }
    }
}

async fn dispatch(
    action: &str,
    args: &[String],
    data_root: &std::path::Path,
    version: &str,
) -> Result<(), String> {
    match action {
        // --- authoring (offline, against the data dir) --------------------
        "siteCreate" => {
            let state = open_state(data_root, version).await;
            let (address, privatekey) = state.create_xite().await?;
            println!("----------------------------------------------------------------------");
            println!("Site private key: {privatekey}");
            println!("          !!! ^ Save it now, required to modify the site ^ !!!");
            println!("Site address:     {address}");
            println!("----------------------------------------------------------------------");
            println!("Site created! You can find it in {}", data_root.join("data").join(&address).display());
            Ok(())
        }
        "siteSign" => {
            // Flags may appear anywhere among the arguments: `--full`
            // re-hashes every file instead of trusting the sign cache;
            // `--keep-missing` keeps declared optional entries whose file is
            // gone from disk (the default prunes them, so a deletion leaves
            // the manifest).
            let full = args.iter().any(|a| a == "--full");
            let keep = args.iter().any(|a| a == "--keep-missing");
            let args: Vec<String> =
                args.iter().filter(|a| !a.starts_with("--")).cloned().collect();
            let [address, rest @ ..] = args.as_slice() else {
                return Err(
                    "usage: siteSign <address> [privatekey] [inner_path] [--full] [--keep-missing]"
                        .into(),
                );
            };
            let privatekey = rest.first().filter(|k| !k.is_empty()).cloned();
            let inner_path = rest.get(1).cloned().unwrap_or_else(|| "content.json".to_string());
            // Live path first, like sitePublish: a running node must do the
            // signing itself so its EDX store registers the new bundles - an
            // offline sign next to a running node leaves the store on the old
            // version and peers get "file(s) not yet available" until restart.
            let live_params = serde_json::json!({
                "inner_path": inner_path, "privatekey": privatekey,
                "full": full, "keep_missing": keep,
            });
            if admin_call(data_root, "siteSign", Some(address), live_params).await?.is_some() {
                println!("{inner_path} signed via the running node [live]");
                return Ok(());
            }
            let state = open_state(data_root, version).await;
            if !state.has_any_alias(address).await {
                return Err(format!("Site not found: {address}"));
            }
            let content_path = state.content_inner_path(address, &inner_path).await;
            if content_path == "content.json" {
                let key = match privatekey {
                    Some(k) => k,
                    None => state
                        .site_privatekey(address)
                        .await
                        .ok_or("No saved private key for this site; pass one")?,
                };
                state
                    .sign_xite_with(
                        address,
                        &key,
                        epix_ui::SignOpts { full, keep_missing_optional: keep },
                    )
                    .await?;
            } else {
                state.sign_user_content(address, &content_path, privatekey, None).await?;
            }
            println!("{content_path} signed");
            Ok(())
        }
        "sitePublish" => {
            let [address, rest @ ..] = args else {
                return Err("usage: sitePublish <address> [inner_path]".into());
            };
            let inner_path = rest.first().cloned().unwrap_or_else(|| "content.json".to_string());
            // Live path first: if a node is running it holds the single-writer
            // EDX store lock (an offline publish could not open it anyway) and
            // already has a warm swarm, so route the publish to it over the
            // admin socket. `sign:false` - the CLI signs via `siteSign`, so this
            // publishes the already-signed content.json as-is (CLI semantics).
            let live_params =
                serde_json::json!({ "inner_path": inner_path, "sign": false });
            if let Some(_reply) =
                admin_call(data_root, "sitePublish", Some(address), live_params).await?
            {
                println!("{inner_path} published via the running node [live]");
                return Ok(());
            }
            // Offline path: no node running, so this command drives the publish.
            let state = open_state(data_root, version).await;
            if !state.has_any_alias(address).await {
                return Err(format!("Site not found: {address}"));
            }
            // Offline CLI: dial clearnet peers directly. Onion/i2p peers need
            // the node's Tor/I2P clients, so the dialable-networks filter
            // skips them here - they pull the version from the swarm on their
            // next sync instead.
            state.set_transport(std::sync::Arc::new(epix_transport::TcpTransport)).await;
            // EDX is the sole publish transport, and its fetcher is what
            // `publish()` pushes over. The long-running node installs it during
            // fileserver boot (ensure_edx_serve); this one-shot command boots no
            // fileserver, so we must open the object store + fetcher ourselves,
            // or publish() fails with "publishing requires EDX (it is disabled)".
            // No choker: an offline publish needs no reciprocity accounting.
            if let Some(dir) = state.data_root_path() {
                let node_key = epix_runtime::edx::node_key(&state).await;
                if epix_runtime::edx::enable_serving(&state, &dir, node_key, None)
                    .await
                    .is_none()
                {
                    return Err(
                        "could not open the EDX store (is another node instance running?)"
                            .into(),
                    );
                }
            }
            let content_path = state.content_inner_path(address, &inner_path).await;
            let published = state.publish(address, &content_path, None, true).await?;
            if published == 0 {
                return Err("no peers reachable right now - the update spreads on the next sync"
                    .into());
            }
            println!("{content_path} published to {published} peer(s)");
            Ok(())
        }
        "siteVerify" => {
            let [address] = args else { return Err("usage: siteVerify <address>".into()) };
            let state = open_state(data_root, version).await;
            if !state.has_any_alias(address).await {
                return Err(format!("Site not found: {address}"));
            }
            // The restore already verified the root signature (an invalid one
            // would not have loaded); check every declared file's bytes.
            let started = std::time::Instant::now();
            let bad = state.list_modified_files(address).await;
            let count = state
                .content(address)
                .await
                .and_then(|c| c.get("files").and_then(|f| f.as_object()).map(|m| m.len()))
                .unwrap_or(0);
            if bad.is_empty() {
                println!(
                    "[OK] {address}: {count} file(s) verified in {:.3}s",
                    started.elapsed().as_secs_f64()
                );
                Ok(())
            } else {
                for f in &bad {
                    println!("[CHANGED] {f}");
                }
                Err(format!("{} file(s) differ from the signed content.json", bad.len()))
            }
        }
        "dbRebuild" => {
            let [address] = args else { return Err("usage: dbRebuild <address>".into()) };
            let state = open_state(data_root, version).await;
            let started = std::time::Instant::now();
            if state.rebuild_xite_db(address).await {
                println!("Db rebuilt in {:.3}s", started.elapsed().as_secs_f64());
                Ok(())
            } else {
                Err("No db for this site (no dbschema.json?)".into())
            }
        }
        "dbQuery" => {
            let [address, query] = args else {
                return Err("usage: dbQuery <address> <sql>".into());
            };
            let state = open_state(data_root, version).await;
            let rows = state.db_query(address, query, &serde_json::Value::Null).await?;
            println!("{}", serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?);
            Ok(())
        }
        "importBundle" => {
            let [path] = args else { return Err("usage: importBundle <bundle.zip>".into()) };
            let state = open_state(data_root, version).await;
            let imported = state.import_bundle(std::path::Path::new(path)).await?;
            for address in &imported {
                println!("Imported {address}");
            }
            println!("{} site(s) imported", imported.len());
            Ok(())
        }

        // --- site admin: one path, run live via the admin socket when the node
        // is up, else the offline data-dir equivalent. `siteList` takes no arg;
        // the others take an address.
        "siteList" | "siteDelete" | "siteDownload" => {
            let address = if action == "siteList" {
                String::new()
            } else {
                let [a] = args else { return Err(format!("usage: {action} <address>")) };
                a.clone()
            };
            // The live command name and its params (siteDownload maps to siteAdd).
            let (live_cmd, params) = match action {
                "siteList" => ("siteList", serde_json::json!({})),
                "siteDelete" => ("siteDelete", serde_json::json!({ "address": address })),
                _ => ("siteAdd", serde_json::json!({ "address": address })),
            };
            match admin_call(data_root, live_cmd, None, params).await? {
                Some(reply) => match action {
                    "siteList" => {
                        let sites = reply.as_array().map(Vec::as_slice).unwrap_or_default();
                        for s in sites {
                            let addr = s.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                            let peers = s.get("peers").and_then(|v| v.as_i64()).unwrap_or(0);
                            println!("{addr}  ({peers} peers)");
                        }
                        println!("{} site(s) [live]", sites.len());
                    }
                    "siteDelete" => println!("Deleted {address} [live]"),
                    _ => println!("Downloading {address} [live] - watch the node log"),
                },
                None => {
                    let state = open_state(data_root, version).await;
                    match action {
                        "siteList" => {
                            let sites = state.xite_addresses().await;
                            for addr in &sites {
                                println!("{addr}");
                            }
                            println!("{} site(s) [offline]", sites.len());
                        }
                        "siteDelete" if !state.remove_xite(&address).await => {
                            return Err(format!("Unknown site: {address}"));
                        }
                        "siteDelete" => println!("Deleted {address} [offline]"),
                        // No network stack offline: register it so the node
                        // clones it on the next start.
                        _ => {
                            state.register_for_download(&address).await?;
                            println!("Queued {address}; downloads on next start [offline]");
                        }
                    }
                }
            }
            Ok(())
        }

        // --- key operations (no node, no data dir) -------------------------
        "cryptSign" => {
            let [message, privatekey] = args else {
                return Err("usage: cryptSign <message> <privatekey>".into());
            };
            println!("{}", epix_crypt::sign(message, privatekey).map_err(|e| e.to_string())?);
            Ok(())
        }
        "cryptVerify" => {
            let [message, sign, address] = args else {
                return Err("usage: cryptVerify <message> <sign> <address>".into());
            };
            println!("{}", epix_crypt::verify(message, address, sign));
            Ok(())
        }
        "cryptGetPrivatekey" => {
            let [master_seed, rest @ ..] = args else {
                return Err("usage: cryptGetPrivatekey <master_seed> [site_address_index]".into());
            };
            if master_seed.len() != 64 {
                return Err(format!(
                    "Invalid master seed length: {} (required: 64)",
                    master_seed.len()
                ));
            }
            let index: u64 = rest
                .first()
                .map(|s| s.parse().map_err(|_| "index must be a number".to_string()))
                .transpose()?
                .unwrap_or(0);
            println!(
                "Requested private key: {}",
                epix_crypt::hd_privatekey(master_seed, index).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "cryptPrivatekeyToAddress" => {
            let [privatekey] = args else {
                return Err("usage: cryptPrivatekeyToAddress <privatekey>".into());
            };
            println!(
                "{}",
                epix_crypt::privatekey_to_address(privatekey).map_err(|e| e.to_string())?
            );
            Ok(())
        }

        // --- run any WS command against a running node, bound to one xite ---
        // Per-site commands (feedItemQuery, feedSegmentSearch, dbQuery, ...)
        // read their target from the CONNECTION, not from params, so they are
        // unreachable without a bound xite. The admin socket binds one from the
        // request's `xite` key; this exposes that from the shell.
        "siteCmd" => {
            let (address, cmd, params_raw) = match args {
                [a, c] => (a, c, "{}"),
                [a, c, p] => (a, c, p.as_str()),
                _ => return Err("usage: siteCmd <address> <command> [json-params]".into()),
            };
            let params: serde_json::Value = serde_json::from_str(params_raw)
                .map_err(|e| format!("params must be JSON: {e}"))?;
            match admin_call(data_root, cmd, Some(address), params).await? {
                Some(reply) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&reply).unwrap_or_else(|_| reply.to_string())
                    );
                    Ok(())
                }
                // Unlike the site-admin actions there is no offline equivalent:
                // these commands read live node state.
                None => Err("node is not running (no admin socket)".into()),
            }
        }

        // --- peer diagnostics (an EDX link to a running node) --------------
        "peerPing" => {
            let [ip, port] = args else { return Err("usage: peerPing <ip> <port>".into()) };
            let conn = connect(ip, port).await?;
            for _ in 0..5 {
                let rtt = conn.ping().await.map_err(|e| e.to_string())?;
                println!("Response time: {:.3}ms", rtt.as_secs_f64() * 1000.0);
            }
            Ok(())
        }
        _ => Err("unknown action".into()),
    }
}

/// Send one command to the running node's admin socket, if it is up.
///
/// `Ok(None)` means the node is not running (no socket to connect to), so the
/// caller falls back to an offline data-dir operation. `Ok(Some(value))` is the
/// command's result. A command-level failure comes back as `Err`.
///
/// Windows has no admin socket (the server side is Unix-only), so this always
/// reports the node as absent and the caller takes the offline path.
#[cfg(not(unix))]
async fn admin_call(
    _data_root: &std::path::Path,
    _cmd: &str,
    _xite: Option<&str>,
    _params: serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    Ok(None)
}

/// `xite` binds the trusted session to a site, needed by commands that resolve
/// their target from the connection (e.g. `sitePublish`); pass `None` for
/// commands that carry the address in `params` (siteList/siteDelete/...).
#[cfg(unix)]
async fn admin_call(
    data_root: &std::path::Path,
    cmd: &str,
    xite: Option<&str>,
    params: serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let path = data_root.join("admin.sock");
    let mut stream = match tokio::net::UnixStream::connect(&path).await {
        Ok(s) => s,
        Err(_) => {
            // A node whose data dir cannot host unix sockets (network share)
            // binds in the temp dir and records where in admin.sock.path.
            let redirected = std::fs::read_to_string(data_root.join("admin.sock.path"))
                .ok()
                .map(|p| p.trim().to_string());
            match redirected {
                Some(p) => match tokio::net::UnixStream::connect(&p).await {
                    Ok(s) => s,
                    Err(_) => return Ok(None), // node not running -> offline path
                },
                None => return Ok(None),
            }
        }
    };
    let mut req_obj = serde_json::json!({ "cmd": cmd, "params": params });
    if let Some(x) = xite {
        req_obj["xite"] = serde_json::Value::String(x.to_string());
    }
    let req = req_obj.to_string();
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(b"\n").await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    let (r, _w) = stream.into_split();
    let mut line = String::new();
    BufReader::new(r).read_line(&mut line).await.map_err(|e| e.to_string())?;
    let reply: serde_json::Value =
        serde_json::from_str(line.trim()).map_err(|e| format!("bad admin reply: {e}"))?;
    // A transport/protocol error, or the EpixNet convention where a command
    // failure comes back as a result of `{"error": …}`.
    if let Some(err) = reply.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }
    let result = reply.get("result").cloned().unwrap_or(serde_json::Value::Null);
    if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }
    Ok(Some(result))
}

/// Open the node state offline: data dir + user + the served-site registry.
async fn open_state(data_root: &std::path::Path, version: &str) -> Arc<AppState> {
    let state = AppState::with_data_dir(version, data_root);
    state.restore_sites().await;
    state
}

/// Bring up an EDX link to a clearnet peer: dial, exchange the magic, run the
/// Noise handshake. No Hello is sent - a frame-level ping needs no identity,
/// so this measures the link itself.
async fn connect(ip: &str, port: &str) -> Result<epix_edx::conn::Conn, String> {
    use epix_transport::Transport;
    let addr = epix_core::PeerAddr::parse(&format!("{ip}:{port}"))
        .map_err(|e| format!("bad peer address: {e}"))?;
    let stream =
        epix_transport::TcpTransport.dial(&addr).await.map_err(|e| e.to_string())?;
    let link = epix_edx::link::dial(stream).await.map_err(|e| e.to_string())?;
    Ok(link.conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offline authoring cycle: create, edit, sign with the saved key,
    /// verify clean, tamper, verify dirty.
    #[tokio::test]
    async fn create_sign_verify_cycle() {
        let root = tempfile::tempdir().unwrap();
        let state = open_state(root.path(), "test").await;
        let (address, _privatekey) = state.create_xite().await.unwrap();
        assert!(state.has_xite(&address).await);
        assert!(state.site_privatekey(&address).await.is_some(), "key saved for later signs");
        assert!(state.list_modified_files(&address).await.is_empty(), "fresh site verifies");

        // Edit + re-sign via the same paths the CLI uses.
        let dir = state.xite_dir(&address).unwrap();
        std::fs::write(dir.join("index.html"), b"<h1>edited</h1>").unwrap();
        assert_eq!(state.list_modified_files(&address).await, vec!["index.html".to_string()]);
        let key = state.site_privatekey(&address).await.unwrap();
        state.sign_xite(&address, &key).await.unwrap();
        assert!(state.list_modified_files(&address).await.is_empty(), "signed clean again");

        // A second state over the same data dir restores the site (what a
        // fresh CLI invocation does).
        let state2 = open_state(root.path(), "test").await;
        assert!(state2.has_xite(&address).await, "registry persisted");
    }

    #[test]
    fn crypt_round_trips() {
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let sig = epix_crypt::sign("hello epix", &key).unwrap();
        assert!(epix_crypt::verify("hello epix", &address, &sig));
        assert!(!epix_crypt::verify("hello epi", &address, &sig));
        // HD derivation is deterministic per (seed, index).
        let a = epix_crypt::hd_privatekey(&epix_crypt::new_seed(), 5).unwrap();
        assert!(!a.is_empty());
    }

}
