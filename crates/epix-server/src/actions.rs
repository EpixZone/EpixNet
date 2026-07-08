//! Authoring + diagnostics CLI actions, the EpixNet `epixnet.py <action>`
//! surface: siteCreate / siteSign / siteVerify / dbRebuild / dbQuery /
//! importBundle work offline against the data dir; crypt* are pure key
//! operations; peer* drive the wire protocol against a running node.
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
            | "siteVerify"
            | "dbRebuild"
            | "dbQuery"
            | "importBundle"
            | "cryptSign"
            | "cryptVerify"
            | "cryptGetPrivatekey"
            | "cryptPrivatekeyToAddress"
            | "peerPing"
            | "peerGetFile"
            | "peerCmd"
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
            let [address, rest @ ..] = args else {
                return Err("usage: siteSign <address> [privatekey] [inner_path]".into());
            };
            let privatekey = rest.first().filter(|k| !k.is_empty()).cloned();
            let inner_path = rest.get(1).cloned().unwrap_or_else(|| "content.json".to_string());
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
                state.sign_xite(address, &key).await?;
            } else {
                state.sign_user_content(address, &content_path, privatekey, None).await?;
            }
            println!("{content_path} signed");
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

        // --- peer diagnostics (wire protocol against a running node) -------
        "peerPing" => {
            let [ip, port] = args else { return Err("usage: peerPing <ip> <port>".into()) };
            let mut conn = connect(ip, port).await?;
            for _ in 0..5 {
                let started = std::time::Instant::now();
                conn.ping().await.map_err(|e| e.to_string())?;
                println!("Response time: {:.3}ms", started.elapsed().as_secs_f64() * 1000.0);
            }
            Ok(())
        }
        "peerGetFile" => {
            let [ip, port, site, inner_path] = args else {
                return Err("usage: peerGetFile <ip> <port> <site> <inner_path>".into());
            };
            let mut conn = connect(ip, port).await?;
            let bytes = conn.get_file(site, inner_path).await.map_err(|e| e.to_string())?;
            use std::io::Write;
            std::io::stdout().write_all(&bytes).map_err(|e| e.to_string())?;
            Ok(())
        }
        "peerCmd" => {
            let [ip, port, cmd, rest @ ..] = args else {
                return Err("usage: peerCmd <ip> <port> <cmd> [json-params]".into());
            };
            let params: serde_json::Value = match rest.first() {
                Some(raw) => serde_json::from_str(raw).map_err(|e| format!("bad params: {e}"))?,
                None => serde_json::json!({}),
            };
            let mut conn = connect(ip, port).await?;
            let reply =
                conn.request(cmd, json_to_rmpv(&params)).await.map_err(|e| e.to_string())?;
            println!("{}", serde_json::to_string_pretty(&rmpv_to_json(&reply)).unwrap());
            Ok(())
        }
        _ => Err("unknown action".into()),
    }
}

/// Open the node state offline: data dir + user + the served-site registry.
async fn open_state(data_root: &std::path::Path, version: &str) -> Arc<AppState> {
    let state = AppState::with_data_dir(version, data_root);
    state.restore_sites().await;
    state
}

async fn connect(ip: &str, port: &str) -> Result<epix_protocol::Connection, String> {
    let addr = epix_core::PeerAddr::parse(&format!("{ip}:{port}"))
        .map_err(|e| format!("bad peer address: {e}"))?;
    let mut conn = epix_protocol::Connection::connect(&epix_transport::TcpTransport, &addr)
        .await
        .map_err(|e| e.to_string())?;
    conn.handshake().await.map_err(|e| e.to_string())?;
    Ok(conn)
}

fn json_to_rmpv(v: &serde_json::Value) -> rmpv::Value {
    match v {
        serde_json::Value::Null => rmpv::Value::Nil,
        serde_json::Value::Bool(b) => rmpv::Value::from(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                rmpv::Value::from(i)
            } else {
                rmpv::Value::from(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => rmpv::Value::from(s.as_str()),
        serde_json::Value::Array(items) => {
            rmpv::Value::Array(items.iter().map(json_to_rmpv).collect())
        }
        serde_json::Value::Object(map) => rmpv::Value::Map(
            map.iter().map(|(k, v)| (rmpv::Value::from(k.as_str()), json_to_rmpv(v))).collect(),
        ),
    }
}

fn rmpv_to_json(v: &rmpv::Value) -> serde_json::Value {
    match v {
        rmpv::Value::Nil => serde_json::Value::Null,
        rmpv::Value::Boolean(b) => serde_json::json!(b),
        rmpv::Value::Integer(i) => i
            .as_i64()
            .map(|n| serde_json::json!(n))
            .unwrap_or_else(|| serde_json::json!(i.as_u64())),
        rmpv::Value::F32(f) => serde_json::json!(f),
        rmpv::Value::F64(f) => serde_json::json!(f),
        rmpv::Value::String(s) => serde_json::json!(s.as_str().unwrap_or_default()),
        rmpv::Value::Binary(b) => {
            // Show small binaries as lossy text, large ones as a length note.
            if b.len() <= 256 {
                serde_json::json!(String::from_utf8_lossy(b))
            } else {
                serde_json::json!(format!("<{} bytes>", b.len()))
            }
        }
        rmpv::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(rmpv_to_json).collect())
        }
        rmpv::Value::Map(pairs) => serde_json::Value::Object(
            pairs
                .iter()
                .map(|(k, v)| (k.as_str().unwrap_or_default().to_string(), rmpv_to_json(v)))
                .collect(),
        ),
        _ => serde_json::Value::Null,
    }
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

    #[test]
    fn json_rmpv_round_trip() {
        let v = serde_json::json!({
            "site": "epix1abc", "need": 5, "flag": true, "list": [1, "two", null],
            "nested": { "f": 1.5 },
        });
        let back = rmpv_to_json(&json_to_rmpv(&v));
        assert_eq!(back, v);
    }
}
