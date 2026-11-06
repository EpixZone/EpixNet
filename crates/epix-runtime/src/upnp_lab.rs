//! Run only through scripts/run-upnp-lab.py. The real runtime discovers a real
//! IGD and changes a disposable router's firewall inside Linux namespaces.
//! Only the public dial-back service and long renewal interval are substituted.

use super::{portcheck::PortCheck, AppState};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

const PORT: u16 = 42424;
const EXTERNAL_IP: &str = "192.0.2.1";
const PROBE_URL: &str = "http://192.0.2.2:42425/check";
const CHALLENGE: &[u8] = b"EPIX-UPNP-LAB\n";
const ANSWER: &[u8] = b"EPIX-UPNP-OK\n";

fn isolated_case() -> String {
    assert_eq!(
        std::env::var("EPIX_UPNP_LAB").as_deref(),
        Ok("1"),
        "use the isolated lab runner"
    );
    let host =
        std::env::var("EPIX_UPNP_LAB_HOST_NETNS").expect("runner must record the host namespace");
    let current = std::fs::read_link("/proc/self/ns/net").expect("Linux network namespace");
    assert_ne!(
        current.to_string_lossy(),
        host,
        "never discover UPnP on the host network"
    );
    assert_eq!(
        std::env::var("EPIX_UPNP_LAB_PROBE_URL").as_deref(),
        Ok(PROBE_URL),
        "only the isolated outside-probe endpoint is permitted"
    );
    let case = std::env::var("EPIX_UPNP_LAB_CASE").expect("runner must select a case");
    assert!(matches!(
        case.as_str(),
        "mapped"
            | "unmapped"
            | "static-forward"
            | "manual-override"
            | "tor-always"
            | "mapped-filtered"
    ));
    case
}

async fn dialback(client: &reqwest::Client) -> PortCheck {
    let response = client
        .get(PROBE_URL)
        .query(&[("port", PORT)])
        .send()
        .await
        .expect("isolated outside probe is running")
        .error_for_status()
        .expect("outside probe returned a successful response");
    let body: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(body["ip"], EXTERNAL_IP);
    PortCheck {
        ip: EXTERNAL_IP.into(),
        opened: body["open"].as_bool().expect("boolean probe verdict"),
    }
}

async fn echo_service() -> tokio::task::JoinHandle<()> {
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", PORT))
        .await
        .unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(2), async {
                    let mut challenge = [0; CHALLENGE.len()];
                    socket.read_exact(&mut challenge).await?;
                    if challenge == CHALLENGE {
                        socket.write_all(ANSWER).await?;
                    }
                    std::io::Result::Ok(())
                })
                .await;
            });
        }
    })
}

async fn await_observation(
    state: &Arc<AppState>,
    runtime: &tokio::task::JoinHandle<()>,
    probes: &Mutex<Vec<PortCheck>>,
    case: &str,
) {
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            let calls = probes.lock().unwrap().len();
            let opened = state.port_status().await.0;
            let ready = match case {
                "mapped" => opened && calls == 2,
                "mapped-filtered" => !opened && calls == 2,
                "static-forward" => opened && calls == 1,
                "manual-override" => opened && calls == 0,
                "unmapped" | "tor-always" => runtime.is_finished(),
                _ => unreachable!(),
            };
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("runtime reached the expected observable phase");
}

fn verdict_json(verdict: &PortCheck) -> Value {
    json!({"ip": verdict.ip, "open": verdict.opened})
}

#[tokio::test]
#[ignore = "requires the isolated Linux router lab runner; never run on the host network"]
async fn isolated_router_reachability() {
    let case = isolated_case();
    let echo = echo_service().await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let before = dialback(&client).await;
    let state = AppState::new("isolated-upnp-lab");
    if case == "manual-override" {
        state.config_set("ip_external", json!(EXTERNAL_IP)).await;
    }
    let probes = Arc::new(Mutex::new(Vec::new()));
    let probe_log = probes.clone();
    let probe_client = client.clone();
    let shutdown = Arc::new(Notify::new());
    let runtime = tokio::spawn(super::upnp_loop_with_probe(
        state.clone(),
        PORT,
        case != "tor-always",
        shutdown.clone(),
        super::local_ipv4,
        move |port| {
            assert_eq!(port, PORT);
            let probe_log = probe_log.clone();
            let client = probe_client.clone();
            async move {
                let verdict = dialback(&client).await;
                probe_log.lock().unwrap().push(verdict.clone());
                Some(verdict)
            }
        },
        Duration::from_secs(2),
    ));
    await_observation(&state, &runtime, &probes, &case).await;
    // With a mapping, exercise real AddPortMapping renewals. The lease remains
    // 3600 seconds; only the wait is shorter. The daemon log and nft snapshots
    // are independently inspected by the runner, including the WAN-drop case.
    if matches!(case.as_str(), "mapped" | "mapped-filtered") {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let active_status = state.port_status().await;
    let active = dialback(&client).await;
    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(15), runtime)
        .await
        .unwrap()
        .unwrap();
    let final_status = state.port_status().await;
    let after = dialback(&client).await;
    echo.abort();
    let probe_results = probes.lock().unwrap().clone();
    let result = json!({
        "case": case,
        "before": verdict_json(&before),
        "active": verdict_json(&active),
        "after_shutdown": verdict_json(&after),
        "runtime_active": {"open": active_status.0, "ip": active_status.1},
        "runtime_shutdown": {"open": final_status.0, "ip": final_status.1},
        "runtime_probes": probe_results.iter().map(verdict_json).collect::<Vec<_>>(),
        "lease_seconds": 3600,
        "refresh_seconds": 2,
    });
    let result_path = std::env::var("EPIX_UPNP_LAB_RESULT").expect("runner result path");
    tokio::fs::write(result_path, serde_json::to_vec_pretty(&result).unwrap())
        .await
        .unwrap();
    println!("{result}");

    assert_eq!(before.opened, case == "static-forward");
    assert_eq!(
        active.opened,
        matches!(case.as_str(), "mapped" | "static-forward")
    );
    assert_eq!(
        after.opened,
        case == "static-forward",
        "UPnP cleanup must remove only its own mapping"
    );
    assert_eq!(
        active_status.0,
        matches!(
            case.as_str(),
            "mapped" | "static-forward" | "manual-override"
        ),
        "a configured address currently assumes reachability without probing"
    );
    assert!(!final_status.0);
    let expected_probes = match case.as_str() {
        "mapped" | "mapped-filtered" => 2,
        "static-forward" | "unmapped" => 1,
        _ => 0,
    };
    assert_eq!(
        probe_results.len(),
        expected_probes,
        "renewals reuse the first verified verdict"
    );
}

#[tokio::test]
async fn configured_address_is_trusted_without_network_inspection() {
    let state = AppState::new("configured-ip-test");
    state.config_set("ip_external", json!(EXTERNAL_IP)).await;
    let resolved = super::resolve_direct_port_status(
        &state,
        PORT,
        &|| panic!("configured address must not inspect local routes"),
        &|_| -> std::future::Ready<Option<PortCheck>> {
            panic!("configured address must not call the external checker")
        },
    )
    .await;
    assert!(resolved);
    assert_eq!(state.port_status().await, (true, Some(EXTERNAL_IP.into())));
}
