//! A short-lived, loopback-only page that confirms Firefox has painted a tab.
//!
//! Loading or prefetching the page is not an acknowledgement. Its script waits
//! for a visible top-level document and two animation frames before posting the
//! per-launch token, then replaces this temporary history entry with the xite.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine as _;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
// Reuse the exact white mark displayed by the mobile startup splash.
const BRAND_PNG: &[u8] = include_bytes!("../../../shells/ios/EpixBrowser/epix-mark-white.png");

pub struct BrowserHandoff {
    url: String,
    acknowledgement: Option<oneshot::Receiver<()>>,
    shutdown: watch::Sender<bool>,
    // The task owns its graceful shutdown and bounded drain after Drop signals
    // cancellation. Aborting it immediately could cut off the POST response.
    _server: JoinHandle<()>,
}

impl BrowserHandoff {
    pub async fn start(target_url: String) -> Result<Self, String> {
        let target: Uri = target_url
            .split('#')
            .next()
            .unwrap_or_default()
            .parse()
            .map_err(|_| "invalid browser handoff target URL".to_string())?;
        if !matches!(target.scheme_str(), Some("http" | "https"))
            || target.authority().is_none()
            || target_url.chars().any(char::is_control)
        {
            return Err("browser handoff requires an absolute HTTP(S) target URL".to_string());
        }

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|error| format!("bind browser handoff: {error}"))?;
        let host = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .to_string();
        let origin = format!("http://{host}");
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let path = format!("/startup/{nonce}");
        let ack_path = format!("{path}/visible");
        let (ack_tx, ack_rx) = oneshot::channel();
        let state = Arc::new(HandoffState {
            host,
            origin: origin.clone(),
            html: render_page(&target_url, &ack_path, &nonce),
            csp: format!(
                "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; \
                 script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
                 connect-src 'self'; img-src data:; form-action 'none'"
            ),
            acknowledgement: Mutex::new(Some(ack_tx)),
        });
        let app = Router::new()
            .route(&path, get(page))
            .route(&ack_path, post(acknowledge))
            .with_state(state);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(serve(listener, app, shutdown_rx));
        Ok(Self {
            url: format!("{origin}{path}"),
            acknowledgement: Some(ack_rx),
            shutdown: shutdown_tx,
            _server: server_task,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Wait once for the page's visible acknowledgement. The caller owns the
    /// startup deadline; cancelling this future and dropping the handoff shuts
    /// down its listener as well.
    pub async fn wait(&mut self) -> Result<(), String> {
        self.acknowledgement
            .take()
            .ok_or_else(|| "browser handoff has already been awaited".to_string())?
            .await
            .map_err(|_| "browser handoff closed before acknowledgement".to_string())
    }
}

impl Drop for BrowserHandoff {
    fn drop(&mut self) {
        // Stop accepting connections, but let the acknowledgement response
        // drain. A stalled connection cannot keep the server alive past grace.
        let _ = self.shutdown.send(true);
    }
}

async fn serve(listener: TcpListener, app: Router, mut shutdown: watch::Receiver<bool>) {
    // Own every connection: axum::serve detaches connection tasks, which would
    // let a stalled request survive cancellation of this temporary listener.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait_for(|stop| *stop) => break,
            connection = listener.accept() => {
                let Ok((stream, _)) = connection else { break };
                let service = TowerToHyperService::new(app.clone());
                connections.spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {},
        }
    }
    drop(listener);
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    // JoinSet aborts any connections that did not drain within the deadline.
}

struct HandoffState {
    host: String,
    origin: String,
    html: String,
    csp: String,
    acknowledgement: Mutex<Option<oneshot::Sender<()>>>,
}

fn header_is(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    headers.get(name).and_then(|value| value.to_str().ok()) == Some(expected)
}

async fn page(State(state): State<Arc<HandoffState>>, headers: HeaderMap) -> Response {
    if !header_is(&headers, "host", &state.host) {
        return StatusCode::FORBIDDEN.into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_SECURITY_POLICY, state.csp.as_str()),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        state.html.clone(),
    )
        .into_response()
}

async fn acknowledge(State(state): State<Arc<HandoffState>>, headers: HeaderMap) -> Response {
    if !header_is(&headers, "host", &state.host)
        || !header_is(&headers, "origin", &state.origin)
        || (headers.contains_key("sec-fetch-site")
            && !header_is(&headers, "sec-fetch-site", "same-origin"))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state.acknowledgement.lock() {
        Ok(mut acknowledgement) => match acknowledgement.take() {
            Some(sender) => {
                let _ = sender.send(());
                (
                    StatusCode::NO_CONTENT,
                    [(header::CACHE_CONTROL, "no-store")],
                )
                    .into_response()
            }
            None => StatusCode::GONE.into_response(),
        },
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn script_string(value: &str) -> String {
    // JSON escaping alone permits </script>, which the HTML parser recognizes
    // even inside a JavaScript string. Escape HTML delimiters as well.
    serde_json::to_string(value)
        .expect("serializing a string cannot fail")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn render_page(target_url: &str, ack_path: &str, nonce: &str) -> String {
    let target = script_string(target_url);
    let acknowledgement = script_string(ack_path);
    let mark = base64::engine::general_purpose::STANDARD.encode(BRAND_PNG);
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Opening Epix Browser…</title>
<style nonce="{nonce}">
:root {{ color-scheme: dark; font-family: system-ui, sans-serif; }}
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0b0e14; color: #f8fafc; }}
main {{ text-align: center; padding: 32px; }}
.mark {{ display: block; width: 96px; height: 96px; margin: 0 auto 28px; }}
h1 {{ margin: 0; font-size: 24px; font-weight: 600; }}
p {{ margin: 12px 0 0; font-size: 14px; color: #94a3b8; }}
</style></head><body><main role="status"><img class="mark" width="96" height="96" src="data:image/png;base64,{mark}" alt="">
<h1>Opening Epix Browser…</h1><p>Your connection to EpixNet is ready.</p></main>
<script nonce="{nonce}">
(() => {{
  if (window.top !== window) return;
  const target = {target};
  const acknowledgement = {acknowledgement};
  let acknowledged = false;
  let visibilityCycle = 0;
  async function finish() {{
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    try {{
      // Firefox sends Origin:null for a same-origin-mode POST under the
      // page's no-referrer policy. CORS mode preserves its real Origin while
      // keeping referrers private; the URL and CSP remain same-origin only.
      await fetch(acknowledgement, {{method: "POST", mode: "cors", credentials: "omit", cache: "no-store", signal: controller.signal}});
    }} catch (_) {{
      // The browser can still open the xite if the ephemeral listener closed.
    }} finally {{
      clearTimeout(timeout);
      window.location.replace(target);
    }}
  }}
  function whenVisible() {{
    const cycle = ++visibilityCycle;
    if (acknowledged || document.visibilityState !== "visible") return;
    requestAnimationFrame(() => {{
      if (cycle !== visibilityCycle || document.visibilityState !== "visible") return;
      requestAnimationFrame(() => {{
        if (cycle !== visibilityCycle || acknowledged || document.visibilityState !== "visible") return;
        acknowledged = true;
        void finish();
      }});
    }});
  }}
  document.addEventListener("visibilitychange", whenVisible);
  whenVisible();
}})();
</script></body></html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn parts(handoff: &BrowserHandoff) -> (String, String) {
        let uri: Uri = handoff.url().parse().unwrap();
        (uri.authority().unwrap().to_string(), uri.path().to_string())
    }

    async fn request(host: &str, method: &str, path: &str, extra_headers: &str) -> String {
        request_with_host(host, host, method, path, extra_headers).await
    }

    async fn request_with_host(
        connection_host: &str,
        request_host: &str,
        method: &str,
        path: &str,
        extra_headers: &str,
    ) -> String {
        let mut stream = TcpStream::connect(connection_host).await.unwrap();
        stream
            .write_all(format!("{method} {path} HTTP/1.1\r\nHost: {request_host}\r\nConnection: close\r\nContent-Length: 0\r\n{extra_headers}\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        response
    }

    fn pending(handoff: &mut BrowserHandoff) {
        assert!(matches!(
            handoff.acknowledgement.as_mut().unwrap().try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn only_a_same_origin_post_with_the_current_token_acknowledges() {
        let mut handoff = BrowserHandoff::start("https://dashboard.epix/".to_string())
            .await
            .unwrap();
        let (host, path) = parts(&handoff);
        let origin = format!("Origin: http://{host}\r\n");
        let ack = format!("{path}/visible");
        let page = request(&host, "GET", &path, "").await;
        assert!(page.starts_with("HTTP/1.1 200"));
        assert!(page.contains("Opening Epix Browser…"));
        assert!(page.contains("content-security-policy: default-src 'none'"));
        assert!(page.contains("frame-ancestors 'none'"));
        assert!(page.contains("cache-control: no-store"));
        pending(&mut handoff);
        for (method, path, headers, status) in [
            ("GET", ack.as_str(), origin.as_str(), 405),
            ("OPTIONS", ack.as_str(), origin.as_str(), 405),
            ("POST", "/startup/wrong-token/visible", origin.as_str(), 404),
            ("POST", ack.as_str(), "", 403),
            (
                "POST",
                ack.as_str(),
                "Origin: https://untrusted.example\r\n",
                403,
            ),
        ] {
            assert!(request(&host, method, path, headers)
                .await
                .starts_with(&format!("HTTP/1.1 {status}")));
            pending(&mut handoff);
        }
        let cross_site = format!("{origin}Sec-Fetch-Site: cross-site\r\n");
        assert!(request(&host, "POST", &ack, &cross_site)
            .await
            .starts_with("HTTP/1.1 403"));
        pending(&mut handoff);
        assert!(
            request_with_host(&host, "untrusted.example", "GET", &path, "")
                .await
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            request_with_host(&host, "untrusted.example", "POST", &ack, &origin)
                .await
                .starts_with("HTTP/1.1 403")
        );
        pending(&mut handoff);
        let same_origin = format!("{origin}Sec-Fetch-Site: same-origin\r\n");
        assert!(request(&host, "POST", &ack, &same_origin)
            .await
            .starts_with("HTTP/1.1 204"));
        tokio::time::timeout(Duration::from_secs(1), handoff.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(request(&host, "POST", &ack, &same_origin)
            .await
            .starts_with("HTTP/1.1 410"));
        assert!(handoff.wait().await.is_err());
    }

    #[tokio::test]
    async fn a_token_from_another_launch_cannot_acknowledge() {
        let first = BrowserHandoff::start("https://first.epix/".to_string())
            .await
            .unwrap();
        let mut second = BrowserHandoff::start("https://second.epix/".to_string())
            .await
            .unwrap();
        let (_, old_path) = parts(&first);
        let (host, path) = parts(&second);
        assert_ne!(old_path, path);
        let response = request(
            &host,
            "POST",
            &format!("{old_path}/visible"),
            &format!("Origin: http://{host}\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 404"));
        pending(&mut second);
    }

    async fn assert_closed(host: &str) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while TcpStream::connect(host).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("dropping a handoff must close its listener");
    }

    #[tokio::test]
    async fn dropping_after_acknowledgement_drains_the_response_and_closes_the_listener() {
        let mut handoff = BrowserHandoff::start("https://dashboard.epix/".to_string())
            .await
            .unwrap();
        let (host, path) = parts(&handoff);
        let mut stream = TcpStream::connect(&host).await.unwrap();
        stream.write_all(format!("POST {path}/visible HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), handoff.wait())
            .await
            .unwrap()
            .unwrap();
        drop(handoff);
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 204"), "{response}");
        assert_closed(&host).await;
    }

    #[tokio::test]
    async fn dropping_without_an_acknowledgement_closes_the_listener() {
        let handoff = BrowserHandoff::start("https://dashboard.epix/".to_string())
            .await
            .unwrap();
        let (host, _) = parts(&handoff);
        drop(handoff);
        assert_closed(&host).await;
    }

    #[tokio::test]
    async fn dropping_also_closes_a_stalled_connection_within_the_grace_period() {
        let handoff = BrowserHandoff::start("https://dashboard.epix/".to_string())
            .await
            .unwrap();
        let (host, _) = parts(&handoff);
        let mut stream = TcpStream::connect(&host).await.unwrap();
        stream.write_all(b"POST /startup/").await.unwrap();
        // Establish that the listener has processed another connection before
        // dropping, rather than only testing an unaccepted socket.
        assert!(request(&host, "GET", "/missing", "")
            .await
            .starts_with("HTTP/1.1 404"));
        drop(handoff);
        assert_closed(&host).await;
        let mut byte = [0];
        let result = tokio::time::timeout(
            SHUTDOWN_GRACE + Duration::from_secs(1),
            stream.read(&mut byte),
        )
        .await;
        assert!(
            matches!(result, Ok(Ok(0)) | Ok(Err(_))),
            "stalled connection survived handoff: {result:?}"
        );
    }

    #[tokio::test]
    async fn refuses_executable_or_relative_target_urls() {
        for target in [
            "javascript:alert(1)",
            "data:text/html,hello",
            "/relative",
            "https://dashboard.epix/\n",
        ] {
            assert!(
                BrowserHandoff::start(target.to_string()).await.is_err(),
                "{target}"
            );
        }
    }

    #[test]
    fn target_serialization_cannot_end_the_script_element() {
        let target = "https://dashboard.epix/#</script><script>bad()</script>&\"\u{2028}\u{2029}";
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let html = render_page(target, "/startup/token/visible", &nonce);
        assert_eq!(html.matches("</script>").count(), 1);
        assert!(!html.contains("<script>bad()"));
        assert!(html.contains("\\u003c/script\\u003e"));
        assert!(html.contains("\\u2028\\u2029"));
    }

    #[test]
    fn browser_script_waits_for_visible_paint_and_redirects_even_if_ack_fails() {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let html = render_page(
            "https://dashboard.epix/#ready",
            "/startup/token/visible",
            &nonce,
        );
        let script_tag = format!("<script nonce=\"{nonce}\">\n");
        let script = html
            .split(&script_tag)
            .nth(1)
            .unwrap()
            .split("</script>")
            .next()
            .unwrap();
        let harness = r#"
const assert = require('node:assert/strict');
const vm = require('node:vm');
function fixture({visible = false, frame = false, failure = false, stalled = false} = {}) {
  const frames = [], calls = [], replacements = [], timers = new Map();
  let visibility;
  const window = {location: {replace: value => replacements.push(value)}};
  window.top = frame ? {} : window;
  const document = {visibilityState: visible ? 'visible' : 'hidden', addEventListener: (name, fn) => {assert.equal(name, 'visibilitychange'); visibility = fn;}};
  vm.runInNewContext(process.env.HANDOFF_SCRIPT, {window, document, AbortController,
    requestAnimationFrame: fn => frames.push(fn),
    setTimeout: fn => {timers.set(1, fn); return 1;}, clearTimeout: id => timers.delete(id),
    fetch: (url, options) => {calls.push({url, options}); return stalled
      ? new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('timeout'))))
      : failure ? Promise.reject(new Error('server closed')) : Promise.resolve({ok:true});}
  });
  return {frames, calls, replacements, timers, setVisible(value) {document.visibilityState = value ? 'visible' : 'hidden'; visibility();}};
}
(async () => {
  const hidden = fixture();
  assert.equal(hidden.frames.length, 0); assert.equal(hidden.calls.length, 0);
  hidden.setVisible(true); hidden.frames.shift()();
  assert.equal(hidden.calls.length, 0, 'one frame is not enough');
  hidden.setVisible(false); hidden.frames.shift()();
  assert.equal(hidden.calls.length, 0, 'a hidden document cannot acknowledge');
  hidden.setVisible(true); hidden.frames.shift()(); hidden.frames.shift()();
  await new Promise(setImmediate);
  assert.equal(hidden.calls.length, 1); assert.equal(hidden.calls[0].options.method, 'POST');
  assert.equal(hidden.calls[0].options.mode, 'cors', 'Firefox must retain Origin under no-referrer');
  assert.deepEqual(hidden.replacements, ['https://dashboard.epix/#ready']);
  hidden.setVisible(true); assert.equal(hidden.frames.length, 0, 'acknowledge once');
  const frame = fixture({visible: true, frame: true}); assert.equal(frame.frames.length, 0);
  for (const options of [{failure:true}, {stalled:true}]) {
    const test = fixture({visible:true, ...options}); test.frames.shift()(); test.frames.shift()();
    if (options.stalled) test.timers.get(1)();
    await new Promise(setImmediate);
    assert.deepEqual(test.replacements, ['https://dashboard.epix/#ready']);
    assert.equal(test.timers.size, 0);
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
"#;
        let output = match std::process::Command::new("node")
            .args(["-e", harness])
            .env("HANDOFF_SCRIPT", script)
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("Node.js is unavailable; skipping the optional browser-script VM check");
                return;
            }
            Err(error) => panic!("run browser-script VM check: {error}"),
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
