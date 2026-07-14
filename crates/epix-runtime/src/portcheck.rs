//! Ask a public port-scan service to connect to our fileserver port and
//! take BOTH the open/closed verdict and our external IP from its response,
//! the IP the internet actually sees, which no amount of local interface
//! inspection can tell us.
//!
//! The services are tried in order until one gives a definitive answer.
//! Parsing is deliberately the same loose substring matching the Python
//! client used, against the same endpoints.

/// One service's dial-back verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortCheck {
    /// Our external IP as the service saw it.
    pub ip: String,
    /// Whether the service could connect to `ip:port` from the internet.
    pub opened: bool,
}

fn client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) \
             Chrome/23.0.1271.64 Safari/537.11",
        )
        .build()
        .ok()
}

/// Strip HTML tags and entity spaces, like the Python checker's cleanup.
fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.replace("<br>", " ").replace("&nbsp;", " ").chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// The text between `start` (exclusive) and the next `end`, if both exist.
fn between<'a>(hay: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let s = hay.find(start)? + start.len();
    let e = hay[s..].find(end)? + s;
    Some(&hay[s..e])
}

/// Parse a canyouseeme.org response body. The message looks like
/// `Success: I can see your service on 1.2.3.4 on port (26552)` or
/// `Error: I could not see your service on 1.2.3.4 on port (26552)`.
pub(crate) fn parse_canyouseeme(body: &str) -> Option<PortCheck> {
    let message = between(body, r#"<p style="padding-left:15px">"#, "</p>")?;
    let message = strip_tags(message);
    let ip = between(&message, "service on ", " on ")?.trim().to_string();
    if ip.is_empty() {
        return None;
    }
    if message.contains("Success") {
        Some(PortCheck { ip, opened: true })
    } else if message.contains("Error") {
        Some(PortCheck { ip, opened: false })
    } else {
        None
    }
}

async fn check_canyouseeme(client: &reqwest::Client, port: u16) -> Option<PortCheck> {
    let body = client
        .post("https://www.canyouseeme.org/")
        .header(reqwest::header::REFERER, "https://www.canyouseeme.org/")
        .body(format!("ip=1.1.1.1&port={port}"))
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    parse_canyouseeme(&body)
}

/// Extract the visitor IP ipfingerprints.com pre-fills into its scan form.
pub(crate) fn parse_ipfingerprints_ip(body: &str) -> Option<String> {
    let after = &body[body.find("name=\"remoteHost\"")?..];
    let ip = between(after, "value=\"", "\"")?.trim().to_string();
    (!ip.is_empty()).then_some(ip)
}

/// Map an ipfingerprints.com scan result to a verdict, Python-style: any
/// mention of `filtered`/`closed` beats `open` (its output for a filtered
/// port can be phrased either way).
pub(crate) fn parse_ipfingerprints_verdict(message: &str, ip: String) -> Option<PortCheck> {
    if message.contains("filtered") || message.contains("closed") {
        Some(PortCheck { ip, opened: false })
    } else if message.contains("open") {
        Some(PortCheck { ip, opened: true })
    } else {
        None
    }
}

async fn check_ipfingerprints(client: &reqwest::Client, port: u16) -> Option<PortCheck> {
    let form_page = client
        .get("https://www.ipfingerprints.com/portscan.php")
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let ip = parse_ipfingerprints_ip(&form_page)?;
    let port = port.to_string();
    let message = client
        .post("https://www.ipfingerprints.com/scripts/getPortsInfo.php")
        .header(reqwest::header::REFERER, "https://www.ipfingerprints.com/portscan.php")
        .form(&[
            ("remoteHost", ip.as_str()),
            ("start_port", port.as_str()),
            ("end_port", port.as_str()),
            ("normalScan", "Yes"),
            ("scan_type", "connect2"),
            ("ping_type", "none"),
        ])
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    parse_ipfingerprints_verdict(&message, ip)
}

/// Ask the check services, in order, whether `port` is reachable from the
/// internet. `None` means no service could be reached or parsed - reachability
/// is UNKNOWN, not closed.
pub async fn port_check(port: u16) -> Option<PortCheck> {
    let client = client()?;
    if let Some(res) = check_canyouseeme(&client, port).await {
        return Some(res);
    }
    check_ipfingerprints(&client, port).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canyouseeme_closed() {
        // A real response body (captured 2026-07): filtered port.
        let body = r#"...<p style="padding-left:15px"><font color="red"><b>Error:</b></font>&nbsp;I could <b>not</b> see your service on <b>136.36.77.130</b> on port (<b>26552</b>)<br>Reason:<small>&nbsp;Connection timed out</small></p>..."#;
        assert_eq!(
            parse_canyouseeme(body),
            Some(PortCheck { ip: "136.36.77.130".into(), opened: false })
        );
    }

    #[test]
    fn parses_canyouseeme_open() {
        let body = r#"<p style="padding-left:15px"><b>Success:</b> I can see your service on <b>74.208.249.9</b> on port (<b>26552</b>)<br>Your ISP is not blocking port 26552</p>"#;
        assert_eq!(
            parse_canyouseeme(body),
            Some(PortCheck { ip: "74.208.249.9".into(), opened: true })
        );
    }

    #[test]
    fn canyouseeme_garbage_is_unknown_not_closed() {
        assert_eq!(parse_canyouseeme("<html>maintenance</html>"), None);
        assert_eq!(parse_canyouseeme(r#"<p style="padding-left:15px">???</p>"#), None);
    }

    #[test]
    fn parses_ipfingerprints() {
        let form = r#"<input type="text" name="remoteHost" maxlength="50" value="136.36.77.130" class="textinput">"#;
        assert_eq!(parse_ipfingerprints_ip(form), Some("136.36.77.130".into()));

        let ip = || "136.36.77.130".to_string();
        assert_eq!(
            parse_ipfingerprints_verdict("26552/tcp open  unknown", ip()),
            Some(PortCheck { ip: ip(), opened: true })
        );
        assert_eq!(
            parse_ipfingerprints_verdict("26552/tcp filtered unknown", ip()),
            Some(PortCheck { ip: ip(), opened: false })
        );
        assert_eq!(parse_ipfingerprints_verdict("scan failed", ip()), None);
    }
}
