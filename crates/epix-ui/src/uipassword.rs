//! UiPassword - a cookie-session login gate over the whole UI.
//!
//! Mirrors EpixNet's `UiPassword` plugin: when the operator sets a UI password
//! (config `ui_password`), every HTTP request must carry a valid `session_id`
//! cookie or it is shown a login page. Posting the correct password mints a
//! session and sets the cookie. Sessions live in memory only (like the Python
//! plugin's module-global `sessions` dict), so a restart logs everyone out.
//!
//! Feature-gated behind `ui-password` and off by default / on mobile, where the
//! UI is already local to the device.

use std::collections::HashSet;
use std::sync::{OnceLock, RwLock};

/// In-memory set of valid session ids (mirrors the Python module-global dict).
fn sessions() -> &'static RwLock<HashSet<String>> {
    static S: OnceLock<RwLock<HashSet<String>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(HashSet::new()))
}

/// A 26-char alphanumeric session id, matching the reference `randomString(26)`.
pub fn random_session_id() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = [0u8; 26];
    getrandom::getrandom(&mut buf).expect("os randomness");
    buf.iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect()
}

/// Mint a new session and return its id.
pub fn session_create() -> String {
    let id = random_session_id();
    sessions().write().unwrap().insert(id.clone());
    id
}

/// Whether `id` is a live session.
pub fn session_valid(id: &str) -> bool {
    !id.is_empty() && sessions().read().unwrap().contains(id)
}

/// Drop a session (logout).
pub fn session_delete(id: &str) {
    sessions().write().unwrap().remove(id);
}

/// Read the `session_id` value from a request's `Cookie` header.
pub fn cookie_session_id(cookie_header: Option<&str>) -> String {
    let Some(header) = cookie_header else { return String::new() };
    for part in header.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("session_id=") {
            return val.to_string();
        }
    }
    String::new()
}

/// The login page. `bad_password` shakes the field red after a wrong attempt.
pub fn login_html(bad_password: bool) -> String {
    let result = if bad_password { "bad_password" } else { "" };
    LOGIN_HTML.replace("{result}", result)
}

const LOGIN_HTML: &str = r#"<html>
<head>
 <title>Log In</title>
 <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<style>
body { background-color: #09090A; font-family: Inter, -apple-system, "Segoe UI", Roboto, sans-serif; font-size: 16px; color: #F6F6F9; overflow: hidden; margin: 0; }
.login { left: 50%; position: absolute; top: 50%; transform: translateX(-50%) translateY(-50%); width: calc(100% - 32px); max-width: 400px; text-align: center; background-color: #151517; border: 1px solid #2E2E32; border-radius: 12px; padding: 40px 28px; box-sizing: border-box; }
*:focus { outline: 0; }
input[type=password] { padding: 12px 16px; display: block; margin: 0; width: 100%; border-radius: 8px; transition: border-color 0.2s ease-out; background-color: #242428; text-align: center; font-family: inherit; font-size: 16px; border: 1px solid #404045; color: #F6F6F9; box-sizing: border-box; }
input[type=password]::placeholder { color: #ABABB5; }
input[type=password]:focus { border-color: #69E9F5; }
input.error { border-color: #F0224B !important; animation: shake 1s }
.button { padding: 0; display: inline-block; margin: 20px 0 0; width: 100%; height: 44px; line-height: 44px; border-radius: 8px; text-align: center; white-space: nowrap; font-size: 16px; font-weight: 600; font-family: inherit; background: #8A4BDB; box-sizing: border-box; color: #FEFEFE; text-decoration: none; transition: box-shadow 0.2s ease-out; border: 0; cursor: pointer; }
.button:hover, .button:focus { box-shadow: 0 1px 3px rgba(2,2,2,0.12); }
.button:active { transform: translateY(1px); transition: none; }
@keyframes shake { 0%, 100% { transform: translateX(0); } 10%, 30%, 50%, 70%, 90% { transform: translateX(-10px); } 20%, 40%, 60%, 80% { transform: translateX(10px); } }
</style>
<body>
<div class="login">
 <form action="/Login" method="post">
  <input type="password" name="password" placeholder="Password" class="{result}" required autofocus/>
  <button type="submit" class="button">Log In</button>
 </form>
</div>
<script>
if ("{result}" == "bad_password") { document.querySelector("input").className = "error"; }
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_lifecycle() {
        let id = session_create();
        assert!(session_valid(&id));
        session_delete(&id);
        assert!(!session_valid(&id));
        assert!(!session_valid(""));
    }

    #[test]
    fn parses_session_cookie() {
        assert_eq!(cookie_session_id(Some("a=1; session_id=xyz; b=2")), "xyz");
        assert_eq!(cookie_session_id(Some("session_id=abc")), "abc");
        assert_eq!(cookie_session_id(None), "");
        assert_eq!(cookie_session_id(Some("other=1")), "");
    }

    #[test]
    fn random_ids_are_26_chars_and_distinct() {
        let a = random_session_id();
        let b = random_session_id();
        assert_eq!(a.len(), 26);
        assert_ne!(a, b);
    }
}
