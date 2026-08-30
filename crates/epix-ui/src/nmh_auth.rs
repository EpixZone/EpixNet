use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const REQUEST_DOMAIN: &[u8] = b"EpixNet NMH resolve request v1\0";
const RESPONSE_DOMAIN: &[u8] = b"EpixNet NMH resolve response v1\0";

fn mac(token: &str, domain: &[u8]) -> Result<HmacSha256, String> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("native-messaging token is malformed".to_string());
    }
    let mut mac = HmacSha256::new_from_slice(token.as_bytes())
        .map_err(|_| "native-messaging token is invalid".to_string())?;
    mac.update(domain);
    Ok(mac)
}

fn update_field(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

fn request_authenticator(token: &str, nonce: &str, name: &str) -> Result<HmacSha256, String> {
    if nonce.len() != 64 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("native-messaging request nonce is malformed".to_string());
    }
    let mut mac = mac(token, REQUEST_DOMAIN)?;
    update_field(&mut mac, nonce.as_bytes());
    update_field(&mut mac, name.as_bytes());
    Ok(mac)
}

fn response_authenticator(
    token: &str,
    nonce: &str,
    name: &str,
    status: u16,
    address: Option<&str>,
    error: Option<&str>,
) -> Result<HmacSha256, String> {
    if nonce.len() != 64 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("native-messaging response nonce is malformed".to_string());
    }
    let mut mac = mac(token, RESPONSE_DOMAIN)?;
    update_field(&mut mac, nonce.as_bytes());
    update_field(&mut mac, name.as_bytes());
    mac.update(&status.to_be_bytes());
    match address {
        Some(address) => {
            mac.update(&[1]);
            update_field(&mut mac, address.as_bytes());
        }
        None => mac.update(&[0]),
    }
    match error {
        Some(error) => {
            mac.update(&[1]);
            update_field(&mut mac, error.as_bytes());
        }
        None => mac.update(&[0]),
    }
    Ok(mac)
}

fn verify_hex(mac: HmacSha256, claimed: &str) -> bool {
    let Ok(claimed) = hex::decode(claimed) else {
        return false;
    };
    mac.verify_slice(&claimed).is_ok()
}

/// Generate a fresh request nonce for one native-messaging resolve call.
pub fn new_nmh_nonce() -> Result<String, String> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|error| format!("operating-system randomness failed: {error}"))?;
    Ok(hex::encode(nonce))
}

/// Authenticate one resolve request without sending the per-run secret.
pub fn nmh_request_mac(token: &str, nonce: &str, name: &str) -> Result<String, String> {
    Ok(hex::encode(
        request_authenticator(token, nonce, name)?
            .finalize()
            .into_bytes(),
    ))
}

/// Verify a native-messaging resolve request in constant time.
pub fn nmh_request_mac_valid(token: &str, nonce: &str, name: &str, claimed: &str) -> bool {
    request_authenticator(token, nonce, name)
        .map(|mac| verify_hex(mac, claimed))
        .unwrap_or(false)
}

/// Authenticate the exact HTTP status and payload returned for a request.
pub fn nmh_response_mac(
    token: &str,
    nonce: &str,
    name: &str,
    status: u16,
    address: Option<&str>,
    error: Option<&str>,
) -> Result<String, String> {
    Ok(hex::encode(
        response_authenticator(token, nonce, name, status, address, error)?
            .finalize()
            .into_bytes(),
    ))
}

/// Verify a native-messaging resolve response in constant time.
pub fn nmh_response_mac_valid(
    token: &str,
    nonce: &str,
    name: &str,
    status: u16,
    address: Option<&str>,
    error: Option<&str>,
    claimed: &str,
) -> bool {
    response_authenticator(token, nonce, name, status, address, error)
        .map(|mac| verify_hex(mac, claimed))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_response_are_bound_to_every_field() {
        let token = "11".repeat(32);
        let nonce = "22".repeat(32);
        let request = nmh_request_mac(&token, &nonce, "talk.epix").unwrap();
        assert!(nmh_request_mac_valid(&token, &nonce, "talk.epix", &request));
        assert!(!nmh_request_mac_valid(
            &token,
            &nonce,
            "other.epix",
            &request
        ));

        let response = nmh_response_mac(
            &token,
            &nonce,
            "talk.epix",
            200,
            Some("epix1verified"),
            None,
        )
        .unwrap();
        assert!(nmh_response_mac_valid(
            &token,
            &nonce,
            "talk.epix",
            200,
            Some("epix1verified"),
            None,
            &response,
        ));
        assert!(!nmh_response_mac_valid(
            &token,
            &nonce,
            "talk.epix",
            200,
            Some("epix1forged"),
            None,
            &response,
        ));
    }
}
