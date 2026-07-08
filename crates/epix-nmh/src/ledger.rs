//! Ledger hardware wallet over raw HID.
//!
//! Firefox, GeckoView, and WKWebView do not implement WebHID/WebUSB (they are
//! Chromium-only), so Keplr's Ledger flow cannot reach the device from the
//! wallet UI. The Epix wallet instead bridges each APDU to this native host,
//! which talks to the device directly and implements the Ledger HID framing
//! here.
//!
//! The host is spawned fresh per `sendNativeMessage`, so there is no persistent
//! device handle: each `exchange` opens the device, runs one APDU, and closes.
//! That is fine because a Ledger APDU is a complete request/response at the
//! transport layer - the app's signing state lives on the device, not on the
//! HID connection - so opening and closing between APDUs does not lose context.

use hidapi::{HidApi, HidDevice};
use serde_json::{json, Value};

/// Ledger's USB vendor id.
const LEDGER_VID: u16 = 0x2c97;
/// The APDU interface's HID usage page (Ledger exposes several interfaces;
/// only this one speaks the APDU protocol).
const APDU_USAGE_PAGE: u16 = 0xffa0;
/// Ledger HID framing constants.
const CHANNEL: u16 = 0x0101;
const TAG: u8 = 0x05;
const PACKET: usize = 64;
/// Read timeout per frame. Long, because the signing APDU only returns after
/// the user confirms on the device.
const READ_TIMEOUT_MS: i32 = 60_000;

/// `{"cmd":"ledgerList"}` -> `{ devices: [{ path, product }] }`. Empty when no
/// Ledger is connected. Used by the wallet to decide the device is present.
pub fn list() -> Value {
    let api = match HidApi::new() {
        Ok(a) => a,
        Err(e) => return json!({ "error": format!("hidapi: {e}") }),
    };
    let devices: Vec<Value> = api
        .device_list()
        .filter(|d| d.vendor_id() == LEDGER_VID && d.usage_page() == APDU_USAGE_PAGE)
        .map(|d| {
            json!({
                "path": d.path().to_string_lossy(),
                "product": d.product_string().unwrap_or(""),
            })
        })
        .collect();
    json!({ "devices": devices })
}

/// `{"cmd":"ledgerExchange","apdu":"<hex>","path":"<optional>"}` ->
/// `{ response: "<hex>" }` (the device reply, status word included) or
/// `{ error: "..." }`. `path` selects a specific device from `list`; without
/// it the first Ledger APDU interface is used.
pub fn exchange(req: &Value) -> Value {
    let apdu = match req.get("apdu").and_then(|v| v.as_str()).map(decode_hex) {
        Some(Ok(a)) => a,
        Some(Err(e)) => return json!({ "error": format!("bad apdu hex: {e}") }),
        None => return json!({ "error": "missing apdu" }),
    };
    let api = match HidApi::new() {
        Ok(a) => a,
        Err(e) => return json!({ "error": format!("hidapi: {e}") }),
    };
    let device = match open_device(&api, req.get("path").and_then(|v| v.as_str())) {
        Ok(d) => d,
        Err(e) => return json!({ "error": e }),
    };
    match transceive(&device, &apdu) {
        Ok(resp) => json!({ "response": encode_hex(&resp) }),
        Err(e) => json!({ "error": e }),
    }
}

fn open_device(api: &HidApi, path: Option<&str>) -> Result<HidDevice, String> {
    if let Some(path) = path {
        let cpath = std::ffi::CString::new(path).map_err(|_| "bad device path".to_string())?;
        return api.open_path(&cpath).map_err(|e| format!("open {path}: {e}"));
    }
    let info = api
        .device_list()
        .find(|d| d.vendor_id() == LEDGER_VID && d.usage_page() == APDU_USAGE_PAGE)
        .ok_or_else(|| "no Ledger device connected".to_string())?;
    api.open_path(info.path()).map_err(|e| format!("open device: {e}"))
}

/// Write one APDU and read its response, using the Ledger HID framing:
/// a 2-byte big-endian length prefix over the APDU, split into 64-byte
/// packets each headed by channel (2), tag (1), and a big-endian sequence
/// number (2).
fn transceive(device: &HidDevice, apdu: &[u8]) -> Result<Vec<u8>, String> {
    write_apdu(device, apdu).map_err(|e| format!("write: {e}"))?;
    read_apdu(device).map_err(|e| format!("read: {e}"))
}

fn write_apdu(device: &HidDevice, apdu: &[u8]) -> Result<(), String> {
    let mut payload = Vec::with_capacity(2 + apdu.len());
    payload.extend_from_slice(&(apdu.len() as u16).to_be_bytes());
    payload.extend_from_slice(apdu);

    let mut seq: u16 = 0;
    let mut offset = 0;
    while offset < payload.len() {
        let mut frame = Vec::with_capacity(PACKET);
        frame.extend_from_slice(&CHANNEL.to_be_bytes());
        frame.push(TAG);
        frame.extend_from_slice(&seq.to_be_bytes());
        let take = (PACKET - frame.len()).min(payload.len() - offset);
        frame.extend_from_slice(&payload[offset..offset + take]);
        frame.resize(PACKET, 0);

        // hidapi expects a leading report-id byte (0 = no numbered report).
        let mut report = Vec::with_capacity(PACKET + 1);
        report.push(0x00);
        report.extend_from_slice(&frame);
        device.write(&report).map_err(|e| e.to_string())?;

        offset += take;
        seq += 1;
    }
    Ok(())
}

fn read_apdu(device: &HidDevice) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; PACKET];
    let mut response: Vec<u8> = Vec::new();
    let mut expected: Option<usize> = None;
    let mut seq: u16 = 0;

    loop {
        let n = device
            .read_timeout(&mut buf, READ_TIMEOUT_MS)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("timed out waiting for the device".to_string());
        }
        if buf[0..2] != CHANNEL.to_be_bytes() || buf[2] != TAG {
            return Err("unexpected HID frame".to_string());
        }
        if buf[3..5] != seq.to_be_bytes() {
            return Err("out-of-order HID frame".to_string());
        }

        let mut idx = 5;
        if seq == 0 {
            expected = Some(u16::from_be_bytes([buf[5], buf[6]]) as usize);
            idx = 7;
        }
        let want = expected.ok_or("no length in first frame")?;
        let take = (PACKET - idx).min(want - response.len());
        response.extend_from_slice(&buf[idx..idx + take]);
        if response.len() >= want {
            break;
        }
        seq += 1;
    }
    Ok(response)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
