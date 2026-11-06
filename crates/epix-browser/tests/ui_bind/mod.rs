use super::browser_ui_addr;

#[test]
fn managed_browser_accepts_loopback_ports_and_address_families() {
    for value in ["127.0.0.1:42222", "127.0.0.1:42301", "[::1]:42301", "127.0.0.1:0"] {
        assert_eq!(browser_ui_addr(value).unwrap().to_string(), value);
    }
}

#[test]
fn managed_browser_rejects_public_listeners_before_boot() {
    for value in ["0.0.0.0:42222", "[::]:42222", "192.168.1.10:42222"] {
        let error = browser_ui_addr(value).unwrap_err();
        assert!(error.contains("loopback"));
        assert!(error.contains("--browser system"));
    }
    assert!(browser_ui_addr("invalid").unwrap_err().contains("Invalid UI address"));
}
