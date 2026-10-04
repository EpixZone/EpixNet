#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > evx_api::MAX_MODULE {
        return;
    }
    if let Ok(summary) = evx_runtime::validate_module(data) {
        assert!(data.starts_with(b"\0asm\x01\0\0\0"));
        assert!(summary
            .imports
            .iter()
            .all(|(module, name)| module == "evx" && name == "call"));
        assert!(summary.exports.iter().any(|name| name == "run"));
        assert!(summary.exports.iter().any(|name| name == "memory"));
    }
});
