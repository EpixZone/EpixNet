#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let parsed = evx_declaration::parse_bytes(data);
    let _ = evx_declaration::declaration_digest_bytes(data);
    if let Ok(Some(declaration)) = parsed {
        let content: serde_json::Value = serde_json::from_slice(data).unwrap();
        for (id, program) in &declaration.programs {
            assert_eq!(program.runtime_profile, evx_declaration::RUNTIME_PROFILE);
            assert!(program.limits.validate().is_ok());
            assert!(evx_api::validate_relative_path(&program.entry).is_ok());
            let _ = evx_declaration::bind(&declaration, id, &content);
        }
        for job in declaration.jobs.values() {
            assert!(declaration.programs.contains_key(&job.program));
        }
    }
    if let Ok(request) = evx_api::Request::decode(data) {
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(evx_api::Request::decode(&encoded).unwrap(), request);
    }
});
