#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz filter parsing with random bytes — must never panic.
    if let Ok(s) = core::str::from_utf8(data) {
        // Try various separator combinations
        let _ = usbredir_proto::filter::parse_rules(s, ",", "|");
        let _ = usbredir_proto::filter::parse_rules(s, " ", "\n");

        // If parsing succeeds, also test verify and roundtrip
        if let Ok(rules) = usbredir_proto::filter::parse_rules(s, ",", "|") {
            let _ = usbredir_proto::filter::verify_rules(&rules);
            let _ = usbredir_proto::filter::rules_to_string(&rules, ",", "|");

            // Test check with dummy device info
            let _ = usbredir_proto::filter::check(
                &rules,
                &usbredir_proto::DeviceInfo {
                    device_class: 0x00,
                    interfaces: &[(0x08, 0x06, 0x50)],
                    vendor_id: 0x1234,
                    product_id: 0x5678,
                    device_version_bcd: 0x0100,
                },
                usbredir_proto::CheckFlags::empty(),
            );
        }
    }
});
