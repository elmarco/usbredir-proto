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
                0x00,
                0x00,
                0x00,
                &[(0x08, 0x06, 0x50)],
                0x1234,
                0x5678,
                0x0100,
                usbredir_proto::CheckFlags::empty(),
            );
        }
    }
});
