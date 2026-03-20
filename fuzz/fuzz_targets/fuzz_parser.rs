#![no_main]

use libfuzzer_sys::fuzz_target;
use usbredir_proto::*;

fuzz_target!(|data: &[u8]| {
    // Fuzz the parser with random bytes — must never panic.
    // Test both host and guest parsers, with and without caps.

    let mut caps = Caps::new();
    // Enable all caps so all code paths are reachable
    caps.set(Cap::ConnectDeviceVersion);
    caps.set(Cap::Filter);
    caps.set(Cap::DeviceDisconnectAck);
    caps.set(Cap::EpInfoMaxPacketSize);
    caps.set(Cap::Ids64Bits);
    caps.set(Cap::BulkLength32Bits);
    caps.set(Cap::BulkReceiving);

    let config = ParserConfig {
        version: "fuzz".into(),
        caps,
        no_hello: true,
    };

    // Host parser
    let mut parser = Parser::<Host>::new(config.clone());
    parser.feed(data);
    while parser.poll().is_some() {}

    // Guest parser
    let mut parser = Parser::<Guest>::new(config);
    parser.feed(data);
    while parser.poll().is_some() {}

    // Also test with minimal caps (32-bit ids, no compat features)
    let mut parser = Parser::<Host>::new(ParserConfig {
        version: "fuzz".into(),
        caps: Caps::new(),
        no_hello: true,
    });
    parser.feed(data);
    while parser.poll().is_some() {}
});
