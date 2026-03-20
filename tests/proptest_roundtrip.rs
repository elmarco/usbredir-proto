use bytes::Bytes;
use proptest::prelude::*;
use usbredir_proto::*;

fn all_caps() -> Caps {
    Caps::new()
        .with(Cap::ConnectDeviceVersion)
        .with(Cap::Filter)
        .with(Cap::DeviceDisconnectAck)
        .with(Cap::EpInfoMaxPacketSize)
        .with(Cap::Ids64Bits)
        .with(Cap::BulkLength32Bits)
        .with(Cap::BulkReceiving)
}

fn connected_pair() -> (Parser, Parser) {
    let caps = all_caps();
    let mut host = Parser::new(ParserConfig {
        version: "proptest".into(),
        caps,
        is_host: true,
        no_hello: false,
    });
    let mut guest = Parser::new(ParserConfig {
        version: "proptest".into(),
        caps,
        is_host: false,
        no_hello: false,
    });

    let h = drain_all(&mut host);
    let g = drain_all(&mut guest);
    guest.feed(&h);
    host.feed(&g);
    while guest.poll().is_some() {}
    while host.poll().is_some() {}

    (host, guest)
}

fn drain_all(p: &mut Parser) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(b) = p.drain() {
        out.extend_from_slice(&b);
    }
    out
}

fn roundtrip(sender: &mut Parser, receiver: &mut Parser, packet: Packet) -> Packet {
    sender.send(packet).unwrap();
    let wire = drain_all(sender);
    receiver.feed(&wire);
    loop {
        match receiver.poll().unwrap() {
            Event::Packet(p) => return *p,
            Event::ParseError(_) => continue,
            _ => continue,
        }
    }
}

fn arb_status() -> impl Strategy<Value = Status> {
    prop_oneof![
        Just(Status::Success),
        Just(Status::Cancelled),
        Just(Status::Inval),
        Just(Status::IoError),
        Just(Status::Stall),
        Just(Status::Timeout),
        Just(Status::Babble),
    ]
}

fn arb_speed() -> impl Strategy<Value = Speed> {
    prop_oneof![
        Just(Speed::Low),
        Just(Speed::Full),
        Just(Speed::High),
        Just(Speed::Super),
    ]
}

fn arb_endpoint() -> impl Strategy<Value = Endpoint> {
    (any::<bool>(), 0u8..16).prop_map(|(is_in, num)| {
        Endpoint::new(if is_in { num | 0x80 } else { num })
    })
}

fn arb_input_endpoint() -> impl Strategy<Value = Endpoint> {
    (0u8..16).prop_map(|n| Endpoint::new(n | 0x80))
}

fn arb_output_endpoint() -> impl Strategy<Value = Endpoint> {
    (0u8..16).prop_map(Endpoint::new)
}

fn arb_data(max_len: usize) -> impl Strategy<Value = Bytes> {
    prop::collection::vec(any::<u8>(), 0..=max_len).prop_map(Bytes::from)
}

/// Packets sent by the host (is_host=true), received by guest.
fn arb_host_sends() -> impl Strategy<Value = Packet> {
    prop_oneof![
        // Device-info packets (host sends device status to guest)
        (
            arb_speed(),
            any::<u8>(),
            any::<u8>(),
            any::<u8>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>()
        )
            .prop_map(|(speed, dc, ds, dp, vid, pid, bcd)| {
                Packet::device_connect(speed, dc, ds, dp, vid, pid, bcd)
            }),
        Just(Packet::DeviceDisconnect),
        // Status responses
        (any::<u64>(), arb_status(), any::<u8>())
            .prop_map(|(id, st, cfg)| Packet::configuration_status(id, st, cfg)),
        (any::<u64>(), arb_status(), any::<u8>(), any::<u8>())
            .prop_map(|(id, st, iface, alt)| Packet::alt_setting_status(id, st, iface, alt)),
        (any::<u64>(), arb_status(), arb_endpoint())
            .prop_map(|(id, st, ep)| Packet::iso_stream_status(id, st, ep)),
        (any::<u64>(), arb_status(), arb_input_endpoint())
            .prop_map(|(id, st, ep)| Packet::interrupt_receiving_status(id, st, ep)),
        (any::<u64>(), any::<u32>(), any::<u32>(), arb_status())
            .prop_map(|(id, eps, ns, st)| Packet::bulk_streams_status(id, eps, ns, st)),
        (
            any::<u64>(),
            any::<u32>(),
            arb_input_endpoint(),
            arb_status()
        )
            .prop_map(|(id, sid, ep, st)| Packet::bulk_receiving_status(id, sid, ep, st)),
    ]
}

/// Packets sent by the guest (is_host=false), received by host.
fn arb_guest_sends() -> impl Strategy<Value = Packet> {
    prop_oneof![
        any::<u64>().prop_map(Packet::reset),
        (any::<u64>(), any::<u8>()).prop_map(|(id, cfg)| Packet::set_configuration(id, cfg)),
        any::<u64>().prop_map(Packet::get_configuration),
        (any::<u64>(), any::<u8>(), any::<u8>())
            .prop_map(|(id, iface, alt)| Packet::set_alt_setting(id, iface, alt)),
        (any::<u64>(), any::<u8>()).prop_map(|(id, iface)| Packet::get_alt_setting(id, iface)),
        (any::<u64>(), arb_endpoint(), any::<u8>(), any::<u8>())
            .prop_map(|(id, ep, pkts, urbs)| Packet::start_iso_stream(id, ep, pkts, urbs)),
        (any::<u64>(), arb_endpoint()).prop_map(|(id, ep)| Packet::stop_iso_stream(id, ep)),
        (any::<u64>(), arb_input_endpoint())
            .prop_map(|(id, ep)| Packet::start_interrupt_receiving(id, ep)),
        (any::<u64>(), arb_input_endpoint())
            .prop_map(|(id, ep)| Packet::stop_interrupt_receiving(id, ep)),
        any::<u64>().prop_map(Packet::cancel_data_packet),
        Just(Packet::DeviceDisconnectAck),
        Just(Packet::FilterReject),
        (any::<u64>(), any::<u32>(), any::<u32>())
            .prop_map(|(id, eps, ns)| Packet::alloc_bulk_streams(id, eps, ns)),
        (any::<u64>(), any::<u32>()).prop_map(|(id, eps)| Packet::free_bulk_streams(id, eps)),
        (
            any::<u64>(),
            any::<u32>(),
            1..=65536u32,
            arb_input_endpoint(),
            any::<u8>()
        )
            .prop_map(|(id, sid, bpt, ep, nt)| Packet::start_bulk_receiving(id, sid, bpt, ep, nt)),
        (any::<u64>(), any::<u32>(), arb_input_endpoint())
            .prop_map(|(id, sid, ep)| Packet::stop_bulk_receiving(id, sid, ep)),
    ]
}

/// Data packets: guest sends with OUT endpoint (no data) or host sends with IN endpoint (with data).
/// Here we test guest sending control/bulk with OUT endpoint (request, no data).
fn arb_data_packet_guest_sends() -> impl Strategy<Value = Packet> {
    prop_oneof![
        // ControlPacket with OUT endpoint, no data (guest sends request to device)
        (
            any::<u64>(),
            arb_output_endpoint(),
            any::<u8>(),
            any::<u8>(),
            arb_status(),
            any::<u16>(),
            any::<u16>()
        )
            .prop_map(|(id, ep, req, rtype, st, val, idx)| {
                Packet::control_packet(id, ep, req, rtype, st, val, idx, 0, Bytes::new())
            }),
        // BulkPacket with OUT endpoint, no data
        (
            any::<u64>(),
            arb_output_endpoint(),
            arb_status(),
            any::<u32>()
        )
            .prop_map(|(id, ep, st, sid)| {
                Packet::bulk_packet(id, ep, st, 0, sid, Bytes::new())
            }),
    ]
}

/// Data packets: host sends with IN endpoint + data (response from device).
fn arb_data_packet_host_sends() -> impl Strategy<Value = Packet> {
    prop_oneof![
        // ControlPacket with IN endpoint + data
        (
            any::<u64>(),
            arb_input_endpoint(),
            any::<u8>(),
            any::<u8>(),
            arb_status(),
            any::<u16>(),
            any::<u16>(),
            arb_data(512)
        )
            .prop_map(|(id, ep, req, rtype, st, val, idx, data)| {
                let len = data.len() as u16;
                Packet::control_packet(id, ep, req, rtype, st, val, idx, len, data)
            }),
        // BulkPacket with IN endpoint + data
        (
            any::<u64>(),
            arb_input_endpoint(),
            arb_status(),
            any::<u32>(),
            arb_data(1024)
        )
            .prop_map(|(id, ep, st, sid, data)| {
                let len = data.len() as u32;
                Packet::bulk_packet(id, ep, st, len, sid, data)
            }),
        // IsoPacket with IN endpoint + data (host sends, like device response)
        (
            any::<u64>(),
            arb_input_endpoint(),
            arb_status(),
            arb_data(512)
        )
            .prop_map(|(id, ep, st, data)| {
                let len = data.len() as u16;
                Packet::iso_packet(id, ep, st, len, data)
            }),
        // InterruptPacket with IN endpoint + data
        (
            any::<u64>(),
            arb_input_endpoint(),
            arb_status(),
            arb_data(512)
        )
            .prop_map(|(id, ep, st, data)| {
                let len = data.len() as u16;
                Packet::interrupt_packet(id, ep, st, len, data)
            }),
    ]
}

proptest! {
    #[test]
    fn roundtrip_host_sends(packet in arb_host_sends()) {
        let (mut host, mut guest) = connected_pair();
        let decoded = roundtrip(&mut host, &mut guest, packet.clone());
        prop_assert_eq!(decoded, packet);
    }

    #[test]
    fn roundtrip_guest_sends(packet in arb_guest_sends()) {
        let (mut host, mut guest) = connected_pair();
        let decoded = roundtrip(&mut guest, &mut host, packet.clone());
        prop_assert_eq!(decoded, packet);
    }

    #[test]
    fn roundtrip_data_guest_sends(packet in arb_data_packet_guest_sends()) {
        let (mut host, mut guest) = connected_pair();
        let decoded = roundtrip(&mut guest, &mut host, packet.clone());
        prop_assert_eq!(decoded, packet);
    }

    #[test]
    fn roundtrip_data_host_sends(packet in arb_data_packet_host_sends()) {
        let (mut host, mut guest) = connected_pair();
        let decoded = roundtrip(&mut host, &mut guest, packet.clone());
        prop_assert_eq!(decoded, packet);
    }
}
