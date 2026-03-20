use criterion::{black_box, criterion_group, criterion_main, Criterion};

use bytes::Bytes;
use usbredir_proto::*;

fn make_connected_pair() -> (Parser<Host>, Parser<Guest>) {
    let mut caps = Caps::new();
    caps.set(Cap::ConnectDeviceVersion);
    caps.set(Cap::Filter);
    caps.set(Cap::DeviceDisconnectAck);
    caps.set(Cap::EpInfoMaxPacketSize);
    caps.set(Cap::Ids64Bits);
    caps.set(Cap::BulkLength32Bits);
    caps.set(Cap::BulkReceiving);

    let config = ParserConfig {
        version: "bench".into(),
        caps,
        no_hello: false,
        max_input_buffer: None,
    };

    let mut host = Parser::<Host>::new(config.clone());
    let mut guest = Parser::<Guest>::new(config);

    // Exchange hellos
    let h = drain_all(&mut host);
    let g = drain_all(&mut guest);
    guest.feed(&h).unwrap();
    host.feed(&g).unwrap();
    while guest.poll().is_some() {}
    while host.poll().is_some() {}

    (host, guest)
}

fn drain_all<R: Role>(p: &mut Parser<R>) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(b) = p.drain() {
        out.extend_from_slice(&b);
    }
    out
}

fn bench_encode_bulk(c: &mut Criterion) {
    let (_, mut guest) = make_connected_pair();
    let data = Bytes::from(vec![0xABu8; 1024]);

    c.bench_function("encode_bulk_1k", |b| {
        b.iter(|| {
            guest
                .send(&Packet::bulk_packet(
                    1,
                    Endpoint::new(0x02),
                    Status::Success,
                    1024,
                    0,
                    data.clone(),
                ))
                .unwrap();
            while guest.drain().is_some() {}
        })
    });
}

fn bench_decode_bulk(c: &mut Criterion) {
    let (mut host, mut guest) = make_connected_pair();
    let data = Bytes::from(vec![0xABu8; 1024]);

    // Encode a bulk packet to get its wire bytes
    guest
        .send(&Packet::bulk_packet(
            1,
            Endpoint::new(0x02),
            Status::Success,
            1024,
            0,
            data,
        ))
        .unwrap();
    let wire = drain_all(&mut guest);

    c.bench_function("decode_bulk_1k", |b| {
        b.iter(|| {
            host.feed(black_box(&wire)).unwrap();
            while host.poll().is_some() {}
        })
    });
}

fn bench_encode_control(c: &mut Criterion) {
    let (_, mut guest) = make_connected_pair();

    c.bench_function("encode_control_no_data", |b| {
        b.iter(|| {
            guest
                .send(&Packet::control_packet(
                    1,
                    Endpoint::new(0x00),
                    0x09,
                    0x00,
                    Status::Success,
                    1,
                    0,
                    0,
                    Bytes::new(),
                ))
                .unwrap();
            while guest.drain().is_some() {}
        })
    });
}

fn bench_roundtrip_hello(c: &mut Criterion) {
    let mut caps = Caps::new();
    caps.set(Cap::Ids64Bits);

    let config = ParserConfig {
        version: "bench".into(),
        caps,
        no_hello: false,
        max_input_buffer: None,
    };

    c.bench_function("roundtrip_hello", |b| {
        b.iter(|| {
            let mut p = Parser::<Host>::new(config.clone());
            let wire = drain_all(&mut p);

            let mut p2 = Parser::<Guest>::new(config.clone());
            p2.feed(black_box(&wire)).unwrap();
            while p2.poll().is_some() {}
        })
    });
}

fn bench_filter_parse(c: &mut Criterion) {
    let filter_str = "0x03,-1,-1,-1,0|0x08,-1,-1,-1,1|-1,0x1234,0x5678,-1,0|-1,-1,-1,-1,1";

    c.bench_function("filter_parse_4_rules", |b| {
        b.iter(|| {
            usbredir_proto::filter::parse_rules(black_box(filter_str), ",", "|").unwrap();
        })
    });
}

fn bench_filter_check(c: &mut Criterion) {
    let rules = usbredir_proto::filter::parse_rules(
        "0x03,-1,-1,-1,0|0x08,-1,-1,-1,1|-1,0x1234,0x5678,-1,0|-1,-1,-1,-1,1",
        ",",
        "|",
    )
    .unwrap();

    c.bench_function("filter_check_4_rules", |b| {
        b.iter(|| {
            usbredir_proto::filter::check(
                black_box(&rules),
                &usbredir_proto::DeviceInfo {
                    device_class: 0x00,
                    interfaces: &[(0x08, 0x06, 0x50)],
                    vendor_id: 0x1234,
                    product_id: 0x5678,
                    device_version_bcd: 0x0100,
                },
                CheckFlags::empty(),
            )
            .unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_encode_bulk,
    bench_decode_bulk,
    bench_encode_control,
    bench_roundtrip_hello,
    bench_filter_parse,
    bench_filter_check,
);
criterion_main!(benches);
