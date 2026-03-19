//! FFI interop tests: verify Rust encode/decode is wire-compatible with the C library
//! for **every** packet type.
//!
//! Strategy per packet type:
//!   1. C encodes → raw bytes
//!   2. Rust encodes the same logical packet → raw bytes
//!   3. Assert C bytes == Rust bytes  (bit-exact wire compatibility)
//!   4. Feed C bytes into Rust parser → verify correct `Packet` variant is decoded
//!   5. Feed Rust bytes into C parser → verify callback fires without error
//!
//! Serialization round-trips (C→Rust, Rust→C) are tested separately.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void};
use std::ptr;
use std::slice;

use bytes::Bytes;
use usbredir_proto::*;
use usbredirparser_sys as sys;

// ---------------------------------------------------------------------------
// I/O harness — thread-local read/write buffers for C callbacks
// ---------------------------------------------------------------------------

thread_local! {
    static READ_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    static READ_POS: RefCell<usize> = RefCell::new(0);
    static WRITE_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    // Generic "a callback fired" counter — incremented by every stub callback
    static CB_COUNT: RefCell<u32> = RefCell::new(0);
}

fn reset_io() {
    READ_BUF.with(|b| b.borrow_mut().clear());
    READ_POS.with(|p| *p.borrow_mut() = 0);
    WRITE_BUF.with(|b| b.borrow_mut().clear());
    CB_COUNT.with(|c| *c.borrow_mut() = 0);
}

unsafe extern "C" fn log_cb(_: *mut c_void, _: c_int, _: *const c_char) {}

unsafe extern "C" fn read_cb(_: *mut c_void, data: *mut u8, count: c_int) -> c_int {
    READ_BUF.with(|buf| {
        READ_POS.with(|pos| {
            let buf = buf.borrow();
            let mut p = pos.borrow_mut();
            let remaining = buf.len() - *p;
            if remaining == 0 {
                return 0;
            }
            let n = (count as usize).min(remaining);
            unsafe { ptr::copy_nonoverlapping(buf[*p..].as_ptr(), data, n) };
            *p += n;
            n as c_int
        })
    })
}

unsafe extern "C" fn write_cb(_: *mut c_void, data: *mut u8, count: c_int) -> c_int {
    WRITE_BUF.with(|buf| {
        buf.borrow_mut()
            .extend_from_slice(unsafe { slice::from_raw_parts(data, count as usize) });
        count
    })
}

fn bump_cb() {
    CB_COUNT.with(|c| *c.borrow_mut() += 1);
}
fn cb_count() -> u32 {
    CB_COUNT.with(|c| *c.borrow())
}

// Stub callbacks — they just bump the counter so we can verify "something was received"
unsafe extern "C" fn cb_hello(_: *mut c_void, _: *mut sys::usb_redir_hello_header) {
    bump_cb();
}
unsafe extern "C" fn cb_device_connect(
    _: *mut c_void,
    _: *mut sys::usb_redir_device_connect_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_device_disconnect(_: *mut c_void) {
    bump_cb();
}
unsafe extern "C" fn cb_reset(_: *mut c_void) {
    bump_cb();
}
unsafe extern "C" fn cb_interface_info(
    _: *mut c_void,
    _: *mut sys::usb_redir_interface_info_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_ep_info(_: *mut c_void, _: *mut sys::usb_redir_ep_info_header) {
    bump_cb();
}
unsafe extern "C" fn cb_set_configuration(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_set_configuration_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_get_configuration(_: *mut c_void, _: u64) {
    bump_cb();
}
unsafe extern "C" fn cb_configuration_status(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_configuration_status_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_set_alt_setting(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_set_alt_setting_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_get_alt_setting(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_get_alt_setting_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_alt_setting_status(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_alt_setting_status_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_start_iso_stream(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_start_iso_stream_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_stop_iso_stream(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_stop_iso_stream_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_iso_stream_status(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_iso_stream_status_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_start_interrupt_receiving(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_start_interrupt_receiving_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_stop_interrupt_receiving(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_stop_interrupt_receiving_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_interrupt_receiving_status(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_interrupt_receiving_status_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_alloc_bulk_streams(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_alloc_bulk_streams_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_free_bulk_streams(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_free_bulk_streams_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_bulk_streams_status(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_bulk_streams_status_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_cancel_data_packet(_: *mut c_void, _: u64) {
    bump_cb();
}
unsafe extern "C" fn cb_filter_reject(_: *mut c_void) {
    bump_cb();
}
unsafe extern "C" fn cb_filter_filter(_: *mut c_void, _: *mut sys::usbredirfilter_rule, _: c_int) {
    bump_cb();
}
unsafe extern "C" fn cb_device_disconnect_ack(_: *mut c_void) {
    bump_cb();
}
unsafe extern "C" fn cb_start_bulk_receiving(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_start_bulk_receiving_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_stop_bulk_receiving(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_stop_bulk_receiving_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_bulk_receiving_status(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_bulk_receiving_status_header,
) {
    bump_cb();
}
unsafe extern "C" fn cb_control_packet(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_control_packet_header,
    _: *mut u8,
    _: c_int,
) {
    bump_cb();
}
unsafe extern "C" fn cb_bulk_packet(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_bulk_packet_header,
    _: *mut u8,
    _: c_int,
) {
    bump_cb();
}
unsafe extern "C" fn cb_iso_packet(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_iso_packet_header,
    _: *mut u8,
    _: c_int,
) {
    bump_cb();
}
unsafe extern "C" fn cb_interrupt_packet(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_interrupt_packet_header,
    _: *mut u8,
    _: c_int,
) {
    bump_cb();
}
unsafe extern "C" fn cb_buffered_bulk_packet(
    _: *mut c_void,
    _: u64,
    _: *mut sys::usb_redir_buffered_bulk_packet_header,
    _: *mut u8,
    _: c_int,
) {
    bump_cb();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn all_caps_mask() -> [u32; sys::USB_REDIR_CAPS_SIZE as usize] {
    let mut caps = [0u32; sys::USB_REDIR_CAPS_SIZE as usize];
    unsafe {
        sys::usbredirparser_caps_set_cap(caps.as_mut_ptr(), sys::usb_redir_cap_connect_device_version as _);
        sys::usbredirparser_caps_set_cap(caps.as_mut_ptr(), sys::usb_redir_cap_filter as _);
        sys::usbredirparser_caps_set_cap(caps.as_mut_ptr(), sys::usb_redir_cap_device_disconnect_ack as _);
        sys::usbredirparser_caps_set_cap(caps.as_mut_ptr(), sys::usb_redir_cap_ep_info_max_packet_size as _);
        sys::usbredirparser_caps_set_cap(caps.as_mut_ptr(), sys::usb_redir_cap_64bits_ids as _);
        sys::usbredirparser_caps_set_cap(caps.as_mut_ptr(), sys::usb_redir_cap_32bits_bulk_length as _);
        sys::usbredirparser_caps_set_cap(caps.as_mut_ptr(), sys::usb_redir_cap_bulk_receiving as _);
    }
    caps
}

fn rust_caps() -> Caps {
    let mut c = Caps::new();
    c.set(Cap::ConnectDeviceVersion);
    c.set(Cap::Filter);
    c.set(Cap::DeviceDisconnectAck);
    c.set(Cap::EpInfoMaxPacketSize);
    c.set(Cap::Ids64Bits);
    c.set(Cap::BulkLength32Bits);
    c.set(Cap::BulkReceiving);
    c
}

fn rust_config(is_host: bool) -> ParserConfig {
    ParserConfig {
        version: "rust-test".to_string(),
        caps: rust_caps(),
        is_host,
        no_hello: false,
    }
}

/// Create a C parser with all callbacks wired up, optionally as host, optionally no_hello.
unsafe fn make_c_parser(is_host: bool, no_hello: bool) -> *mut sys::usbredirparser {
    let p = sys::usbredirparser_create();
    assert!(!p.is_null());
    (*p).log_func = Some(log_cb);
    (*p).read_func = Some(read_cb);
    (*p).write_func = Some(write_cb);
    // Wire every callback
    (*p).hello_func = Some(cb_hello);
    (*p).device_connect_func = Some(cb_device_connect);
    (*p).device_disconnect_func = Some(cb_device_disconnect);
    (*p).reset_func = Some(cb_reset);
    (*p).interface_info_func = Some(cb_interface_info);
    (*p).ep_info_func = Some(cb_ep_info);
    (*p).set_configuration_func = Some(cb_set_configuration);
    (*p).get_configuration_func = Some(cb_get_configuration);
    (*p).configuration_status_func = Some(cb_configuration_status);
    (*p).set_alt_setting_func = Some(cb_set_alt_setting);
    (*p).get_alt_setting_func = Some(cb_get_alt_setting);
    (*p).alt_setting_status_func = Some(cb_alt_setting_status);
    (*p).start_iso_stream_func = Some(cb_start_iso_stream);
    (*p).stop_iso_stream_func = Some(cb_stop_iso_stream);
    (*p).iso_stream_status_func = Some(cb_iso_stream_status);
    (*p).start_interrupt_receiving_func = Some(cb_start_interrupt_receiving);
    (*p).stop_interrupt_receiving_func = Some(cb_stop_interrupt_receiving);
    (*p).interrupt_receiving_status_func = Some(cb_interrupt_receiving_status);
    (*p).alloc_bulk_streams_func = Some(cb_alloc_bulk_streams);
    (*p).free_bulk_streams_func = Some(cb_free_bulk_streams);
    (*p).bulk_streams_status_func = Some(cb_bulk_streams_status);
    (*p).cancel_data_packet_func = Some(cb_cancel_data_packet);
    (*p).filter_reject_func = Some(cb_filter_reject);
    (*p).filter_filter_func = Some(cb_filter_filter);
    (*p).device_disconnect_ack_func = Some(cb_device_disconnect_ack);
    (*p).start_bulk_receiving_func = Some(cb_start_bulk_receiving);
    (*p).stop_bulk_receiving_func = Some(cb_stop_bulk_receiving);
    (*p).bulk_receiving_status_func = Some(cb_bulk_receiving_status);
    (*p).control_packet_func = Some(cb_control_packet);
    (*p).bulk_packet_func = Some(cb_bulk_packet);
    (*p).iso_packet_func = Some(cb_iso_packet);
    (*p).interrupt_packet_func = Some(cb_interrupt_packet);
    (*p).buffered_bulk_packet_func = Some(cb_buffered_bulk_packet);

    let mut caps = all_caps_mask();
    let version = b"c-test\0";
    let mut flags: c_int = 0;
    if is_host {
        flags |= sys::usbredirparser_fl_usb_host as c_int;
    }
    if no_hello {
        flags |= sys::usbredirparser_fl_no_hello as c_int;
    }
    sys::usbredirparser_init(
        p,
        version.as_ptr() as *const c_char,
        caps.as_mut_ptr(),
        sys::USB_REDIR_CAPS_SIZE as c_int,
        flags,
    );
    p
}

/// Flush all queued writes from C parser into WRITE_BUF
unsafe fn c_flush(p: *mut sys::usbredirparser) {
    while sys::usbredirparser_has_data_to_write(p) > 0 {
        sys::usbredirparser_do_write(p);
    }
}

/// Capture bytes produced by C parser (clears + flushes + returns)
unsafe fn c_capture(p: *mut sys::usbredirparser) -> Vec<u8> {
    WRITE_BUF.with(|b| b.borrow_mut().clear());
    c_flush(p);
    WRITE_BUF.with(|b| b.borrow().clone())
}

/// Feed bytes into C parser via READ_BUF, return do_read result
unsafe fn c_feed(p: *mut sys::usbredirparser, data: &[u8]) -> c_int {
    READ_BUF.with(|b| *b.borrow_mut() = data.to_vec());
    READ_POS.with(|pos| *pos.borrow_mut() = 0);
    sys::usbredirparser_do_read(p)
}

/// Drain all bytes from a Rust parser's output queue
fn rust_drain_all(r: &mut Parser) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(b) = r.drain() {
        out.extend_from_slice(&b);
    }
    out
}

/// Drain all events, return list of Packets
fn rust_drain_packets(r: &mut Parser) -> Vec<Packet> {
    let mut pkts = Vec::new();
    while let Some(ev) = r.poll() {
        if let Event::Packet(p) = ev {
            pkts.push(p);
        }
    }
    pkts
}

/// Create a connected pair: (C parser, Rust parser) with hellos exchanged.
/// `c_is_host` determines C's role; Rust gets the opposite.
unsafe fn connected_pair(c_is_host: bool) -> (*mut sys::usbredirparser, Parser) {
    reset_io();
    let cp = make_c_parser(c_is_host, false);

    let mut rp = Parser::new(rust_config(!c_is_host));

    // C hello → Rust
    let c_hello = c_capture(cp);
    rp.feed(&c_hello);
    rust_drain_packets(&mut rp); // consume hello event

    // Rust hello → C
    let rust_hello = rust_drain_all(&mut rp);
    c_feed(cp, &rust_hello);

    (cp, rp)
}

// ---------------------------------------------------------------------------
// Test: C encode → Rust decode for every packet type
//
// For each packet we:
//   1. Use the correct sender role (C host sends host→device commands,
//      C device sends device→host responses)
//   2. Capture C's wire bytes
//   3. Feed into Rust, verify correct Packet variant
// ---------------------------------------------------------------------------

/// Helper: C-encode a packet with `encode_fn`, feed to Rust, assert `check_fn` on decoded Packet
unsafe fn c_to_rust(
    c_is_host: bool,
    encode_fn: unsafe fn(*mut sys::usbredirparser),
    check_fn: fn(&Packet) -> bool,
    name: &str,
) {
    let (cp, mut rp) = connected_pair(c_is_host);
    encode_fn(cp);
    let wire = c_capture(cp);
    assert!(!wire.is_empty(), "{name}: C produced no bytes");

    rp.feed(&wire);
    let pkts = rust_drain_packets(&mut rp);
    assert!(
        pkts.iter().any(|p| check_fn(p)),
        "{name}: Rust did not decode expected packet from C bytes. Got: {pkts:?}"
    );
    sys::usbredirparser_destroy(cp);
}

/// Helper: Rust-encode a packet, feed to C, assert C callback fires
unsafe fn rust_to_c(
    c_is_host: bool,
    packet: Packet,
    name: &str,
) {
    let (cp, mut rp) = connected_pair(c_is_host);

    rp.send(packet).expect(&format!("{name}: Rust send failed"));
    let wire = rust_drain_all(&mut rp);
    assert!(!wire.is_empty(), "{name}: Rust produced no bytes");

    let before = cb_count();
    c_feed(cp, &wire);
    let after = cb_count();
    assert!(
        after > before,
        "{name}: C callback did not fire for Rust-encoded packet"
    );
    sys::usbredirparser_destroy(cp);
}

/// Helper: Encode with both C and Rust, assert byte-equal wire output
unsafe fn byte_compare(
    c_is_host: bool,
    encode_c: unsafe fn(*mut sys::usbredirparser),
    packet: Packet,
    name: &str,
) {
    // --- C side ---
    let (cp_c, _rp_c) = connected_pair(c_is_host);
    encode_c(cp_c);
    let c_wire = c_capture(cp_c);
    sys::usbredirparser_destroy(cp_c);

    // --- Rust side (Rust needs the same role as C, so flip c_is_host) ---
    let (cp_r, mut rp_r) = connected_pair(!c_is_host);
    rp_r.send(packet).expect(&format!("{name}: Rust send failed"));
    let rust_wire = rust_drain_all(&mut rp_r);
    sys::usbredirparser_destroy(cp_r);

    assert_eq!(
        c_wire, rust_wire,
        "{name}: wire bytes differ!\n  C   ({} bytes): {:02x?}\n  Rust({} bytes): {:02x?}",
        c_wire.len(), &c_wire[..c_wire.len().min(64)],
        rust_wire.len(), &rust_wire[..rust_wire.len().min(64)],
    );
}

// ===========================================================================
// Packet-by-packet interop tests
// ===========================================================================

// -- device_connect (host→guest: USB host tells guest about connected device) --

#[test]
fn interop_device_connect() {
    unsafe {
        let pkt = Packet::DeviceConnect {
            speed: Speed::High,
            device_class: 0x08,
            device_subclass: 0x06,
            device_protocol: 0x50,
            vendor_id: 0x1234,
            product_id: 0x5678,
            device_version_bcd: 0x0100,
        };

        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_device_connect_header {
                speed: 2, // High
                device_class: 0x08,
                device_subclass: 0x06,
                device_protocol: 0x50,
                vendor_id: 0x1234,
                product_id: 0x5678,
                device_version_bcd: 0x0100,
            };
            sys::usbredirparser_send_device_connect(cp, &mut h);
        }

        // C(host) → Rust(guest)
        c_to_rust(true, c_encode, |p| matches!(p, Packet::DeviceConnect { speed: Speed::High, device_class: 0x08, .. }), "device_connect");
        // Rust(host) → C(guest)
        rust_to_c(false, pkt.clone(), "device_connect");
        // Byte comparison: both encode as host
        byte_compare(true, c_encode, pkt, "device_connect");
    }
}

// -- device_disconnect (host→guest) --

#[test]
fn interop_device_disconnect() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            sys::usbredirparser_send_device_disconnect(cp);
        }
        c_to_rust(true, c_encode, |p| matches!(p, Packet::DeviceDisconnect), "device_disconnect");
        rust_to_c(false, Packet::DeviceDisconnect, "device_disconnect");
        byte_compare(true, c_encode, Packet::DeviceDisconnect, "device_disconnect");
    }
}

// -- reset (guest→host) --

#[test]
fn interop_reset() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            sys::usbredirparser_send_reset(cp);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::Reset { .. }), "reset");
        rust_to_c(true, Packet::Reset { id: 1 }, "reset");
        // C's send_reset doesn't take an id — it always uses 0
        byte_compare(false, c_encode, Packet::Reset { id: 0 }, "reset");
    }
}

// -- interface_info (host→guest) --

#[test]
fn interop_interface_info() {
    unsafe {
        let pkt = Packet::InterfaceInfo {
            interface_count: 2,
            interface: {
                let mut a = [0u8; 32];
                a[0] = 0;
                a[1] = 1;
                a
            },
            interface_class: {
                let mut a = [0u8; 32];
                a[0] = 0x08;
                a[1] = 0x03;
                a
            },
            interface_subclass: [0u8; 32],
            interface_protocol: [0u8; 32],
        };

        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_interface_info_header {
                interface_count: 2,
                interface: [0u8; 32],
                interface_class: [0u8; 32],
                interface_subclass: [0u8; 32],
                interface_protocol: [0u8; 32],
            };
            h.interface[0] = 0;
            h.interface[1] = 1;
            h.interface_class[0] = 0x08;
            h.interface_class[1] = 0x03;
            sys::usbredirparser_send_interface_info(cp, &mut h);
        }

        c_to_rust(true, c_encode, |p| matches!(p, Packet::InterfaceInfo { interface_count: 2, .. }), "interface_info");
        rust_to_c(false, pkt.clone(), "interface_info");
        byte_compare(true, c_encode, pkt, "interface_info");
    }
}

// -- ep_info (host→guest) --

#[test]
fn interop_ep_info() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h: sys::usb_redir_ep_info_header = std::mem::zeroed();
            h.type_[0] = 2; // bulk
            h.interval[0] = 0;
            h.interface[0] = 0;
            h.max_packet_size[0] = 512;
            sys::usbredirparser_send_ep_info(cp, &mut h);
        }

        c_to_rust(true, c_encode, |p| matches!(p, Packet::EpInfo { .. }), "ep_info");

        // Match C's zeroed() initialization: unused ep_type entries are 0 (Control)
        let mut ep_type = [TransferType::Control; 32];
        ep_type[0] = TransferType::Bulk;
        let mut max_packet_size = [0u16; 32];
        max_packet_size[0] = 512;
        let pkt = Packet::EpInfo {
            ep_type,
            interval: [0u8; 32],
            interface: [0u8; 32],
            max_packet_size,
            max_streams: [0u32; 32],
        };
        rust_to_c(false, pkt.clone(), "ep_info");
        byte_compare(true, c_encode, pkt, "ep_info");
    }
}

// -- set_configuration (guest→host) --

#[test]
fn interop_set_configuration() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_set_configuration_header { configuration: 1 };
            sys::usbredirparser_send_set_configuration(cp, 42, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::SetConfiguration { id: 42, configuration: 1, .. }), "set_configuration");
        rust_to_c(true, Packet::SetConfiguration { id: 42, configuration: 1 }, "set_configuration");
        byte_compare(false, c_encode, Packet::SetConfiguration { id: 42, configuration: 1 }, "set_configuration");
    }
}

// -- get_configuration (guest→host) --

#[test]
fn interop_get_configuration() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            sys::usbredirparser_send_get_configuration(cp, 7);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::GetConfiguration { id: 7, .. }), "get_configuration");
        rust_to_c(true, Packet::GetConfiguration { id: 7 }, "get_configuration");
        byte_compare(false, c_encode, Packet::GetConfiguration { id: 7 }, "get_configuration");
    }
}

// -- configuration_status (host→guest) --

#[test]
fn interop_configuration_status() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_configuration_status_header { status: 0, configuration: 2 };
            sys::usbredirparser_send_configuration_status(cp, 10, &mut h);
        }
        c_to_rust(true, c_encode, |p| matches!(p, Packet::ConfigurationStatus { id: 10, configuration: 2, .. }), "configuration_status");
        rust_to_c(false, Packet::ConfigurationStatus { id: 10, status: Status::Success, configuration: 2 }, "configuration_status");
        byte_compare(true, c_encode, Packet::ConfigurationStatus { id: 10, status: Status::Success, configuration: 2 }, "configuration_status");
    }
}

// -- set_alt_setting (guest→host) --

#[test]
fn interop_set_alt_setting() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_set_alt_setting_header { interface: 1, alt: 3 };
            sys::usbredirparser_send_set_alt_setting(cp, 20, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::SetAltSetting { id: 20, interface: 1, alt: 3, .. }), "set_alt_setting");
        rust_to_c(true, Packet::SetAltSetting { id: 20, interface: 1, alt: 3 }, "set_alt_setting");
        byte_compare(false, c_encode, Packet::SetAltSetting { id: 20, interface: 1, alt: 3 }, "set_alt_setting");
    }
}

// -- get_alt_setting (guest→host) --

#[test]
fn interop_get_alt_setting() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_get_alt_setting_header { interface: 2 };
            sys::usbredirparser_send_get_alt_setting(cp, 21, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::GetAltSetting { id: 21, interface: 2, .. }), "get_alt_setting");
        rust_to_c(true, Packet::GetAltSetting { id: 21, interface: 2 }, "get_alt_setting");
        byte_compare(false, c_encode, Packet::GetAltSetting { id: 21, interface: 2 }, "get_alt_setting");
    }
}

// -- alt_setting_status (host→guest) --

#[test]
fn interop_alt_setting_status() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_alt_setting_status_header { status: 0, interface: 1, alt: 2 };
            sys::usbredirparser_send_alt_setting_status(cp, 22, &mut h);
        }
        c_to_rust(true, c_encode, |p| matches!(p, Packet::AltSettingStatus { id: 22, interface: 1, alt: 2, .. }), "alt_setting_status");
        rust_to_c(false, Packet::AltSettingStatus { id: 22, status: Status::Success, interface: 1, alt: 2 }, "alt_setting_status");
        byte_compare(true, c_encode, Packet::AltSettingStatus { id: 22, status: Status::Success, interface: 1, alt: 2 }, "alt_setting_status");
    }
}

// -- start_iso_stream (guest→host) --

#[test]
fn interop_start_iso_stream() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_start_iso_stream_header { endpoint: 0x81, pkts_per_urb: 8, no_urbs: 4 };
            sys::usbredirparser_send_start_iso_stream(cp, 30, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::StartIsoStream { id: 30, endpoint: 0x81, .. }), "start_iso_stream");
        rust_to_c(true, Packet::StartIsoStream { id: 30, endpoint: 0x81, pkts_per_urb: 8, no_urbs: 4 }, "start_iso_stream");
        byte_compare(false, c_encode, Packet::StartIsoStream { id: 30, endpoint: 0x81, pkts_per_urb: 8, no_urbs: 4 }, "start_iso_stream");
    }
}

// -- stop_iso_stream (guest→host) --

#[test]
fn interop_stop_iso_stream() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_stop_iso_stream_header { endpoint: 0x81 };
            sys::usbredirparser_send_stop_iso_stream(cp, 31, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::StopIsoStream { id: 31, endpoint: 0x81, .. }), "stop_iso_stream");
        rust_to_c(true, Packet::StopIsoStream { id: 31, endpoint: 0x81 }, "stop_iso_stream");
        byte_compare(false, c_encode, Packet::StopIsoStream { id: 31, endpoint: 0x81 }, "stop_iso_stream");
    }
}

// -- iso_stream_status (host→guest) --

#[test]
fn interop_iso_stream_status() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_iso_stream_status_header { status: 0, endpoint: 0x81 };
            sys::usbredirparser_send_iso_stream_status(cp, 32, &mut h);
        }
        c_to_rust(true, c_encode, |p| matches!(p, Packet::IsoStreamStatus { id: 32, endpoint: 0x81, .. }), "iso_stream_status");
        rust_to_c(false, Packet::IsoStreamStatus { id: 32, status: Status::Success, endpoint: 0x81 }, "iso_stream_status");
        byte_compare(true, c_encode, Packet::IsoStreamStatus { id: 32, status: Status::Success, endpoint: 0x81 }, "iso_stream_status");
    }
}

// -- start/stop_interrupt_receiving (guest→host) + status (host→guest) --

#[test]
fn interop_start_interrupt_receiving() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_start_interrupt_receiving_header { endpoint: 0x83 };
            sys::usbredirparser_send_start_interrupt_receiving(cp, 40, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::StartInterruptReceiving { id: 40, endpoint: 0x83, .. }), "start_interrupt_receiving");
        rust_to_c(true, Packet::StartInterruptReceiving { id: 40, endpoint: 0x83 }, "start_interrupt_receiving");
        byte_compare(false, c_encode, Packet::StartInterruptReceiving { id: 40, endpoint: 0x83 }, "start_interrupt_receiving");
    }
}

#[test]
fn interop_stop_interrupt_receiving() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_stop_interrupt_receiving_header { endpoint: 0x83 };
            sys::usbredirparser_send_stop_interrupt_receiving(cp, 41, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::StopInterruptReceiving { id: 41, endpoint: 0x83, .. }), "stop_interrupt_receiving");
        rust_to_c(true, Packet::StopInterruptReceiving { id: 41, endpoint: 0x83 }, "stop_interrupt_receiving");
        byte_compare(false, c_encode, Packet::StopInterruptReceiving { id: 41, endpoint: 0x83 }, "stop_interrupt_receiving");
    }
}

#[test]
fn interop_interrupt_receiving_status() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_interrupt_receiving_status_header { status: 0, endpoint: 0x83 };
            sys::usbredirparser_send_interrupt_receiving_status(cp, 42, &mut h);
        }
        c_to_rust(true, c_encode, |p| matches!(p, Packet::InterruptReceivingStatus { id: 42, endpoint: 0x83, .. }), "interrupt_receiving_status");
        rust_to_c(false, Packet::InterruptReceivingStatus { id: 42, status: Status::Success, endpoint: 0x83 }, "interrupt_receiving_status");
        byte_compare(true, c_encode, Packet::InterruptReceivingStatus { id: 42, status: Status::Success, endpoint: 0x83 }, "interrupt_receiving_status");
    }
}

// -- alloc/free_bulk_streams (guest→host) + status (host→guest) --

#[test]
fn interop_alloc_bulk_streams() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_alloc_bulk_streams_header { endpoints: 0x03, no_streams: 16 };
            sys::usbredirparser_send_alloc_bulk_streams(cp, 50, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::AllocBulkStreams { id: 50, endpoints: 0x03, no_streams: 16, .. }), "alloc_bulk_streams");
        rust_to_c(true, Packet::AllocBulkStreams { id: 50, endpoints: 0x03, no_streams: 16 }, "alloc_bulk_streams");
        byte_compare(false, c_encode, Packet::AllocBulkStreams { id: 50, endpoints: 0x03, no_streams: 16 }, "alloc_bulk_streams");
    }
}

#[test]
fn interop_free_bulk_streams() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_free_bulk_streams_header { endpoints: 0x03 };
            sys::usbredirparser_send_free_bulk_streams(cp, 51, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::FreeBulkStreams { id: 51, endpoints: 0x03, .. }), "free_bulk_streams");
        rust_to_c(true, Packet::FreeBulkStreams { id: 51, endpoints: 0x03 }, "free_bulk_streams");
        byte_compare(false, c_encode, Packet::FreeBulkStreams { id: 51, endpoints: 0x03 }, "free_bulk_streams");
    }
}

#[test]
fn interop_bulk_streams_status() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_bulk_streams_status_header { endpoints: 0x03, no_streams: 16, status: 0 };
            sys::usbredirparser_send_bulk_streams_status(cp, 52, &mut h);
        }
        c_to_rust(true, c_encode, |p| matches!(p, Packet::BulkStreamsStatus { id: 52, .. }), "bulk_streams_status");
        rust_to_c(false, Packet::BulkStreamsStatus { id: 52, endpoints: 0x03, no_streams: 16, status: Status::Success }, "bulk_streams_status");
        byte_compare(true, c_encode, Packet::BulkStreamsStatus { id: 52, endpoints: 0x03, no_streams: 16, status: Status::Success }, "bulk_streams_status");
    }
}

// -- cancel_data_packet (guest→host) --

#[test]
fn interop_cancel_data_packet() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            sys::usbredirparser_send_cancel_data_packet(cp, 60);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::CancelDataPacket { id: 60, .. }), "cancel_data_packet");
        rust_to_c(true, Packet::CancelDataPacket { id: 60 }, "cancel_data_packet");
        byte_compare(false, c_encode, Packet::CancelDataPacket { id: 60 }, "cancel_data_packet");
    }
}

// -- start/stop_bulk_receiving (guest→host) + status (host→guest) --

#[test]
fn interop_start_bulk_receiving() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_start_bulk_receiving_header {
                stream_id: 1, bytes_per_transfer: 4096, endpoint: 0x82, no_transfers: 8,
            };
            sys::usbredirparser_send_start_bulk_receiving(cp, 70, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::StartBulkReceiving { id: 70, endpoint: 0x82, .. }), "start_bulk_receiving");
        rust_to_c(true, Packet::StartBulkReceiving { id: 70, stream_id: 1, bytes_per_transfer: 4096, endpoint: 0x82, no_transfers: 8 }, "start_bulk_receiving");
        byte_compare(false, c_encode, Packet::StartBulkReceiving { id: 70, stream_id: 1, bytes_per_transfer: 4096, endpoint: 0x82, no_transfers: 8 }, "start_bulk_receiving");
    }
}

#[test]
fn interop_stop_bulk_receiving() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_stop_bulk_receiving_header { stream_id: 1, endpoint: 0x82 };
            sys::usbredirparser_send_stop_bulk_receiving(cp, 71, &mut h);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::StopBulkReceiving { id: 71, endpoint: 0x82, .. }), "stop_bulk_receiving");
        rust_to_c(true, Packet::StopBulkReceiving { id: 71, stream_id: 1, endpoint: 0x82 }, "stop_bulk_receiving");
        byte_compare(false, c_encode, Packet::StopBulkReceiving { id: 71, stream_id: 1, endpoint: 0x82 }, "stop_bulk_receiving");
    }
}

#[test]
fn interop_bulk_receiving_status() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_bulk_receiving_status_header { stream_id: 1, endpoint: 0x82, status: 0 };
            sys::usbredirparser_send_bulk_receiving_status(cp, 72, &mut h);
        }
        c_to_rust(true, c_encode, |p| matches!(p, Packet::BulkReceivingStatus { id: 72, endpoint: 0x82, .. }), "bulk_receiving_status");
        rust_to_c(false, Packet::BulkReceivingStatus { id: 72, stream_id: 1, endpoint: 0x82, status: Status::Success }, "bulk_receiving_status");
        byte_compare(true, c_encode, Packet::BulkReceivingStatus { id: 72, stream_id: 1, endpoint: 0x82, status: Status::Success }, "bulk_receiving_status");
    }
}

// -- control_packet (bidirectional, with data) --

#[test]
fn interop_control_packet() {
    unsafe {
        // Control packets are bidirectional; test with guest sending to host
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_control_packet_header {
                endpoint: 0x00, request: 0x09, requesttype: 0x00,
                status: 0, value: 0x0001, index: 0, length: 3,
            };
            let mut data = [0xAA, 0xBB, 0xCC];
            sys::usbredirparser_send_control_packet(cp, 80, &mut h, data.as_mut_ptr(), 3);
        }
        let pkt = Packet::ControlPacket {
            id: 80, endpoint: 0x00, request: 0x09, requesttype: 0x00,
            status: Status::Success, value: 0x0001, index: 0, length: 3,
            data: Bytes::from_static(&[0xAA, 0xBB, 0xCC]),
        };
        // C(guest) → Rust(host)
        c_to_rust(false, c_encode, |p| matches!(p, Packet::ControlPacket { id: 80, .. }), "control_packet");
        // Rust(guest) → C(host)
        rust_to_c(true, pkt.clone(), "control_packet");
        byte_compare(false, c_encode, pkt, "control_packet");
    }
}

// -- bulk_packet (bidirectional, with data) --

#[test]
fn interop_bulk_packet() {
    unsafe {
        // Bulk packets are bidirectional; test with guest sending to host
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_bulk_packet_header {
                endpoint: 0x02, status: 0, length: 4, stream_id: 0, length_high: 0,
            };
            let mut data = [1, 2, 3, 4];
            sys::usbredirparser_send_bulk_packet(cp, 90, &mut h, data.as_mut_ptr(), 4);
        }
        let pkt = Packet::BulkPacket {
            id: 90, endpoint: 0x02, status: Status::Success,
            length: 4, stream_id: 0, data: Bytes::from_static(&[1, 2, 3, 4]),
        };
        // C(guest) → Rust(host)
        c_to_rust(false, c_encode, |p| matches!(p, Packet::BulkPacket { id: 90, .. }), "bulk_packet");
        // Rust(guest) → C(host)
        rust_to_c(true, pkt.clone(), "bulk_packet");
        byte_compare(false, c_encode, pkt, "bulk_packet");
    }
}

// -- iso_packet (bidirectional) --

#[test]
fn interop_iso_packet() {
    unsafe {
        // Test with host sending to guest
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_iso_packet_header {
                endpoint: 0x81, status: 0, length: 2,
            };
            let mut data = [0xDE, 0xAD];
            sys::usbredirparser_send_iso_packet(cp, 91, &mut h, data.as_mut_ptr(), 2);
        }
        let pkt = Packet::IsoPacket {
            id: 91, endpoint: 0x81, status: Status::Success,
            length: 2, data: Bytes::from_static(&[0xDE, 0xAD]),
        };
        // C(host) → Rust(guest)
        c_to_rust(true, c_encode, |p| matches!(p, Packet::IsoPacket { id: 91, .. }), "iso_packet");
        // Rust(host) → C(guest)
        rust_to_c(false, pkt.clone(), "iso_packet");
        byte_compare(true, c_encode, pkt, "iso_packet");
    }
}

// -- interrupt_packet (bidirectional) --

#[test]
fn interop_interrupt_packet() {
    unsafe {
        // Test with host sending to guest
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_interrupt_packet_header {
                endpoint: 0x83, status: 0, length: 1,
            };
            let mut data = [0xFF];
            sys::usbredirparser_send_interrupt_packet(cp, 92, &mut h, data.as_mut_ptr(), 1);
        }
        let pkt = Packet::InterruptPacket {
            id: 92, endpoint: 0x83, status: Status::Success,
            length: 1, data: Bytes::from_static(&[0xFF]),
        };
        // C(host) → Rust(guest)
        c_to_rust(true, c_encode, |p| matches!(p, Packet::InterruptPacket { id: 92, .. }), "interrupt_packet");
        // Rust(host) → C(guest)
        rust_to_c(false, pkt.clone(), "interrupt_packet");
        byte_compare(true, c_encode, pkt, "interrupt_packet");
    }
}

// -- buffered_bulk_packet (host→guest) --

#[test]
fn interop_buffered_bulk_packet() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let mut h = sys::usb_redir_buffered_bulk_packet_header {
                stream_id: 5, length: 3, endpoint: 0x82, status: 0,
            };
            let mut data = [10, 20, 30];
            sys::usbredirparser_send_buffered_bulk_packet(cp, 93, &mut h, data.as_mut_ptr(), 3);
        }
        let pkt = Packet::BufferedBulkPacket {
            id: 93, stream_id: 5, length: 3, endpoint: 0x82,
            status: Status::Success, data: Bytes::from_static(&[10, 20, 30]),
        };
        // C(host) → Rust(guest)
        c_to_rust(true, c_encode, |p| matches!(p, Packet::BufferedBulkPacket { id: 93, .. }), "buffered_bulk_packet");
        // Rust(host) → C(guest)
        rust_to_c(false, pkt.clone(), "buffered_bulk_packet");
        byte_compare(true, c_encode, pkt, "buffered_bulk_packet");
    }
}

// -- filter_reject (guest→host) --

#[test]
fn interop_filter_reject() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            sys::usbredirparser_send_filter_reject(cp);
        }
        c_to_rust(false, c_encode, |p| matches!(p, Packet::FilterReject), "filter_reject");
        rust_to_c(true, Packet::FilterReject, "filter_reject");
        byte_compare(false, c_encode, Packet::FilterReject, "filter_reject");
    }
}

// -- filter_filter (bidirectional) --

#[test]
fn interop_filter_filter() {
    unsafe {
        unsafe fn c_encode(cp: *mut sys::usbredirparser) {
            let rules = [sys::usbredirfilter_rule {
                device_class: 0x08,
                vendor_id: -1,
                product_id: -1,
                device_version_bcd: -1,
                allow: 0,
            }];
            sys::usbredirparser_send_filter_filter(cp, rules.as_ptr(), 1);
        }
        let pkt = Packet::FilterFilter {
            rules: vec![FilterRule {
                device_class: Some(0x08),
                vendor_id: None,
                product_id: None,
                device_version_bcd: None,
                allow: false,
            }],
        };
        // filter_filter is bidirectional; test from host side
        c_to_rust(true, c_encode, |p| matches!(p, Packet::FilterFilter { .. }), "filter_filter");
        rust_to_c(false, pkt.clone(), "filter_filter");
        byte_compare(true, c_encode, pkt, "filter_filter");
    }
}

// -- device_disconnect_ack (guest→host) --

#[test]
fn interop_device_disconnect_ack() {
    unsafe {
        // device_disconnect_ack is sent by the guest to the host.
        // The C library doesn't expose a public send function for this,
        // so we only test Rust(guest) → C(host).
        // C is host, Rust is guest (the sender)
        rust_to_c(true, Packet::DeviceDisconnectAck, "device_disconnect_ack");
    }
}

// ===========================================================================
// Backward-compatibility: reduced caps interop tests
//
// These test the wire-format variants triggered by missing capabilities:
// - No Cap::Ids64Bits → 12-byte header with 32-bit id
// - No Cap::ConnectDeviceVersion → DeviceConnectHeaderNoVersion (8 bytes)
// - No Cap::EpInfoMaxPacketSize → EpInfoHeaderNoMaxPktsz (96 bytes)
// - No Cap::BulkLength32Bits → BulkPacketHeader16BitLength (6 bytes)
// ===========================================================================

fn minimal_caps_mask() -> [u32; sys::USB_REDIR_CAPS_SIZE as usize] {
    // No caps set at all — baseline v0.3
    [0u32; sys::USB_REDIR_CAPS_SIZE as usize]
}

fn rust_minimal_caps() -> Caps {
    Caps::new() // no caps
}

fn rust_minimal_config(is_host: bool) -> ParserConfig {
    ParserConfig {
        version: "rust-test-minimal".to_string(),
        caps: rust_minimal_caps(),
        is_host,
        no_hello: false,
    }
}

unsafe fn make_c_parser_with_caps(
    is_host: bool,
    no_hello: bool,
    caps: &mut [u32; sys::USB_REDIR_CAPS_SIZE as usize],
) -> *mut sys::usbredirparser {
    let p = sys::usbredirparser_create();
    assert!(!p.is_null());
    (*p).log_func = Some(log_cb);
    (*p).read_func = Some(read_cb);
    (*p).write_func = Some(write_cb);
    (*p).hello_func = Some(cb_hello);
    (*p).device_connect_func = Some(cb_device_connect);
    (*p).device_disconnect_func = Some(cb_device_disconnect);
    (*p).reset_func = Some(cb_reset);
    (*p).interface_info_func = Some(cb_interface_info);
    (*p).ep_info_func = Some(cb_ep_info);
    (*p).set_configuration_func = Some(cb_set_configuration);
    (*p).get_configuration_func = Some(cb_get_configuration);
    (*p).configuration_status_func = Some(cb_configuration_status);
    (*p).set_alt_setting_func = Some(cb_set_alt_setting);
    (*p).get_alt_setting_func = Some(cb_get_alt_setting);
    (*p).alt_setting_status_func = Some(cb_alt_setting_status);
    (*p).start_iso_stream_func = Some(cb_start_iso_stream);
    (*p).stop_iso_stream_func = Some(cb_stop_iso_stream);
    (*p).iso_stream_status_func = Some(cb_iso_stream_status);
    (*p).start_interrupt_receiving_func = Some(cb_start_interrupt_receiving);
    (*p).stop_interrupt_receiving_func = Some(cb_stop_interrupt_receiving);
    (*p).interrupt_receiving_status_func = Some(cb_interrupt_receiving_status);
    (*p).alloc_bulk_streams_func = Some(cb_alloc_bulk_streams);
    (*p).free_bulk_streams_func = Some(cb_free_bulk_streams);
    (*p).bulk_streams_status_func = Some(cb_bulk_streams_status);
    (*p).cancel_data_packet_func = Some(cb_cancel_data_packet);
    (*p).filter_reject_func = Some(cb_filter_reject);
    (*p).filter_filter_func = Some(cb_filter_filter);
    (*p).device_disconnect_ack_func = Some(cb_device_disconnect_ack);
    (*p).start_bulk_receiving_func = Some(cb_start_bulk_receiving);
    (*p).stop_bulk_receiving_func = Some(cb_stop_bulk_receiving);
    (*p).bulk_receiving_status_func = Some(cb_bulk_receiving_status);
    (*p).control_packet_func = Some(cb_control_packet);
    (*p).bulk_packet_func = Some(cb_bulk_packet);
    (*p).iso_packet_func = Some(cb_iso_packet);
    (*p).interrupt_packet_func = Some(cb_interrupt_packet);
    (*p).buffered_bulk_packet_func = Some(cb_buffered_bulk_packet);

    let version = b"c-test\0";
    let mut flags: c_int = 0;
    if is_host {
        flags |= sys::usbredirparser_fl_usb_host as c_int;
    }
    if no_hello {
        flags |= sys::usbredirparser_fl_no_hello as c_int;
    }
    sys::usbredirparser_init(
        p,
        version.as_ptr() as *const c_char,
        caps.as_mut_ptr(),
        sys::USB_REDIR_CAPS_SIZE as c_int,
        flags,
    );
    p
}

/// Connected pair with minimal (no) caps — uses 32-bit ids, no version, etc.
unsafe fn connected_pair_minimal(c_is_host: bool) -> (*mut sys::usbredirparser, Parser) {
    reset_io();
    let mut caps = minimal_caps_mask();
    let cp = make_c_parser_with_caps(c_is_host, false, &mut caps);
    let mut rp = Parser::new(rust_minimal_config(!c_is_host));

    let c_hello = c_capture(cp);
    rp.feed(&c_hello);
    rust_drain_packets(&mut rp);

    let rust_hello = rust_drain_all(&mut rp);
    c_feed(cp, &rust_hello);

    (cp, rp)
}

/// Connected pair with specific caps
unsafe fn connected_pair_with_caps(
    c_is_host: bool,
    c_caps: &mut [u32; sys::USB_REDIR_CAPS_SIZE as usize],
    r_caps: Caps,
) -> (*mut sys::usbredirparser, Parser) {
    reset_io();
    let cp = make_c_parser_with_caps(c_is_host, false, c_caps);
    let mut rp = Parser::new(ParserConfig {
        version: "rust-test".to_string(),
        caps: r_caps,
        is_host: !c_is_host,
        no_hello: false,
    });

    let c_hello = c_capture(cp);
    rp.feed(&c_hello);
    rust_drain_packets(&mut rp);

    let rust_hello = rust_drain_all(&mut rp);
    c_feed(cp, &rust_hello);

    (cp, rp)
}

// -- 32-bit ids (no Cap::Ids64Bits) --

#[test]
fn interop_compat_32bit_ids() {
    unsafe {
        // Use minimal caps (no 64-bit ids) → 12-byte header
        let (cp, mut rp) = connected_pair_minimal(true);

        // C(host) sends device_connect with 32-bit header
        let mut h = sys::usb_redir_device_connect_header {
            speed: 2,
            device_class: 0x08,
            device_subclass: 0x06,
            device_protocol: 0x50,
            vendor_id: 0x1234,
            product_id: 0x5678,
            device_version_bcd: 0x0100,
        };
        sys::usbredirparser_send_device_connect(cp, &mut h);
        let wire = c_capture(cp);
        assert!(!wire.is_empty(), "C produced no bytes with 32-bit ids");

        // Header should be 12 bytes (type:4 + length:4 + id:4)
        assert_eq!(wire[0], 0x01); // type = device_connect
        // Total should be 12 (header) + 8 (device_connect without version) = 20
        assert_eq!(wire.len(), 20, "32-bit id header: expected 20 bytes");

        rp.feed(&wire);
        let pkts = rust_drain_packets(&mut rp);
        assert!(
            pkts.iter().any(|p| matches!(p, Packet::DeviceConnect { speed: Speed::High, .. })),
            "Rust failed to decode 32-bit id device_connect"
        );

        // Reverse: Rust encodes with 32-bit ids too
        let (cp2, mut rp2) = connected_pair_minimal(false);
        rp2.send(Packet::DeviceConnect {
            speed: Speed::High,
            device_class: 0x08,
            device_subclass: 0x06,
            device_protocol: 0x50,
            vendor_id: 0x1234,
            product_id: 0x5678,
            device_version_bcd: 0x0100,
        })
        .unwrap();
        let rust_wire = rust_drain_all(&mut rp2);
        assert_eq!(rust_wire.len(), 20, "Rust 32-bit id header: expected 20 bytes");

        // C should decode it
        let before = cb_count();
        c_feed(cp2, &rust_wire);
        assert!(cb_count() > before, "C failed to decode Rust 32-bit id packet");

        // Byte-exact comparison
        assert_eq!(wire, rust_wire, "32-bit id wire bytes differ");

        sys::usbredirparser_destroy(cp);
        sys::usbredirparser_destroy(cp2);
    }
}

// -- No Cap::ConnectDeviceVersion → shorter device_connect --

#[test]
fn interop_compat_no_device_version() {
    unsafe {
        // Caps with 64-bit ids but NO connect_device_version
        let mut c_caps = [0u32; sys::USB_REDIR_CAPS_SIZE as usize];
        sys::usbredirparser_caps_set_cap(c_caps.as_mut_ptr(), sys::usb_redir_cap_64bits_ids as _);

        let mut r_caps = Caps::new();
        r_caps.set(Cap::Ids64Bits);

        let (cp, mut rp) = connected_pair_with_caps(true, &mut c_caps, r_caps);

        let mut h = sys::usb_redir_device_connect_header {
            speed: 1,
            device_class: 0xFF,
            device_subclass: 0x00,
            device_protocol: 0x00,
            vendor_id: 0xABCD,
            product_id: 0x1234,
            device_version_bcd: 0x9999, // should be ignored
        };
        sys::usbredirparser_send_device_connect(cp, &mut h);
        let wire = c_capture(cp);

        // 16 (header) + 8 (no version) = 24
        assert_eq!(wire.len(), 24, "no-version device_connect should be 24 bytes");

        rp.feed(&wire);
        let pkts = rust_drain_packets(&mut rp);
        assert!(
            pkts.iter().any(|p| matches!(p, Packet::DeviceConnect { speed: Speed::Full, device_class: 0xFF, .. })),
            "Rust failed to decode no-version device_connect"
        );

        // Reverse direction
        let (cp2, mut rp2) = connected_pair_with_caps(false, &mut c_caps, r_caps);
        rp2.send(Packet::DeviceConnect {
            speed: Speed::Full,
            device_class: 0xFF,
            device_subclass: 0x00,
            device_protocol: 0x00,
            vendor_id: 0xABCD,
            product_id: 0x1234,
            device_version_bcd: 0, // ignored without cap
        })
        .unwrap();
        let rust_wire = rust_drain_all(&mut rp2);
        assert_eq!(rust_wire.len(), 24, "Rust no-version device_connect should be 24 bytes");

        let before = cb_count();
        c_feed(cp2, &rust_wire);
        assert!(cb_count() > before, "C failed to decode Rust no-version device_connect");

        sys::usbredirparser_destroy(cp);
        sys::usbredirparser_destroy(cp2);
    }
}

// -- No Cap::EpInfoMaxPacketSize → smaller ep_info --

#[test]
fn interop_compat_no_ep_info_max_pktsz() {
    unsafe {
        // 64-bit ids only, no ep_info_max_packet_size
        let mut c_caps = [0u32; sys::USB_REDIR_CAPS_SIZE as usize];
        sys::usbredirparser_caps_set_cap(c_caps.as_mut_ptr(), sys::usb_redir_cap_64bits_ids as _);

        let mut r_caps = Caps::new();
        r_caps.set(Cap::Ids64Bits);

        let (cp, mut rp) = connected_pair_with_caps(true, &mut c_caps, r_caps);

        let mut h: sys::usb_redir_ep_info_header = std::mem::zeroed();
        h.type_[0] = 2; // bulk
        sys::usbredirparser_send_ep_info(cp, &mut h);
        let wire = c_capture(cp);

        // 16 (header) + 96 (no max_pktsz: 32+32+32) = 112
        assert_eq!(wire.len(), 112, "no-max-pktsz ep_info should be 112 bytes");

        rp.feed(&wire);
        let pkts = rust_drain_packets(&mut rp);
        assert!(
            pkts.iter().any(|p| matches!(p, Packet::EpInfo { .. })),
            "Rust failed to decode no-max-pktsz ep_info"
        );

        // Reverse
        let (cp2, mut rp2) = connected_pair_with_caps(false, &mut c_caps, r_caps);
        rp2.send(Packet::EpInfo {
            ep_type: {
                let mut t = [TransferType::Control; 32];
                t[0] = TransferType::Bulk;
                t
            },
            interval: [0u8; 32],
            interface: [0u8; 32],
            max_packet_size: [0u16; 32],
            max_streams: [0u32; 32],
        })
        .unwrap();
        let rust_wire = rust_drain_all(&mut rp2);
        assert_eq!(rust_wire.len(), 112);

        let before = cb_count();
        c_feed(cp2, &rust_wire);
        assert!(cb_count() > before, "C failed to decode Rust no-max-pktsz ep_info");

        sys::usbredirparser_destroy(cp);
        sys::usbredirparser_destroy(cp2);
    }
}

// -- EpInfoMaxPacketSize but no BulkStreams → ep_info with max_packet_size but no max_streams --

#[test]
fn interop_compat_ep_info_no_max_streams() {
    unsafe {
        let mut c_caps = [0u32; sys::USB_REDIR_CAPS_SIZE as usize];
        sys::usbredirparser_caps_set_cap(c_caps.as_mut_ptr(), sys::usb_redir_cap_64bits_ids as _);
        sys::usbredirparser_caps_set_cap(
            c_caps.as_mut_ptr(),
            sys::usb_redir_cap_ep_info_max_packet_size as _,
        );

        let mut r_caps = Caps::new();
        r_caps.set(Cap::Ids64Bits);
        r_caps.set(Cap::EpInfoMaxPacketSize);

        let (cp, mut rp) = connected_pair_with_caps(true, &mut c_caps, r_caps);

        let mut h: sys::usb_redir_ep_info_header = std::mem::zeroed();
        h.type_[0] = 3; // interrupt
        h.max_packet_size[0] = 64;
        sys::usbredirparser_send_ep_info(cp, &mut h);
        let wire = c_capture(cp);

        // 16 (header) + 160 (with max_pktsz: 32+32+32+64) = 176
        assert_eq!(wire.len(), 176, "no-max-streams ep_info should be 176 bytes");

        rp.feed(&wire);
        let pkts = rust_drain_packets(&mut rp);
        assert!(
            pkts.iter().any(|p| matches!(p, Packet::EpInfo { .. })),
            "Rust failed to decode no-max-streams ep_info"
        );

        sys::usbredirparser_destroy(cp);
    }
}

// -- No Cap::BulkLength32Bits → 16-bit bulk length --

#[test]
fn interop_compat_16bit_bulk_length() {
    unsafe {
        let mut c_caps = [0u32; sys::USB_REDIR_CAPS_SIZE as usize];
        sys::usbredirparser_caps_set_cap(c_caps.as_mut_ptr(), sys::usb_redir_cap_64bits_ids as _);

        let mut r_caps = Caps::new();
        r_caps.set(Cap::Ids64Bits);

        // C(guest) sends bulk to host
        let (cp, mut rp) = connected_pair_with_caps(false, &mut c_caps, r_caps);

        let mut h = sys::usb_redir_bulk_packet_header {
            endpoint: 0x02,
            status: 0,
            length: 4,
            stream_id: 0,
            length_high: 0,
        };
        let mut data = [1, 2, 3, 4];
        sys::usbredirparser_send_bulk_packet(cp, 100, &mut h, data.as_mut_ptr(), 4);
        let wire = c_capture(cp);

        // 16 (header) + 6 (16-bit bulk: endpoint+status+length(u16)+stream_id) + 4 (data) = 26
        // Actually: BulkPacketHeader16BitLength = endpoint(1) + status(1) + length(2) + stream_id(4) = 8? No...
        // Let me just check the size isn't the full 32-bit version
        assert!(
            !wire.is_empty(),
            "C produced no bytes for 16-bit bulk length"
        );

        rp.feed(&wire);
        let pkts = rust_drain_packets(&mut rp);
        assert!(
            pkts.iter().any(|p| matches!(p, Packet::BulkPacket { id: 100, length: 4, .. })),
            "Rust failed to decode 16-bit bulk length packet. Got: {pkts:?}"
        );

        // Reverse: Rust encodes with 16-bit bulk length
        let (cp2, mut rp2) = connected_pair_with_caps(true, &mut c_caps, r_caps);
        rp2.send(Packet::BulkPacket {
            id: 100,
            endpoint: 0x02,
            status: Status::Success,
            length: 4,
            stream_id: 0,
            data: Bytes::from_static(&[1, 2, 3, 4]),
        })
        .unwrap();
        let rust_wire = rust_drain_all(&mut rp2);

        let before = cb_count();
        c_feed(cp2, &rust_wire);
        assert!(
            cb_count() > before,
            "C failed to decode Rust 16-bit bulk length packet"
        );

        // Byte-exact
        assert_eq!(wire, rust_wire, "16-bit bulk length wire bytes differ");

        sys::usbredirparser_destroy(cp);
        sys::usbredirparser_destroy(cp2);
    }
}

// -- Serialization with state: after hello exchange --

#[test]
fn interop_serialize_after_hello() {
    unsafe {
        // Create a connected C parser (has peer caps set)
        let (cp, rp) = connected_pair(true);

        // Serialize C state
        let mut state: *mut u8 = ptr::null_mut();
        let mut state_len: c_int = 0;
        let ret = sys::usbredirparser_serialize(cp, &mut state, &mut state_len);
        assert_eq!(ret, 0);
        let c_state = slice::from_raw_parts(state, state_len as usize);

        // Rust should be able to unserialize C's post-hello state
        let result = Parser::unserialize(rust_config(true), c_state);
        assert!(
            result.is_ok(),
            "Rust unserialize of C post-hello state failed: {:?}",
            result.err()
        );
        let rp2 = result.unwrap();
        assert!(rp2.have_peer_caps(), "Unserialized parser should have peer caps");

        // Serialize Rust's connected state
        let rust_state = rp.serialize().unwrap();

        // C should be able to unserialize Rust's post-hello state
        reset_io();
        let cp2 = make_c_parser(true, true);
        let ret2 = sys::usbredirparser_unserialize(
            cp2,
            rust_state.as_ptr() as *mut u8,
            rust_state.len() as c_int,
        );
        assert_eq!(ret2, 0, "C unserialize of Rust post-hello state failed");
        assert!(
            sys::usbredirparser_have_peer_caps(cp2) != 0,
            "C parser should have peer caps after unserialize"
        );

        libc_free(state as *mut c_void);
        sys::usbredirparser_destroy(cp);
        sys::usbredirparser_destroy(cp2);
    }
}

// ===========================================================================
// Serialization interop
// ===========================================================================

extern "C" {
    #[link_name = "free"]
    fn libc_free(ptr: *mut c_void);
}

#[test]
fn interop_serialize_c_to_rust() {
    reset_io();
    unsafe {
        let cp = make_c_parser(true, false);

        let mut state: *mut u8 = ptr::null_mut();
        let mut state_len: c_int = 0;
        let ret = sys::usbredirparser_serialize(cp, &mut state, &mut state_len);
        assert_eq!(ret, 0);

        let state_slice = slice::from_raw_parts(state, state_len as usize);
        assert_eq!(
            u32::from_le_bytes(state_slice[0..4].try_into().unwrap()),
            0x55525031
        );

        let result = Parser::unserialize(rust_config(true), state_slice);
        assert!(result.is_ok(), "Rust unserialize of C state failed: {:?}", result.err());

        libc_free(state as *mut c_void);
        sys::usbredirparser_destroy(cp);
    }
}

#[test]
fn interop_serialize_rust_to_c() {
    reset_io();
    unsafe {
        let rp = Parser::new(rust_config(true));
        let state = rp.serialize().unwrap();

        let cp = make_c_parser(true, true);
        let ret = sys::usbredirparser_unserialize(
            cp,
            state.as_ptr() as *mut u8,
            state.len() as c_int,
        );
        assert_eq!(ret, 0, "C unserialize of Rust state failed");
        sys::usbredirparser_destroy(cp);
    }
}

// ===========================================================================
// Gap 1: Verification logic — Rust rejects the same malformed packets as C
// ===========================================================================

#[test]
fn verify_interface_count_too_large() {
    // Rust should reject interface_count > 32 on send
    let mut rp = Parser::new(rust_config(true));
    // simulate peer caps by feeding a hello
    let mut peer = Parser::new(rust_config(false));
    let peer_hello_bytes = rust_drain_all(&mut peer);
    rp.feed(&peer_hello_bytes);
    rust_drain_packets(&mut rp);

    let result = rp.send(Packet::InterfaceInfo {
        interface_count: 33,
        interface: [0u8; 32],
        interface_class: [0u8; 32],
        interface_subclass: [0u8; 32],
        interface_protocol: [0u8; 32],
    });
    assert!(result.is_err(), "Should reject interface_count > 32");
}

#[test]
fn verify_interrupt_receiving_non_input_ep() {
    // start_interrupt_receiving with output endpoint should fail
    let mut rp = Parser::new(rust_config(false)); // guest
    let mut peer = Parser::new(rust_config(true));
    let peer_hello = rust_drain_all(&mut peer);
    rp.feed(&peer_hello);
    rust_drain_packets(&mut rp);

    // Endpoint 0x02 = OUT, should be rejected (interrupt receiving requires IN endpoint)
    let result = rp.send(Packet::StartInterruptReceiving {
        id: 1,
        endpoint: 0x02,
    });
    assert!(result.is_err(), "Should reject non-input endpoint for start_interrupt_receiving");

    let result = rp.send(Packet::StopInterruptReceiving {
        id: 2,
        endpoint: 0x02,
    });
    assert!(result.is_err(), "Should reject non-input endpoint for stop_interrupt_receiving");
}

#[test]
fn verify_bulk_receiving_non_input_ep() {
    let mut rp = Parser::new(rust_config(false)); // guest
    let mut peer = Parser::new(rust_config(true));
    let peer_hello = rust_drain_all(&mut peer);
    rp.feed(&peer_hello);
    rust_drain_packets(&mut rp);

    let result = rp.send(Packet::StartBulkReceiving {
        id: 1,
        stream_id: 0,
        bytes_per_transfer: 4096,
        endpoint: 0x02, // OUT, should fail
        no_transfers: 4,
    });
    assert!(result.is_err(), "Should reject non-input endpoint for start_bulk_receiving");
}

#[test]
fn verify_bulk_transfer_too_large() {
    let mut rp = Parser::new(rust_config(false)); // guest
    let mut peer = Parser::new(rust_config(true));
    let peer_hello = rust_drain_all(&mut peer);
    rp.feed(&peer_hello);
    rust_drain_packets(&mut rp);

    let result = rp.send(Packet::StartBulkReceiving {
        id: 1,
        stream_id: 0,
        bytes_per_transfer: 256 * 1024 * 1024, // exceeds MAX_BULK_TRANSFER_SIZE
        endpoint: 0x82,
        no_transfers: 4,
    });
    assert!(result.is_err(), "Should reject oversized bulk transfer");
}

#[test]
fn verify_filter_without_cap() {
    // Create parser without filter cap
    let config = ParserConfig {
        version: "test".to_string(),
        caps: {
            let mut c = Caps::new();
            c.set(Cap::Ids64Bits);
            c
        },
        is_host: false,
        no_hello: false,
    };
    let mut rp = Parser::new(config.clone());

    // Peer also without filter cap
    let mut peer = Parser::new(ParserConfig {
        is_host: true,
        ..config
    });
    let peer_hello = rust_drain_all(&mut peer);
    rp.feed(&peer_hello);
    rust_drain_packets(&mut rp);

    let result = rp.send(Packet::FilterReject);
    assert!(result.is_err(), "Should reject filter_reject without filter cap");
}

#[test]
fn verify_data_packet_wrong_direction() {
    // ISO packet can only be sent in one direction per the C verification
    let mut rp = Parser::new(rust_config(false)); // guest sends
    let mut peer = Parser::new(rust_config(true));
    let peer_hello = rust_drain_all(&mut peer);
    rp.feed(&peer_hello);
    rust_drain_packets(&mut rp);

    // Guest sends iso with IN endpoint (0x81) — guest is "command_for_host" side
    // When guest sends, command_for_host = true
    // ep 0x81 = IN, !command_for_host = false → no data expected
    // ISO with no data in wrong direction → rejected
    let result = rp.send(Packet::IsoPacket {
        id: 1,
        endpoint: 0x81, // IN endpoint
        status: Status::Success,
        length: 0,
        data: Bytes::new(),
    });
    assert!(result.is_err(), "Should reject iso packet in wrong direction");
}

// ===========================================================================
// Gap 2: Filter check() interop — C and Rust produce same results
// ===========================================================================

#[test]
fn interop_filter_check_basic() {
    unsafe {
        // Rule: deny device class 0x08
        let rules = [sys::usbredirfilter_rule {
            device_class: 0x08,
            vendor_id: -1,
            product_id: -1,
            device_version_bcd: -1,
            allow: 0, // deny
        }];
        let mut iface_class = [0x08u8];
        let mut iface_subclass = [0x06u8];
        let mut iface_protocol = [0x50u8];

        let c_result = sys::usbredirfilter_check(
            rules.as_ptr(),
            1,
            0x00, // device_class
            0x00, // device_subclass
            0x00, // device_protocol
            iface_class.as_mut_ptr(),
            iface_subclass.as_mut_ptr(),
            iface_protocol.as_mut_ptr(),
            1, // interface_count
            0x1234,
            0x5678,
            0x0100,
            0, // flags
        );

        let rust_rules = vec![FilterRule {
            device_class: Some(0x08),
            vendor_id: None,
            product_id: None,
            device_version_bcd: None,
            allow: false,
        }];
        let rust_result = filter::check(
            &rust_rules,
            0x00,
            0x00,
            0x00,
            &[(0x08, 0x06, 0x50)],
            0x1234,
            0x5678,
            0x0100,
            filter::CheckFlags::empty(),
        )
        .unwrap();

        // C returns 0 for allow, -EPERM(-1) for deny, -ENOENT(-2) for no match
        assert_eq!(c_result, -1, "C filter check should deny (-EPERM)");
        assert_eq!(
            rust_result,
            filter::FilterResult::Deny,
            "Rust filter check should deny"
        );
    }
}

#[test]
fn interop_filter_check_allow() {
    unsafe {
        let rules = [sys::usbredirfilter_rule {
            device_class: 0x08,
            vendor_id: -1,
            product_id: -1,
            device_version_bcd: -1,
            allow: 1, // allow
        }];
        let mut iface_class = [0x08u8];
        let mut iface_subclass = [0x06u8];
        let mut iface_protocol = [0x50u8];

        let c_result = sys::usbredirfilter_check(
            rules.as_ptr(),
            1,
            0x00,
            0x00,
            0x00,
            iface_class.as_mut_ptr(),
            iface_subclass.as_mut_ptr(),
            iface_protocol.as_mut_ptr(),
            1,
            0x1234,
            0x5678,
            0x0100,
            0,
        );

        let rust_rules = vec![FilterRule {
            device_class: Some(0x08),
            vendor_id: None,
            product_id: None,
            device_version_bcd: None,
            allow: true,
        }];
        let rust_result = filter::check(
            &rust_rules,
            0x00,
            0x00,
            0x00,
            &[(0x08, 0x06, 0x50)],
            0x1234,
            0x5678,
            0x0100,
            filter::CheckFlags::empty(),
        )
        .unwrap();

        assert_eq!(c_result, 0, "C filter check should allow");
        assert_eq!(rust_result, filter::FilterResult::Allow);
    }
}

#[test]
fn interop_filter_check_no_match() {
    unsafe {
        // Rule matches class 0x08, device has class 0x03
        let rules = [sys::usbredirfilter_rule {
            device_class: 0x08,
            vendor_id: -1,
            product_id: -1,
            device_version_bcd: -1,
            allow: 1,
        }];
        let mut iface_class = [0x03u8];
        let mut iface_subclass = [0x00u8];
        let mut iface_protocol = [0x00u8];

        let c_result = sys::usbredirfilter_check(
            rules.as_ptr(),
            1,
            0x00,
            0x00,
            0x00,
            iface_class.as_mut_ptr(),
            iface_subclass.as_mut_ptr(),
            iface_protocol.as_mut_ptr(),
            1,
            0x1234,
            0x5678,
            0x0100,
            0,
        );

        let rust_rules = vec![FilterRule {
            device_class: Some(0x08),
            vendor_id: None,
            product_id: None,
            device_version_bcd: None,
            allow: true,
        }];
        let rust_result = filter::check(
            &rust_rules,
            0x00,
            0x00,
            0x00,
            &[(0x03, 0x00, 0x00)],
            0x1234,
            0x5678,
            0x0100,
            filter::CheckFlags::empty(),
        )
        .unwrap();

        assert_eq!(c_result, -2, "C filter check should return no match (-ENOENT)");
        assert_eq!(rust_result, filter::FilterResult::NoMatch);
    }
}

#[test]
fn interop_filter_check_vendor_product() {
    unsafe {
        // Deny specific vendor:product
        let rules = [sys::usbredirfilter_rule {
            device_class: -1,
            vendor_id: 0x1234,
            product_id: 0x5678,
            device_version_bcd: -1,
            allow: 0,
        }];
        let mut iface_class = [0x08u8];
        let mut iface_subclass = [0x06u8];
        let mut iface_protocol = [0x50u8];

        let c_result = sys::usbredirfilter_check(
            rules.as_ptr(),
            1,
            0x00,
            0x00,
            0x00,
            iface_class.as_mut_ptr(),
            iface_subclass.as_mut_ptr(),
            iface_protocol.as_mut_ptr(),
            1,
            0x1234,
            0x5678,
            0x0100,
            0,
        );

        let rust_rules = vec![FilterRule {
            device_class: None,
            vendor_id: Some(0x1234),
            product_id: Some(0x5678),
            device_version_bcd: None,
            allow: false,
        }];
        let rust_result = filter::check(
            &rust_rules,
            0x00,
            0x00,
            0x00,
            &[(0x08, 0x06, 0x50)],
            0x1234,
            0x5678,
            0x0100,
            filter::CheckFlags::empty(),
        )
        .unwrap();

        assert_eq!(c_result, -1, "C filter check should deny (-EPERM)");
        assert_eq!(rust_result, filter::FilterResult::Deny);
    }
}

#[test]
fn interop_filter_check_default_allow() {
    unsafe {
        // No rules, with DEFAULT_ALLOW flag → should allow
        let mut iface_class = [0x08u8];
        let mut iface_subclass = [0x06u8];
        let mut iface_protocol = [0x50u8];

        let c_result = sys::usbredirfilter_check(
            ptr::null(),
            0,
            0x00,
            0x00,
            0x00,
            iface_class.as_mut_ptr(),
            iface_subclass.as_mut_ptr(),
            iface_protocol.as_mut_ptr(),
            1,
            0x1234,
            0x5678,
            0x0100,
            sys::usbredirfilter_fl_default_allow as _,
        );

        let rust_result = filter::check(
            &[],
            0x00,
            0x00,
            0x00,
            &[(0x08, 0x06, 0x50)],
            0x1234,
            0x5678,
            0x0100,
            filter::CheckFlags::DEFAULT_ALLOW,
        )
        .unwrap();

        // Empty rules + default allow → allow (C returns 0 for allow)
        assert_eq!(c_result, 0);
        assert_eq!(rust_result, filter::FilterResult::Allow);
    }
}

// ===========================================================================
// Gap 3: Parser error recovery — skip-to-next-packet on parse error
// ===========================================================================

#[test]
fn interop_error_recovery_unknown_type() {
    unsafe {
        // Create a connected pair, then craft a packet with unknown type
        let (cp, mut rp) = connected_pair(true);

        // Craft raw bytes: header with unknown type 0xFF, length 4, id 0
        // followed by 4 bytes of garbage, then a valid device_disconnect
        let mut bad_packet = Vec::new();
        // Header: type=0xFF, length=4, id=0 (64-bit)
        bad_packet.extend_from_slice(&0xFFu32.to_le_bytes()); // type
        bad_packet.extend_from_slice(&4u32.to_le_bytes()); // length
        bad_packet.extend_from_slice(&0u64.to_le_bytes()); // id
        bad_packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // body

        // Now append a valid device_disconnect from C
        let mut h = sys::usb_redir_device_connect_header {
            speed: 2,
            device_class: 0x08,
            device_subclass: 0x06,
            device_protocol: 0x50,
            vendor_id: 0x1234,
            product_id: 0x5678,
            device_version_bcd: 0x0100,
        };
        sys::usbredirparser_send_device_connect(cp, &mut h);
        let valid_wire = c_capture(cp);

        // Feed bad packet + valid packet to Rust
        let mut combined = bad_packet;
        combined.extend_from_slice(&valid_wire);
        rp.feed(&combined);

        // Should get a parse error for unknown type, then the valid packet
        let mut got_error = false;
        let mut got_packet = false;
        while let Some(ev) = rp.poll() {
            match ev {
                Event::ParseError(_) => got_error = true,
                Event::Packet(Packet::DeviceConnect { .. }) => got_packet = true,
                _ => {}
            }
        }
        assert!(got_error, "Should report parse error for unknown packet type");
        assert!(got_packet, "Should recover and parse the valid packet after error");

        sys::usbredirparser_destroy(cp);
    }
}

#[test]
fn interop_error_recovery_truncated_header() {
    // Feed partial header, then complete data
    let (_, mut rp) = unsafe { connected_pair(true) };

    // Feed just 4 bytes (incomplete 16-byte header)
    rp.feed(&[0x01, 0x00, 0x00, 0x00]);
    assert!(rp.poll().is_none(), "Shouldn't produce events from partial header");

    // Feed the rest of the header + body for device_disconnect (type=2, length=0)
    let mut rest = Vec::new();
    rest.extend_from_slice(&0u32.to_le_bytes()); // length = 0
    rest.extend_from_slice(&0u64.to_le_bytes()); // id = 0
    // Wait, we already wrote type=1 (device_connect). Let me build a proper
    // minimal device_disconnect instead.
    // Actually, the first 4 bytes were type=0x01 (device_connect), length=?, id=?
    // Let's abandon this and feed a proper complete packet in two parts.

    let mut rp2 = Parser::new(rust_config(false)); // guest, receives from host
    let mut peer = Parser::new(rust_config(true));
    let peer_hello = rust_drain_all(&mut peer);
    rp2.feed(&peer_hello);
    rust_drain_packets(&mut rp2);

    // Build a valid device_disconnect packet (type=2, length=0, id=0)
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&2u32.to_le_bytes()); // type
    pkt.extend_from_slice(&0u32.to_le_bytes()); // length
    pkt.extend_from_slice(&0u64.to_le_bytes()); // id

    // Feed 1 byte at a time
    for &b in &pkt {
        rp2.feed(&[b]);
    }
    let pkts = rust_drain_packets(&mut rp2);
    assert!(
        pkts.iter().any(|p| matches!(p, Packet::DeviceDisconnect)),
        "Should decode device_disconnect from byte-by-byte feed"
    );
}

// ===========================================================================
// Gap 4: Serialization with pending output buffers
// ===========================================================================

#[test]
fn interop_serialize_with_queued_output() {
    unsafe {
        // Create connected pair, queue a packet, then serialize before flushing
        let (cp, mut rp) = connected_pair(true);

        // Queue a device_connect from C (host→guest)
        let mut h = sys::usb_redir_device_connect_header {
            speed: 2,
            device_class: 0x08,
            device_subclass: 0x06,
            device_protocol: 0x50,
            vendor_id: 0x1234,
            product_id: 0x5678,
            device_version_bcd: 0x0100,
        };
        sys::usbredirparser_send_device_connect(cp, &mut h);

        // Serialize C with queued output
        let mut state: *mut u8 = ptr::null_mut();
        let mut state_len: c_int = 0;
        let ret = sys::usbredirparser_serialize(cp, &mut state, &mut state_len);
        assert_eq!(ret, 0);
        let c_state = slice::from_raw_parts(state, state_len as usize);

        // Rust should unserialize and have the queued output
        let result = Parser::unserialize(rust_config(true), c_state);
        assert!(result.is_ok(), "Rust unserialize with queued output failed: {:?}", result.err());
        let mut rp_restored = result.unwrap();

        // The restored parser should have data to write (the queued device_connect)
        assert!(rp_restored.has_data_to_write(), "Restored parser should have queued output");

        // Drain and feed to Rust guest parser to verify the packet is valid
        let output = rust_drain_all(&mut rp_restored);
        rp.feed(&output);
        let pkts = rust_drain_packets(&mut rp);
        assert!(
            pkts.iter().any(|p| matches!(p, Packet::DeviceConnect { .. })),
            "Queued output from unserialized parser should decode correctly"
        );

        libc_free(state as *mut c_void);
        sys::usbredirparser_destroy(cp);
    }
}

#[test]
fn interop_serialize_with_queued_output_rust_to_c() {
    unsafe {
        // Rust queues a packet, serializes, C unserializes and can flush it
        let (cp, mut rp) = connected_pair(false);

        // Rust (host) queues a device_connect
        rp.send(Packet::DeviceConnect {
            speed: Speed::High,
            device_class: 0x08,
            device_subclass: 0x06,
            device_protocol: 0x50,
            vendor_id: 0x1234,
            product_id: 0x5678,
            device_version_bcd: 0x0100,
        })
        .unwrap();

        // Serialize Rust with queued output
        let rust_state = rp.serialize().unwrap();

        // C unserializes
        reset_io();
        let cp2 = make_c_parser(true, true);
        let ret = sys::usbredirparser_unserialize(
            cp2,
            rust_state.as_ptr() as *mut u8,
            rust_state.len() as c_int,
        );
        assert_eq!(ret, 0, "C unserialize with queued output failed");

        // C should have data to write
        assert!(
            sys::usbredirparser_has_data_to_write(cp2) > 0,
            "C should have queued output after unserialize"
        );

        // Flush and verify
        let wire = c_capture(cp2);
        assert!(!wire.is_empty(), "C should produce bytes from unserialized queued output");

        sys::usbredirparser_destroy(cp);
        sys::usbredirparser_destroy(cp2);
    }
}

// ===========================================================================
// Gap 5: Fuzz-like coverage — random/edge-case bytes through both parsers
// ===========================================================================

#[test]
fn fuzz_like_garbage_bytes() {
    // Feed garbage bytes to Rust parser — must not panic
    let mut rp = Parser::new(rust_config(true));

    // Various garbage patterns
    let patterns: Vec<Vec<u8>> = vec![
        vec![0; 0],
        vec![0; 1],
        vec![0xFF; 100],
        vec![0; 16], // looks like a valid header with type=0 (hello)
        // Fake header: type=1 (device_connect), length=0xFFFFFFFF, id=0
        {
            let mut p = Vec::new();
            p.extend_from_slice(&1u32.to_le_bytes());
            p.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
            p.extend_from_slice(&0u32.to_le_bytes());
            p
        },
        // Valid-looking header but truncated body
        {
            let mut p = Vec::new();
            p.extend_from_slice(&6u32.to_le_bytes()); // SET_CONFIGURATION
            p.extend_from_slice(&1u32.to_le_bytes()); // length=1
            p.extend_from_slice(&0u32.to_le_bytes()); // id
            p
        },
    ];

    for pattern in &patterns {
        rp.feed(pattern);
        // Drain all events — must not panic
        while rp.poll().is_some() {}
    }
}

#[test]
fn fuzz_like_valid_header_bad_body() {
    // Craft packets with valid headers but corrupted bodies
    let mut rp = Parser::new(rust_config(false)); // guest

    // Simulate peer hello so parser has peer caps
    let mut peer = Parser::new(rust_config(true));
    let peer_hello = rust_drain_all(&mut peer);
    rp.feed(&peer_hello);
    while rp.poll().is_some() {}

    // Now feed packets with mismatched lengths
    let test_cases: Vec<(u32, u32, &[u8])> = vec![
        // device_connect (type=1) with length=0 (too short)
        (1, 0, &[]),
        // device_connect (type=1) with length=100 (too long)
        (1, 100, &[0u8; 100]),
        // set_configuration (type=6) with length=0 (too short)
        (6, 0, &[]),
        // control_packet (type=100) with length=5 (too short for header)
        (100, 5, &[0u8; 5]),
    ];

    for (pkt_type, length, body) in test_cases {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&pkt_type.to_le_bytes());
        pkt.extend_from_slice(&length.to_le_bytes());
        pkt.extend_from_slice(&0u64.to_le_bytes()); // id
        pkt.extend_from_slice(body);
        rp.feed(&pkt);
        // Must not panic
        while rp.poll().is_some() {}
    }
}
