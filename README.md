# usbredir-proto

[![CI](https://github.com/elmarco/usbredir-proto/actions/workflows/ci.yml/badge.svg)](https://github.com/elmarco/usbredir-proto/actions)
[![crates.io](https://img.shields.io/crates/v/usbredir-proto.svg)](https://crates.io/crates/usbredir-proto)
[![docs.rs](https://docs.rs/usbredir-proto/badge.svg)](https://docs.rs/usbredir-proto)
[![License: LGPL-2.1+](https://img.shields.io/crates/l/usbredir-proto)](LICENSE)

Sans-IO Rust implementation of the [usbredir](https://www.spice-space.org/usbredir.html) binary protocol.

Wire-compatible with the C [`usbredirparser`](https://gitlab.freedesktop.org/spice/usbredir) library.

## What is usbredir?

usbredir is a network protocol for forwarding USB device traffic between a
*USB host* (the machine with the physical device) and a *guest* (typically a
virtual machine). It is the standard USB redirection mechanism in the
QEMU / SPICE ecosystem.

## Features

- Encodes and decodes every packet type defined by the protocol
- Capability negotiation
- [Sans-IO](https://sans-io.readthedocs.io/) design -- no sockets, no callbacks, no async runtime required
- C-compatible serialization format for live VM migration between Rust and C peers
- USB device filter rules (parse, serialize, match)
- Type-safe `Parser<Host>` / `Parser<Guest>` with compile-time role enforcement
- `no_std` support (disable the default `std` feature)
- Optional `tokio` codec (`tokio` feature)
- Optional `tracing` instrumentation (`tracing` feature)

## Quick start

```rust
use usbredir_proto::{Parser, ParserConfig, Cap, Packet, Event, Guest};

let mut parser = Parser::<Guest>::new(
    ParserConfig::new("my-app 1.0")
        .cap(Cap::Ids64Bits)
);

// Drain the hello packet that was auto-sent on construction
while let Some(bytes) = parser.drain() {
    // send `bytes` over the network
}

// Feed received bytes into the parser
// parser.feed(&received_bytes);

// Pull decoded packets
// for event in parser.events() { ... }
```

## Feature flags

| Feature   | Default | Description |
|-----------|---------|-------------|
| `std`     | Yes     | Enable `std` support (disable for `no_std`) |
| `tokio`   | No      | `tokio-util` `Codec` implementation |
| `tracing` | No      | `tracing` instrumentation |

## MSRV

The minimum supported Rust version is **1.82**.

## License

LGPL-2.1-or-later
