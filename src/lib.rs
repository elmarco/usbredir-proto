//! Sans-IO Rust implementation of the [usbredir] binary protocol.
//!
//! [usbredir] is a network protocol for forwarding USB device traffic between
//! a *USB host* (the machine with the physical device) and a *guest* (typically
//! a virtual machine that wants to use the device). It is the standard
//! redirection mechanism in the QEMU / SPICE ecosystem.
//!
//! This crate provides a wire-compatible reimplementation of the C
//! [`usbredirparser`][c-lib] library. It encodes and decodes every packet type
//! defined by the protocol, handles capability negotiation, and supports the
//! C-compatible serialization format so parser state can be migrated between
//! Rust and C peers (useful during live VM migration).
//!
//! [usbredir]: https://www.spice-space.org/usbredir.html
//! [c-lib]: https://gitlab.freedesktop.org/spice/usbredir
//!
//! # Concepts
//!
//! | Term | Meaning |
//! |------|---------|
//! | **Host** | The side that owns the physical USB device (runs `usbredirhost`). |
//! | **Guest** | The side that uses the device remotely (e.g. a QEMU VM). |
//! | **Hello** | Initial handshake packet exchanged by both sides; carries a version string and a capability bitmask ([`Caps`]). |
//! | **Capability** | A feature flag ([`Cap`]) advertised in the Hello. A capability is *negotiated* (active) only when **both** sides set it. |
//! | **Endpoint** | A USB endpoint address ([`Endpoint`]). Bit 7 = direction (IN = device→host, OUT = host→device), bits 0–3 = number. |
//!
//! # Design
//!
//! The [`Parser`] follows a [sans-IO] pattern — no sockets, no callbacks:
//!
//! - [`Parser::feed()`] — push received bytes into the parser
//! - [`Parser::poll()`] / [`Parser::events()`] — pull decoded [`Event`]s (packets or errors)
//! - [`Parser::send()`] — enqueue a [`Packet`] for transmission
//! - [`Parser::drain()`] / [`Parser::drain_output()`] — pull encoded bytes to send
//!
//! [sans-IO]: https://sans-io.readthedocs.io/
//!
//! # Example
//!
//! ```
//! use usbredir_proto::{Parser, ParserConfig, Caps, Cap, Packet, Event};
//!
//! let mut parser = Parser::new(
//!     ParserConfig::new("my-app 1.0")
//!         .cap(Cap::Ids64Bits)
//! );
//!
//! // Drain the hello packet that was auto-sent on construction
//! while let Some(bytes) = parser.drain() {
//!     // send `bytes` over the network
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod caps;
pub mod error;
pub mod filter;
pub mod packet;
pub mod parser;
pub mod proto;
pub mod serializer;
pub(crate) mod wire;

#[cfg(feature = "tokio")]
pub mod codec;

pub use caps::{Cap, Caps};
pub use error::{Error, FilterError, Result};
pub use filter::{CheckFlags, FilterResult, FilterRule};
pub use packet::{DataKind, DataPacket, Packet};
pub use parser::{Event, LogLevel, Parser, ParserConfig};
pub use proto::{Endpoint, Speed, Status, TransferType};
