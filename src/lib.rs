//! Sans-IO Rust implementation of the usbredir binary protocol.
//!
//! This crate provides a wire-compatible reimplementation of the C
//! `usbredirparser` library used for USB device redirection in QEMU/SPICE.
//!
//! # Design
//!
//! The [`Parser`] follows a sans-IO pattern — no sockets, no callbacks:
//!
//! - [`Parser::feed()`] — push received bytes into the parser
//! - [`Parser::poll()`] / [`Parser::events()`] — pull decoded [`Event`]s (packets or errors)
//! - [`Parser::send()`] — enqueue a [`Packet`] for transmission
//! - [`Parser::drain()`] / [`Parser::drain_output()`] — pull encoded bytes to send
//!
//! # Example
//!
//! ```
//! use usbredir_proto::{Parser, ParserConfig, Caps, Cap, Packet, Event};
//!
//! let mut caps = Caps::new();
//! caps.set(Cap::Ids64Bits);
//!
//! let mut parser = Parser::new(ParserConfig {
//!     version: "my-app 1.0".into(),
//!     caps,
//!     is_host: false,
//!     no_hello: false,
//! });
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
pub use packet::Packet;
pub use parser::{Event, LogLevel, Parser, ParserConfig};
pub use proto::{Endpoint, Speed, Status, TransferType};
