# TODO

## High priority

- [x] **Split `Packet` by direction (typestate-aware send/recv types)** — WONTFIX
  Assessed and rejected: Data packets (the hot path) are bidirectional — direction depends
  on the endpoint, not the role. Hello and FilterFilter are also bidirectional. Only ~20
  request/status packet types have strict directionality. A type split would roughly double
  the packet type surface area for limited compile-time benefit, since data packets still
  need runtime direction checks. The existing 27 runtime check points in `get_type_header_len`
  comprehensively cover every directional packet type.

- [x] **Use `PktType` enum instead of `u32` constants internally**
  Done: all internal code now uses `PktType` enum variants. The `pkt_type` constants
  module is `#[doc(hidden)]`. Match arms are now exhaustive (no `_ =>` fallthrough
  in `decode_packet`). Error variants use `PktType` where the type is known-valid.

- [x] **Extract `EpInfo`/`InterfaceInfo` into boxed structs**
  Done: extracted `EpInfoData` and `InterfaceInfoData` structs, boxed in the enum as
  `EpInfo(Box<EpInfoData>)` and `InterfaceInfo(Box<InterfaceInfoData>)`. Updated all
  constructors, match arms, tests, and examples. `Packet` inline size reduced from
  ~300 bytes to ~40 bytes.

- [x] **Split `Error` into subsystem-specific types**
  Done: extracted `SerializeError` with 6 variants (`BadMagic`, `LengthMismatch`,
  `CapsMismatch`, `BufferUnderrun`, `EmptyWriteBuffer`, `ExtraneousData`).
  `serialize()`/`unserialize()` now return `Result<T, SerializeError>` directly.
  `Error::Serialize(SerializeError)` wraps it for callers using the unified type.
  Parse/encode errors share too many variants (direction, capability checks) to split
  further without duplication.

- [x] **Add input buffer size limits**
  Done: added `max_input_buffer: Option<usize>` to `ParserConfig` (default `None` =
  unlimited). `feed()` now returns `Result<()>` and errors with `Error::InputBufferFull`
  when the limit would be exceeded. No bytes are consumed on overflow.

## Medium priority

- [x] **Centralize packet metadata (direction, header size, etc.)** — WONTFIX
  Assessed and rejected: header sizes depend on negotiated capabilities at runtime
  (e.g. DeviceConnect size depends on Cap::ConnectDeviceVersion), so a static lookup
  table won't work. Decode/encode are inherently different logic per type. Only direction
  and expects_extra_data are static, but extracting just those saves minimal code.
  The PktType enum refactor (item 2) already gives exhaustive matching, which catches
  missing arms at compile time when a new variant is added.

- [x] **Wrap multi-field variants in dedicated structs**
  Done: `Packet::DeviceConnect` now holds `DeviceConnectInfo` struct (7 scalar fields).
  `InterfaceInfo` and `EpInfo` left as-is — their array fields don't benefit from wrapping.
  `control_packet()` constructor left as-is — users can construct `Packet::Data(DataPacket { .. })`
  directly for full control.

- [x] **Handle duplicate Hello consistently**
  Done: duplicate Hello now emits `Err(Error::DuplicateHello)` and does not push the
  packet as an event. The existing `Error::DuplicateHello` variant is now used.

- [x] **Simplify direction logic in `get_type_header_len()`**
  Done: added `Direction` enum and `PktType::direction()` method to `proto.rs`.
  `get_type_header_len()` now checks direction in 3 lines upfront, then a clean
  match on just header sizes (~70 lines, down from ~220). `verify_packet()` also
  simplified with `R::IS_HOST ^ sending`.

- [x] **Remove or deprecate `poll_packet()`**
  Done: added `#[deprecated(since = "0.2.0")]` with guidance to use `poll()` or `events()`.

- [x] **Fix misleading codec decode loop**
  Done: replaced loop with direct `match self.parser.poll()`.

- [x] **Replace `Borrow<Packet>` with `&Packet` on `send()`**
  Done: simplified to `&Packet`.

- [x] **Make `Event` a proper enum instead of a type alias**
  Done: replaced `type Event = Result<Box<Packet>>` with
  `enum Event { Packet(Box<Packet>), Error(Error) }`. Updated all match sites
  in parser, codec, tests, and benchmarks.

## Low priority

- [x] **Consider `send(Packet)` by value**
  Done: `send()` now accepts `impl Borrow<Packet>`, so callers can pass either
  `&Packet` (existing code unchanged) or owned `Packet` (no unnecessary borrow).

- [x] **Address `usize` truncation on small targets**
  Done: added compile-time assertion in `proto.rs` that `usize` is at least 32 bits.
  Fails at compile time on 16-bit targets instead of silently truncating.

- [x] **Document or reconsider `Box<Packet>` in events**
  Done: documented the rationale in the `Event` type alias doc comment. `Packet` is ~288
  bytes due to `EpInfo`; boxing is correct to avoid bloating `VecDeque` slots.

- [x] **Remove or hide `verify_rules` no-op**
  Done: added `#[doc(hidden)]` to `verify_rules`. The function is retained for forward
  compatibility but hidden from public API documentation.

- [x] **Remove `our_caps` / `config.caps` redundancy**
  Done: removed the `config` field from `Parser` entirely. All needed values (`caps`,
  `no_hello`, `version`) are extracted in `new()` and the dead `config()` accessor is removed.

- [x] **`Caps::from_le_bytes` silently truncates extra words**
  Done: documented that truncation is safe because `negotiated()` requires both sides
  to set a cap, and our side can never set caps beyond `CAPS_SIZE`. Matches C library
  behavior.

- [x] **`poll_packet()` silently discards errors**
  Done: expanded doc comment to list the error types being discarded and recommend
  `poll()` / `events()` for production code.

- [x] **`#[non_exhaustive]` trade-off**
  Done: documented the rationale on `Packet` enum and noted the version-pinning
  workaround for callers who prefer exhaustive matching.

- [x] **Add `has_events()` method to `Parser`**
  Done: added `has_events()` symmetric with `has_data_to_write()`.

- [x] **`Caps::set` hidden side-effect** — WONTFIX
  Already well-documented on both `set()` and `with()`. The auto-enable of
  `EpInfoMaxPacketSize` when setting `BulkStreams` matches the C library behavior
  and prevents invalid cap combinations. No change needed.

- [x] **`Endpoint::new()` silently masks reserved bits**
  Done: added `Endpoint::from_raw()` that signals the masking behavior. `new()` kept
  as alias for compatibility. `TryFrom<u8>` not added because `From<u8>` (needed for
  wire decoding) conflicts with the blanket impl.

- [x] **Remove `#[doc(hidden)] pkt_type` constants module**
  Done: removed the entire module. No internal or external users.

- [x] **Consider `num_enum` for `TryFrom` boilerplate** — WONTFIX
  The ~80 lines of manual impls work correctly and adding a proc-macro dependency
  for cosmetic reduction isn't worth it for a `no_std` library.
