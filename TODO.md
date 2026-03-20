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

- [ ] **`poll_packet()` silently discards errors**
  Documented but dangerous as a default API. Users should explicitly opt into ignoring
  errors.

- [ ] **`#[non_exhaustive]` trade-off**
  `Packet`/`DataKind`/`RequestKind` are `#[non_exhaustive]`, preventing exhaustive
  matching. Good for forward compat but forces `_ =>` arms. Document the trade-off.
