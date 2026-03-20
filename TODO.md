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

- [ ] **Handle duplicate Hello consistently**
  When a duplicate Hello arrives (`parser.rs:641`), it's logged but still pushed as an
  `Ok(packet)` event. The `Error::DuplicateHello` variant exists but is never used.
  Either emit it as an error event, or don't push the packet.

## Low priority

- [ ] **Consider `send(Packet)` by value**
  `send(&self, packet: &Packet)` forces callers to keep ownership of something they
  typically don't need after sending. Taking by value would let callers transfer ownership
  of `Bytes` buffers without cloning.

- [ ] **Address `usize` truncation on small targets**
  `pkt_length as usize` casts in `parser.rs` — on 16-bit targets, `MAX_PACKET_SIZE`
  (128 MiB + 1 KiB) doesn't fit in `usize`. Either add a `usize` assertion or gate
  `no_std` support to `>= 32-bit`.

- [ ] **Document or reconsider `Box<Packet>` in events**
  `Event = Result<Box<Packet>>` heap-allocates every decoded packet. `Packet` is large
  due to `EpInfo` (320+ bytes) but common hot-path packets (`Data`, `Request`) are small.
  Either document the rationale or consider alternatives (inline small, box large).

- [ ] **Remove or hide `verify_rules` no-op**
  `filter.rs:144` — public function that does nothing. Either remove it or make it
  `#[doc(hidden)]`.

- [ ] **Remove `our_caps` / `config.caps` redundancy**
  `Parser` stores both `config.caps` and `our_caps` (a modified copy). After construction,
  `config` is never used again except by a `#[allow(dead_code)]` accessor.

- [ ] **`Caps::from_le_bytes` silently truncates extra words**
  If the peer sends more capability words than `CAPS_SIZE`, extra bytes are silently
  dropped. The peer thinks both sides have it, your side doesn't. Consider storing the
  full received bitset (variable-length) or warning on truncation.

- [ ] **`poll_packet()` silently discards errors**
  Documented but dangerous as a default API. Users should explicitly opt into ignoring
  errors.

- [ ] **`#[non_exhaustive]` trade-off**
  `Packet`/`DataKind`/`RequestKind` are `#[non_exhaustive]`, preventing exhaustive
  matching. Good for forward compat but forces `_ =>` arms. Document the trade-off.
