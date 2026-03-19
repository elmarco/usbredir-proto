# usbredir-proto TODO

## 1. Structure the `Packet` enum by category
- [ ] Group variants into nested enums/structs (connection-wide, request/response, data)
- [ ] Share common fields (`id`, `endpoint`, `status`, `data`) structurally instead of repeating them
- [ ] Eliminate boilerplate in `Display`, `packet_type()`, `encode_packet_into()`, `decode_packet()`
- [ ] Remove most helper constructors (they become unnecessary with structured variants)

## 2. Encode parse phase as a state-carrying enum
- [ ] Replace the loose `pkt_type`, `pkt_length`, `pkt_id`, `type_header_len` fields on `Parser`
- [ ] Use `enum ParseState { Header, Body { pkt_type, pkt_length, pkt_id, type_header_len } }`
- [ ] Prevents reading stale header fields when in the Header phase

## 3. Make `Packet::id()` return `Option<u64>`
- [ ] Currently returns `0` for connection-wide packets, conflating "no id" with "id is zero"
- [ ] Callers correlating requests by id will accidentally match unrelated packets
- [ ] Return `Option<u64>` instead; callers who need raw value can `.unwrap_or(0)`

## 4. Clean up `Event` enum
- [ ] Remove `Log` variant (use `tracing` unconditionally, or drop log events from the event stream)
- [ ] Consider splitting into `poll_packet() -> Option<Packet>` and `poll_diagnostic() -> Option<Diagnostic>`
- [ ] Users who just want packets shouldn't have to filter through logs and errors

## 5. Guard `send()` against pre-negotiation use
- [ ] `send()` allows sending capability-dependent packets before peer hello is received
- [ ] `peer_caps: None` makes all `negotiated()` checks return false, producing wrong wire formats
- [ ] Return an error (or warn) if `peer_caps` is `None` and the packet type depends on negotiated caps

## 6. Replace `Error::Deserialize(String)` / `Error::Serialize(String)` with typed variants
- [ ] Callers can't programmatically distinguish "magic mismatch" from "buffer underrun" without string matching
- [ ] Add dedicated enum variants for serializer errors (bad magic, length mismatch, buffer underrun, etc.)
- [ ] Keep `String` only for truly free-form messages

## 7. Fix `Caps::verify()` silent mutation
- [ ] Currently strips `BulkStreams` if `EpInfoMaxPacketSize` isn't set, modifying `&mut self` in place
- [ ] Options: `fn verified(self) -> Self`, or enforce invariant at construction (`with(BulkStreams)` auto-sets `EpInfoMaxPacketSize`), or at minimum log when a cap is stripped

## 8. Validate `Endpoint` reserved bits
- [ ] `Endpoint::new(0xFF)` accepts any `u8`; bits 4-6 are not meaningful per USB spec
- [ ] Consider `TryFrom<u8>` that validates reserved bits
- [ ] Evaluate whether `From<u8>` should remain infallible

## 9. Fix codec `Decoder` error handling
- [ ] `UsbredirCodec::decode()` returns `Ok(Some(Event::ParseError(...)))` instead of `Err(...)`
- [ ] tokio-util `Framed` treats parse errors as normal items, not stream errors
- [ ] Map `Event::ParseError` to `Err(...)` in the decoder; yield packets directly as `Ok(Some(Packet))`

## 10. Minor items
- [ ] `filter::check()` has 9 parameters — introduce a `DeviceInfo` struct
- [ ] Verify `device_subclass`/`device_protocol` params in `check()` aren't dead code (`#[allow(clippy::only_used_in_recursion)]`)
- [ ] `Parser::new()` line 197: `let _ = parser.send(hello)` silently ignores errors — handle or assert
- [ ] `Parser::new()` clones `ParserConfig` unnecessarily — take by value and destructure
- [ ] `output_total_size` (`u64`) — use `checked_add`/`saturating_add` for defensive overflow prevention
