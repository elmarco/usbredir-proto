# TODO

## 1. ~~Restructure the `Packet` enum~~ ✅

The 28-variant `Packet` enum mixes three distinct concerns into one flat type: connection-wide packets (no id), request/response packets (with id), and data packets. This forces every consumer to match on all variants, and the `id()`, `endpoint()`, `status()` methods returning `Option` are a sign that the type isn't carrying its weight.

**Suggestion:** Consider a two-level enum:

```rust
pub enum Packet {
    Hello { version: String, caps: Caps },
    DeviceConnect { ... },
    // ...other connection-wide variants...
    Request(RequestPacket),   // always has id
    Data(DataPacket),         // always has id + data
}

pub struct RequestPacket {
    pub id: u64,
    pub kind: RequestKind,
}

pub enum RequestKind {
    SetConfiguration { configuration: u8 },
    ConfigurationStatus { status: Status, configuration: u8 },
    // ...
}
```

This makes `id` structurally guaranteed on request/data packets, eliminates the `Option<u64>` accessor pattern, and cuts down the number of arms in every `match`. It also lets you add blanket methods like `RequestPacket::reply()` in the future.

## 2. ~~`Parser::send()` takes `Packet` by value — consider `&Packet`~~ ✅

`send()` consumes the `Packet`, which forces callers to clone if they want to retain it (e.g. for logging or retry). Since `encode_packet_into` only reads from it, `&Packet` would be more flexible. The one thing that would need adjustment is `data: Bytes` — but `Bytes::clone()` is cheap (refcounted).

## 3. `is_host: bool` is a missed typestate opportunity (deferred — large refactor)

The parser has different allowed packet sets depending on whether it's host or guest, and this is validated at runtime via `command_for_host` logic sprinkled through `get_type_header_len` and `verify_packet`. A `Parser<Host>` / `Parser<Guest>` typestate would:
- Make illegal sends a compile-time error (guest can't send `DeviceConnect`)
- Eliminate the boolean flipping logic (`command_for_host = !command_for_host` when sending)
- Let you have distinct `send` method signatures per role

This is a bigger refactor but would be a significant safety improvement for a protocol library.

## 4. ~~`Event` conflates parse errors with packets~~ ✅

`Event::ParseError` being a thing that comes out of `poll()` is awkward — callers that just want packets use `poll_packet()` which silently drops errors. That's a footgun. Consider:
- Making `feed()` return a `Result` or collect errors separately
- Or having `poll()` return `Result<Packet, Error>` directly

The current `poll_packet()` silently discarding errors is dangerous for a protocol library — a stream of malformed packets would be invisible.

## 5. ~~Duplicate constructor APIs~~ ✅

Every `Packet` variant has both a struct-literal form and a `Packet::foo()` constructor method. The constructors add ~400 lines but provide almost no validation beyond what the struct literal gives you. For a `#[non_exhaustive]` enum, constructors make sense, but you could drop the `DataPacket::control()` / `DataPacket::bulk()` / etc. constructors since they're only used from the `Packet::control_packet()` wrappers. Pick one layer.

## 6. ~~`pkt_type` constants should be an enum~~ ✅

The `pkt_type` module uses bare `u32` constants. This means `get_type_header_len` and `decode_packet` match on `u32` with a `_ => Err(...)` fallback. A proper `#[repr(u32)]` enum with `TryFrom<u32>` would:
- Let the compiler warn about missing match arms
- Make the `_ => Err(Error::UnknownPacketType(_))` pattern unnecessary
- Be self-documenting in function signatures (`fn decode(pkt_type: PktType, ...)`)

## 7. ~~`to_skip` safety comment~~ ✅

In `do_parse`, when an error occurs, `to_skip` is set to `pkt_length as usize`. Since `pkt_length` is validated against `MAX_PACKET_SIZE` (128 MiB + 1 KiB), this means the parser could need to skip up to 128 MiB of input. The skip is drained incrementally (`split_to(skip)` at the top of the loop) so it's safe, but worth a comment explaining why.

## 8. ~~`verify_single_rule` is a no-op~~ ✅

`filter.rs:140` — the function body is `Ok(())`. Either add real validation or remove the abstraction. Right now it's dead code that gives a false sense of security.

## 9. ~~`Caps::from_le_bytes` silently truncates~~ ✅

`Caps::from_le_bytes` silently ignores trailing bytes and accepts short input. This is fine for forward-compatibility with larger cap sets, but for correctness you might want to warn (via tracing) or error if the peer sends caps bits you don't recognize — they could indicate a protocol version mismatch.

## 10. ~~Minor items~~ (partially done ✅)

- **`DataKind::length()` semantics are confusing**: It returns the *header's* length field, not the data length. Callers in `verify_packet` use it as `header_length` which is misleading. Consider renaming to `transfer_length()` or `declared_length()`.
- **`Endpoint::is_output()` for endpoint 0**: EP0 is bidirectional in USB, but `Endpoint::new(0).is_output()` returns `true`. Worth documenting.
- **`Parser` doesn't implement `Clone`**: If serialization is important for live migration, `Clone` would be a simpler mechanism for snapshotting (the `Bytes` inside are refcounted).
- **Codec `decode` drops already-consumed bytes**: `src.split()` in the codec moves all bytes into the parser even if the parser only needs a few — this is fine for correctness but means `BytesMut`'s backpressure hinting doesn't work. Consider implementing `fn decode_eof` too.
- **`#[allow(clippy::too_many_arguments)]`** on `DataPacket::control` and `Packet::control_packet` — this is a hint that a builder or struct-based API would be better. A `ControlSetup { request, requesttype, value, index, length }` struct would clean this up.
