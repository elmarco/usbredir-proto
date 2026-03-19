# usbredir-proto TODO

## High Impact

- [ ] Zero-copy decode — `parser.rs:1092,1107,1118,1130,1141,1153` all do `Bytes::copy_from_slice(data)`. Since input is already a `BytesMut`, split the body as `Bytes` and slice it to avoid a full copy on every data packet. Matters at USB 3.0 bulk speeds.
- [ ] `Box<Packet>` in `Event` — clippy flags `large_enum_variant` (`parser.rs:101`). `Packet` is 288 bytes (because of `EpInfo` with five `[_;32]` arrays), making every `Event` 288 bytes. Boxing drops `Event` to ~40 bytes.
- [ ] `tracing` instead of `Event::Log` — returning log messages through the event queue (`parser.rs:104`) is awkward. A `tracing` feature flag would let the parser emit `tracing::info!()`/`tracing::error!()` directly (Rust ecosystem standard). Remove `Log` variant or keep behind `no_std` path.

## Medium Impact

- [ ] Caps builder — add `fn with(mut self, cap: Cap) -> Self` so caps can be built without `let mut`: `Caps::new().with(Cap::Ids64Bits).with(Cap::BulkLength32Bits)`
- [ ] Packet accessor methods — many variants share `endpoint`, `status`, `data`, `id`. Add `pub fn endpoint(&self) -> Option<Endpoint>`, `status()`, `data()` to avoid destructuring every time.
- [ ] Fix existing clippy warnings — 14 warnings: `map_or` → `is_some_and`/`is_none_or`, `needless_range_loop`, `too_many_arguments`. Worth cleaning up for a library crate.
- [ ] `tokio-util` codec — behind a `tokio` feature flag, impl `Decoder<Item=Event>` and `Encoder<Packet>` on a `UsbredirCodec`. The #1 thing downstream users will want — most usbredir runs over TCP.

## Lower Impact / Polish

- [ ] Property-based testing — `proptest` or `arbitrary` with `Arbitrary` impls for `Packet`. Generate random valid packets, encode, decode, check roundtrip. Stronger than hand-written test cases.
- [ ] `impl Debug` for `Parser` — currently missing (`parser.rs:119`). At minimum a manual impl showing state/caps/buffer sizes.
- [ ] MSRV policy — pick one (e.g. 1.75) and add `rust-version` to `Cargo.toml`. Currently uses `is_some_and`/`is_none_or` (1.82+) after clippy fixes, so worth declaring.
