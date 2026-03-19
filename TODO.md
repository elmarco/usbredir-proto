# usbredir-proto TODO

## High Impact

- [x] `#[deny(missing_docs)]` + public API docs — module-level docs, doc comments on `Packet`, `Parser`, `Caps`, `FilterRule`, and all public methods
- [x] `TryFrom<u8>` instead of `from_u8` — `Status`, `TransferType`, `Speed` now use `TryFrom<u8>` returning `Result`
- [x] `impl Iterator` for `Parser::poll()` — added `Parser::events()` returning `impl Iterator<Item = Event>`
- [x] `impl Iterator` for `Parser::drain()` — added `Parser::drain_output()` returning `impl Iterator<Item = Bytes>`
- [x] Make `wire` module private — changed to `pub(crate) mod wire`
- [x] Reduce `encode_packet` allocation — replaced 288-byte scratch Vec + data Vec with single `BytesMut` + `write_hdr!` macro

## Medium Impact

- [ ] `#[non_exhaustive]` on public enums — `Packet`, `Error`, `Event`, `Status`, `Speed`, `TransferType` to allow adding variants without breaking changes
- [ ] Clippy pedantic — enable `#![warn(clippy::pedantic)]` and fix warnings
- [ ] `Display` for `Packet` — useful for logging/debugging
- [ ] Typed `Endpoint` newtype — replace `endpoint: u8` with `Endpoint(u8)` providing `.is_input()`, `.number()`, `.direction()` methods
- [ ] `Packet` helper constructors — e.g. `Packet::set_configuration(id, config)`, `Packet::bulk_packet(id, endpoint, data)` to reduce verbosity
- [ ] `ParserConfig` builder — use builder pattern or `Default` + method chaining

## Lower Priority / Polish

- [ ] Fuzz targets — `cargo-fuzz` for parser and filter
- [ ] `no_std` support — the crate only uses `alloc` features, could work in embedded/kernel contexts
- [ ] Benchmarks — `criterion` benchmarks for encode/decode throughput
- [ ] CI — GitHub Actions with `cargo test`, `cargo clippy`, `cargo doc`, MSRV check
