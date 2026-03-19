# usbredir-proto TODO

## High Impact

- [x] `#[deny(missing_docs)]` + public API docs — module-level docs, doc comments on `Packet`, `Parser`, `Caps`, `FilterRule`, and all public methods
- [x] `TryFrom<u8>` instead of `from_u8` — `Status`, `TransferType`, `Speed` now use `TryFrom<u8>` returning `Result`
- [x] `impl Iterator` for `Parser::poll()` — added `Parser::events()` returning `impl Iterator<Item = Event>`
- [x] `impl Iterator` for `Parser::drain()` — added `Parser::drain_output()` returning `impl Iterator<Item = Bytes>`
- [x] Make `wire` module private — changed to `pub(crate) mod wire`
- [x] Reduce `encode_packet` allocation — replaced 288-byte scratch Vec + data Vec with single `BytesMut` + `write_hdr!` macro

## Medium Impact

- [x] `#[non_exhaustive]` on public enums — `Packet`, `Error`, `FilterError`, `Event`, `LogLevel`, `Status`, `Speed`, `TransferType`
- [x] Clippy pedantic — fixed `format!` appended to String, added `#[must_use]`, inline format args
- [x] `Display` for `Packet`, `Status`, `TransferType`, `Speed` — concise format for logging
- [x] `ParserConfig` builder — `Default` impl + `ParserConfig::new("v").is_host(true).cap(Cap::Ids64Bits)` chaining
- [x] Typed `Endpoint` newtype — `Endpoint` wrapping `u8` with `is_input()`, `number()`, `raw()` methods; replaces `endpoint: u8` in 14 packet variants
- [x] `Packet` helper constructors — snake_case constructors for all 33 variants (e.g. `Packet::bulk_packet(id, ep, ...)`) with `impl Into<Bytes>` for data params

## Lower Priority / Polish

- [ ] Fuzz targets — `cargo-fuzz` for parser and filter
- [ ] `no_std` support — the crate only uses `alloc` features, could work in embedded/kernel contexts
- [ ] Benchmarks — `criterion` benchmarks for encode/decode throughput
- [ ] CI — GitHub Actions with `cargo test`, `cargo clippy`, `cargo doc`, MSRV check
