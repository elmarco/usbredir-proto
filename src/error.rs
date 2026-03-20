use crate::caps::Cap;
use crate::proto::{Endpoint, PktType};

/// Errors returned by the parser during packet encoding, decoding, or verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("unknown packet type: {0}")]
    UnknownPacketType(u32),
    #[error("invalid packet length: type={packet_type:?}, length={length}")]
    InvalidPacketLength { packet_type: PktType, length: u32 },
    #[error("packet too large: length={length}, max={max}")]
    PacketTooLarge { length: u32, max: u32 },
    #[error("data length mismatch: data_len={data_len}, header_len={header_len}")]
    DataLengthMismatch { data_len: usize, header_len: u32 },
    #[error("missing capability: {cap:?}")]
    MissingCapability { cap: Cap },
    #[error("wrong direction for endpoint: {endpoint}")]
    WrongDirection { endpoint: Endpoint },
    #[error("bulk transfer too large: length={length}, max={max}")]
    BulkTransferTooLarge { length: u32, max: u32 },
    #[error("duplicate hello packet")]
    DuplicateHello,
    #[error("interface count too large: {0}")]
    InterfaceCountTooLarge(u32),
    #[error("invalid enum value: {0}")]
    InvalidEnumValue(u8),
    #[error("failed to decode wire header for packet type {packet_type:?}")]
    WireHeaderDecode { packet_type: PktType },
    #[error("invalid UTF-8 in packet data")]
    InvalidUtf8,
    #[error("filter data not null-terminated")]
    FilterNotNullTerminated,
    #[error("wrong direction packet")]
    WrongDirectionPacket,
    #[error("non-input endpoint for receiving: {endpoint}")]
    NonInputEndpoint { endpoint: Endpoint },
    #[error("peer hello not yet received — cannot send capability-dependent packets")]
    NoPeerCaps,
    #[error("input buffer full: {current} buffered + {incoming} incoming exceeds limit {max}")]
    InputBufferFull {
        current: usize,
        incoming: usize,
        max: usize,
    },
    #[error("filter error: {0}")]
    Filter(#[from] FilterError),
    #[error("serialization error: {0}")]
    Serialize(#[from] SerializeError),
    #[cfg(feature = "std")]
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from serializing or unserializing parser state.
///
/// These are returned by [`Parser::serialize()`](crate::Parser::serialize) and
/// [`Parser::unserialize()`](crate::Parser::unserialize), and are also wrapped
/// in [`Error::Serialize`] for callers using the unified error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SerializeError {
    #[error("magic mismatch")]
    BadMagic,
    #[error("length mismatch")]
    LengthMismatch,
    #[error("caps mismatch: source has caps we don't")]
    CapsMismatch,
    #[error("buffer underrun")]
    BufferUnderrun,
    #[error("empty write buffer")]
    EmptyWriteBuffer,
    #[error("{remaining} extraneous bytes")]
    ExtraneousData { remaining: usize },
}

/// Errors from filter rule parsing or verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FilterError {
    #[error("invalid filter string")]
    InvalidString,
    #[error("empty separator")]
    EmptySeparator,
    #[error("value out of range")]
    ValueOutOfRange,
}

pub type Result<T> = core::result::Result<T, Error>;
