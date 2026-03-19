use crate::caps::Cap;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown packet type: {0}")]
    UnknownPacketType(u32),
    #[error("invalid packet length: type={packet_type}, length={length}")]
    InvalidPacketLength { packet_type: u32, length: u32 },
    #[error("packet too large: length={length}, max={max}")]
    PacketTooLarge { length: u32, max: u32 },
    #[error("data length mismatch: data_len={data_len}, header_len={header_len}")]
    DataLengthMismatch { data_len: usize, header_len: u32 },
    #[error("missing capability: {cap:?}")]
    MissingCapability { cap: Cap },
    #[error("wrong direction for endpoint: {endpoint:#04x}")]
    WrongDirection { endpoint: u8 },
    #[error("bulk transfer too large: length={length}, max={max}")]
    BulkTransferTooLarge { length: u32, max: u32 },
    #[error("duplicate hello packet")]
    DuplicateHello,
    #[error("interface count too large: {0}")]
    InterfaceCountTooLarge(u32),
    #[error("serialize error: {0}")]
    Serialize(String),
    #[error("deserialize error: {0}")]
    Deserialize(String),
    #[error("wrong direction packet")]
    WrongDirectionPacket,
    #[error("non-input endpoint for receiving: {endpoint:#04x}")]
    NonInputEndpoint { endpoint: u8 },
    #[error("filter error: {0}")]
    Filter(#[from] FilterError),
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("invalid filter string")]
    InvalidString,
    #[error("empty separator")]
    EmptySeparator,
    #[error("value out of range")]
    ValueOutOfRange,
}

pub type Result<T> = std::result::Result<T, Error>;
