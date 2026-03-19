/// Protocol version constant (0.7.1).
pub const USBREDIR_VERSION: u32 = 0x000701;
/// Maximum allowed bulk transfer payload size (128 MiB).
pub const MAX_BULK_TRANSFER_SIZE: u32 = 128 * 1024 * 1024;
/// Maximum total packet size (header overhead + bulk payload).
pub const MAX_PACKET_SIZE: u32 = 1024 + MAX_BULK_TRANSFER_SIZE;

/// Wire packet type IDs matching the C `usb_redir_type` enum.
pub mod pkt_type {
    // Control packets
    pub const HELLO: u32 = 0;
    pub const DEVICE_CONNECT: u32 = 1;
    pub const DEVICE_DISCONNECT: u32 = 2;
    pub const RESET: u32 = 3;
    pub const INTERFACE_INFO: u32 = 4;
    pub const EP_INFO: u32 = 5;
    pub const SET_CONFIGURATION: u32 = 6;
    pub const GET_CONFIGURATION: u32 = 7;
    pub const CONFIGURATION_STATUS: u32 = 8;
    pub const SET_ALT_SETTING: u32 = 9;
    pub const GET_ALT_SETTING: u32 = 10;
    pub const ALT_SETTING_STATUS: u32 = 11;
    pub const START_ISO_STREAM: u32 = 12;
    pub const STOP_ISO_STREAM: u32 = 13;
    pub const ISO_STREAM_STATUS: u32 = 14;
    pub const START_INTERRUPT_RECEIVING: u32 = 15;
    pub const STOP_INTERRUPT_RECEIVING: u32 = 16;
    pub const INTERRUPT_RECEIVING_STATUS: u32 = 17;
    pub const ALLOC_BULK_STREAMS: u32 = 18;
    pub const FREE_BULK_STREAMS: u32 = 19;
    pub const BULK_STREAMS_STATUS: u32 = 20;
    pub const CANCEL_DATA_PACKET: u32 = 21;
    pub const FILTER_REJECT: u32 = 22;
    pub const FILTER_FILTER: u32 = 23;
    pub const DEVICE_DISCONNECT_ACK: u32 = 24;
    pub const START_BULK_RECEIVING: u32 = 25;
    pub const STOP_BULK_RECEIVING: u32 = 26;
    pub const BULK_RECEIVING_STATUS: u32 = 27;

    // Data packets
    pub const CONTROL_PACKET: u32 = 100;
    pub const BULK_PACKET: u32 = 101;
    pub const ISO_PACKET: u32 = 102;
    pub const INTERRUPT_PACKET: u32 = 103;
    pub const BUFFERED_BULK_PACKET: u32 = 104;
}

/// USB transfer completion status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Status {
    Success = 0,
    Cancelled = 1,
    Inval = 2,
    IoError = 3,
    Stall = 4,
    Timeout = 5,
    Babble = 6,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Success => "success",
            Self::Cancelled => "cancelled",
            Self::Inval => "invalid",
            Self::IoError => "io-error",
            Self::Stall => "stall",
            Self::Timeout => "timeout",
            Self::Babble => "babble",
        })
    }
}

impl TryFrom<u8> for Status {
    type Error = u8;

    fn try_from(v: u8) -> std::result::Result<Self, u8> {
        match v {
            0 => Ok(Self::Success),
            1 => Ok(Self::Cancelled),
            2 => Ok(Self::Inval),
            3 => Ok(Self::IoError),
            4 => Ok(Self::Stall),
            5 => Ok(Self::Timeout),
            6 => Ok(Self::Babble),
            _ => Err(v),
        }
    }
}

/// USB endpoint transfer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum TransferType {
    Control = 0,
    Iso = 1,
    Bulk = 2,
    Interrupt = 3,
    Invalid = 255,
}

impl std::fmt::Display for TransferType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Control => "control",
            Self::Iso => "isochronous",
            Self::Bulk => "bulk",
            Self::Interrupt => "interrupt",
            Self::Invalid => "invalid",
        })
    }
}

impl TryFrom<u8> for TransferType {
    type Error = u8;

    fn try_from(v: u8) -> std::result::Result<Self, u8> {
        match v {
            0 => Ok(Self::Control),
            1 => Ok(Self::Iso),
            2 => Ok(Self::Bulk),
            3 => Ok(Self::Interrupt),
            _ => Err(v),
        }
    }
}

/// A USB endpoint address, encoding both number (0–15) and direction (IN/OUT).
///
/// Bit 7 indicates direction: set = IN (device-to-host), clear = OUT (host-to-device).
/// Bits 0–3 are the endpoint number.
///
/// ```
/// # use usbredir_proto::Endpoint;
/// let ep = Endpoint::new(0x81);
/// assert!(ep.is_input());
/// assert_eq!(ep.number(), 1);
/// assert_eq!(ep.raw(), 0x81);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint(u8);

impl Endpoint {
    /// Create an endpoint from a raw USB endpoint address byte.
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// The raw endpoint address byte.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// The endpoint number (bits 0–3).
    #[must_use]
    pub const fn number(self) -> u8 {
        self.0 & 0x0F
    }

    /// Returns `true` if this is an IN endpoint (device-to-host).
    #[must_use]
    pub const fn is_input(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// Returns `true` if this is an OUT endpoint (host-to-device).
    #[must_use]
    pub const fn is_output(self) -> bool {
        self.0 & 0x80 == 0
    }
}

impl From<u8> for Endpoint {
    fn from(v: u8) -> Self {
        Self(v)
    }
}

impl From<Endpoint> for u8 {
    fn from(ep: Endpoint) -> Self {
        ep.0
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dir = if self.is_input() { "IN" } else { "OUT" };
        write!(f, "ep{} {dir}", self.number())
    }
}

/// USB device speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Speed {
    Low = 0,
    Full = 1,
    High = 2,
    Super = 3,
    Unknown = 255,
}

impl std::fmt::Display for Speed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Low => "low",
            Self::Full => "full",
            Self::High => "high",
            Self::Super => "super",
            Self::Unknown => "unknown",
        })
    }
}

impl TryFrom<u8> for Speed {
    type Error = u8;

    fn try_from(v: u8) -> std::result::Result<Self, u8> {
        match v {
            0 => Ok(Self::Low),
            1 => Ok(Self::Full),
            2 => Ok(Self::High),
            3 => Ok(Self::Super),
            _ => Err(v),
        }
    }
}
