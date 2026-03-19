pub const USBREDIR_VERSION: u32 = 0x000701;
pub const MAX_BULK_TRANSFER_SIZE: u32 = 128 * 1024 * 1024;
pub const MAX_PACKET_SIZE: u32 = 1024 + MAX_BULK_TRANSFER_SIZE;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Status {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::Cancelled,
            2 => Self::Inval,
            3 => Self::IoError,
            4 => Self::Stall,
            5 => Self::Timeout,
            6 => Self::Babble,
            _ => Self::Inval,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferType {
    Control = 0,
    Iso = 1,
    Bulk = 2,
    Interrupt = 3,
    Invalid = 255,
}

impl TransferType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Control,
            1 => Self::Iso,
            2 => Self::Bulk,
            3 => Self::Interrupt,
            _ => Self::Invalid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Speed {
    Low = 0,
    Full = 1,
    High = 2,
    Super = 3,
    Unknown = 255,
}

impl Speed {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Low,
            1 => Self::Full,
            2 => Self::High,
            3 => Self::Super,
            _ => Self::Unknown,
        }
    }
}
