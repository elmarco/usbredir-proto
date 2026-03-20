/// Protocol version constant (0.7.1), as defined in `usb-redirection-protocol.md`.
pub const USBREDIR_VERSION: u32 = 0x000701;
/// Maximum allowed bulk transfer payload size (128 MiB).
pub const MAX_BULK_TRANSFER_SIZE: u32 = 128 * 1024 * 1024;
/// Maximum total packet size (type-specific header + data payload).
pub const MAX_PACKET_SIZE: u32 = 1024 + MAX_BULK_TRANSFER_SIZE;

// Ensure usize is at least 32 bits — packet lengths are u32 and cast to usize.
const _: () = assert!(
    core::mem::size_of::<usize>() >= core::mem::size_of::<u32>(),
    "usbredir-proto requires a target with at least 32-bit usize"
);

/// Wire packet type IDs matching the C `usb_redir_type` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PktType {
    Hello = 0,
    DeviceConnect = 1,
    DeviceDisconnect = 2,
    Reset = 3,
    InterfaceInfo = 4,
    EpInfo = 5,
    SetConfiguration = 6,
    GetConfiguration = 7,
    ConfigurationStatus = 8,
    SetAltSetting = 9,
    GetAltSetting = 10,
    AltSettingStatus = 11,
    StartIsoStream = 12,
    StopIsoStream = 13,
    IsoStreamStatus = 14,
    StartInterruptReceiving = 15,
    StopInterruptReceiving = 16,
    InterruptReceivingStatus = 17,
    AllocBulkStreams = 18,
    FreeBulkStreams = 19,
    BulkStreamsStatus = 20,
    CancelDataPacket = 21,
    FilterReject = 22,
    FilterFilter = 23,
    DeviceDisconnectAck = 24,
    StartBulkReceiving = 25,
    StopBulkReceiving = 26,
    BulkReceivingStatus = 27,
    ControlPacket = 100,
    BulkPacket = 101,
    IsoPacket = 102,
    InterruptPacket = 103,
    BufferedBulkPacket = 104,
}

impl TryFrom<u32> for PktType {
    type Error = u32;

    fn try_from(v: u32) -> core::result::Result<Self, u32> {
        match v {
            0 => Ok(Self::Hello),
            1 => Ok(Self::DeviceConnect),
            2 => Ok(Self::DeviceDisconnect),
            3 => Ok(Self::Reset),
            4 => Ok(Self::InterfaceInfo),
            5 => Ok(Self::EpInfo),
            6 => Ok(Self::SetConfiguration),
            7 => Ok(Self::GetConfiguration),
            8 => Ok(Self::ConfigurationStatus),
            9 => Ok(Self::SetAltSetting),
            10 => Ok(Self::GetAltSetting),
            11 => Ok(Self::AltSettingStatus),
            12 => Ok(Self::StartIsoStream),
            13 => Ok(Self::StopIsoStream),
            14 => Ok(Self::IsoStreamStatus),
            15 => Ok(Self::StartInterruptReceiving),
            16 => Ok(Self::StopInterruptReceiving),
            17 => Ok(Self::InterruptReceivingStatus),
            18 => Ok(Self::AllocBulkStreams),
            19 => Ok(Self::FreeBulkStreams),
            20 => Ok(Self::BulkStreamsStatus),
            21 => Ok(Self::CancelDataPacket),
            22 => Ok(Self::FilterReject),
            23 => Ok(Self::FilterFilter),
            24 => Ok(Self::DeviceDisconnectAck),
            25 => Ok(Self::StartBulkReceiving),
            26 => Ok(Self::StopBulkReceiving),
            27 => Ok(Self::BulkReceivingStatus),
            100 => Ok(Self::ControlPacket),
            101 => Ok(Self::BulkPacket),
            102 => Ok(Self::IsoPacket),
            103 => Ok(Self::InterruptPacket),
            104 => Ok(Self::BufferedBulkPacket),
            _ => Err(v),
        }
    }
}

impl From<PktType> for u32 {
    fn from(p: PktType) -> u32 {
        p as u32
    }
}

/// Backward-compatible module re-exporting packet type IDs as constants.
#[doc(hidden)]
pub mod pkt_type {
    use super::PktType;

    pub const HELLO: u32 = PktType::Hello as u32;
    pub const DEVICE_CONNECT: u32 = PktType::DeviceConnect as u32;
    pub const DEVICE_DISCONNECT: u32 = PktType::DeviceDisconnect as u32;
    pub const RESET: u32 = PktType::Reset as u32;
    pub const INTERFACE_INFO: u32 = PktType::InterfaceInfo as u32;
    pub const EP_INFO: u32 = PktType::EpInfo as u32;
    pub const SET_CONFIGURATION: u32 = PktType::SetConfiguration as u32;
    pub const GET_CONFIGURATION: u32 = PktType::GetConfiguration as u32;
    pub const CONFIGURATION_STATUS: u32 = PktType::ConfigurationStatus as u32;
    pub const SET_ALT_SETTING: u32 = PktType::SetAltSetting as u32;
    pub const GET_ALT_SETTING: u32 = PktType::GetAltSetting as u32;
    pub const ALT_SETTING_STATUS: u32 = PktType::AltSettingStatus as u32;
    pub const START_ISO_STREAM: u32 = PktType::StartIsoStream as u32;
    pub const STOP_ISO_STREAM: u32 = PktType::StopIsoStream as u32;
    pub const ISO_STREAM_STATUS: u32 = PktType::IsoStreamStatus as u32;
    pub const START_INTERRUPT_RECEIVING: u32 = PktType::StartInterruptReceiving as u32;
    pub const STOP_INTERRUPT_RECEIVING: u32 = PktType::StopInterruptReceiving as u32;
    pub const INTERRUPT_RECEIVING_STATUS: u32 = PktType::InterruptReceivingStatus as u32;
    pub const ALLOC_BULK_STREAMS: u32 = PktType::AllocBulkStreams as u32;
    pub const FREE_BULK_STREAMS: u32 = PktType::FreeBulkStreams as u32;
    pub const BULK_STREAMS_STATUS: u32 = PktType::BulkStreamsStatus as u32;
    pub const CANCEL_DATA_PACKET: u32 = PktType::CancelDataPacket as u32;
    pub const FILTER_REJECT: u32 = PktType::FilterReject as u32;
    pub const FILTER_FILTER: u32 = PktType::FilterFilter as u32;
    pub const DEVICE_DISCONNECT_ACK: u32 = PktType::DeviceDisconnectAck as u32;
    pub const START_BULK_RECEIVING: u32 = PktType::StartBulkReceiving as u32;
    pub const STOP_BULK_RECEIVING: u32 = PktType::StopBulkReceiving as u32;
    pub const BULK_RECEIVING_STATUS: u32 = PktType::BulkReceivingStatus as u32;
    pub const CONTROL_PACKET: u32 = PktType::ControlPacket as u32;
    pub const BULK_PACKET: u32 = PktType::BulkPacket as u32;
    pub const ISO_PACKET: u32 = PktType::IsoPacket as u32;
    pub const INTERRUPT_PACKET: u32 = PktType::InterruptPacket as u32;
    pub const BUFFERED_BULK_PACKET: u32 = PktType::BufferedBulkPacket as u32;
}

/// USB transfer completion status (maps to `libusb_transfer_status`).
///
/// Returned by the host to indicate the outcome of a USB transfer request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Status {
    /// Transfer completed without error.
    Success = 0,
    /// Transfer was cancelled by the host.
    Cancelled = 1,
    /// Invalid parameter (e.g. bad endpoint, malformed setup packet).
    Inval = 2,
    /// Low-level I/O error on the host controller.
    IoError = 3,
    /// Endpoint returned a STALL handshake (often means "unsupported request").
    Stall = 4,
    /// Transfer did not complete within the allowed time.
    Timeout = 5,
    /// Device sent more data than expected (overflow condition).
    Babble = 6,
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

    fn try_from(v: u8) -> core::result::Result<Self, u8> {
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

/// USB endpoint transfer type (see [USB 2.0 spec §5.4–5.7][usbspec]).
///
/// Each USB endpoint is configured for exactly one transfer type, which
/// determines its throughput, latency, and error-handling characteristics.
///
/// [usbspec]: https://www.usb.org/document-library/usb-20-specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum TransferType {
    /// Used for device enumeration and configuration (endpoint 0).
    Control = 0,
    /// Isochronous — guaranteed bandwidth, no retries (audio/video streaming).
    Iso = 1,
    /// Bulk — reliable, large transfers with no latency guarantee (storage, printing).
    Bulk = 2,
    /// Interrupt — small, latency-sensitive transfers with guaranteed polling interval (HID, keyboards).
    Interrupt = 3,
    /// Sentinel for unused endpoint slots in [`EpInfo`](crate::Packet::EpInfo) arrays.
    Invalid = 255,
}

impl core::fmt::Display for TransferType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

    fn try_from(v: u8) -> core::result::Result<Self, u8> {
        match v {
            0 => Ok(Self::Control),
            1 => Ok(Self::Iso),
            2 => Ok(Self::Bulk),
            3 => Ok(Self::Interrupt),
            255 => Ok(Self::Invalid),
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
///
/// // Reserved bits 4–6 are masked off:
/// assert_eq!(Endpoint::new(0xFF).raw(), 0x8F);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint(u8);

impl Endpoint {
    /// Create an endpoint from a raw USB endpoint address byte.
    ///
    /// Bits 4–6 are reserved per the USB spec and are masked off.
    /// Only bit 7 (direction) and bits 0–3 (endpoint number) are kept.
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw & 0x8F)
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
    ///
    /// Note: endpoint 0 (`Endpoint::new(0)`) returns `true` here even though
    /// USB endpoint 0 is bidirectional (control endpoint). The usbredir protocol
    /// uses the direction bit in data packet headers to distinguish IN vs OUT
    /// control transfers, so EP0 with bit 7 clear is treated as OUT.
    #[must_use]
    pub const fn is_output(self) -> bool {
        self.0 & 0x80 == 0
    }
}

impl From<u8> for Endpoint {
    fn from(v: u8) -> Self {
        Self::new(v)
    }
}

impl From<Endpoint> for u8 {
    fn from(ep: Endpoint) -> Self {
        ep.0
    }
}

impl core::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let dir = if self.is_input() { "IN" } else { "OUT" };
        write!(f, "ep{} {dir}", self.number())
    }
}

/// USB device speed class.
///
/// Reported by the host in [`DeviceConnect`](crate::Packet::DeviceConnect)
/// to tell the guest how fast the device operates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Speed {
    /// USB 1.0 Low Speed (1.5 Mbit/s).
    Low = 0,
    /// USB 1.1 Full Speed (12 Mbit/s).
    Full = 1,
    /// USB 2.0 High Speed (480 Mbit/s).
    High = 2,
    /// USB 3.x SuperSpeed (5+ Gbit/s).
    Super = 3,
    /// Speed could not be determined.
    Unknown = 255,
}

impl core::fmt::Display for Speed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

    fn try_from(v: u8) -> core::result::Result<Self, u8> {
        match v {
            0 => Ok(Self::Low),
            1 => Ok(Self::Full),
            2 => Ok(Self::High),
            3 => Ok(Self::Super),
            255 => Ok(Self::Unknown),
            _ => Err(v),
        }
    }
}
