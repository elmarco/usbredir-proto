use bytes::Bytes;

use crate::caps::Caps;
use crate::filter::FilterRule;
use crate::proto::{Endpoint, Speed, Status, TransferType};

/// A decoded usbredir protocol packet.
///
/// Variants without an `id` field are connectionwide control messages.
/// Variants with `id` carry a request/response correlation identifier.
/// Data packet variants additionally carry a `data: Bytes` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Packet {
    // No id
    Hello {
        version: String,
        caps: Caps,
    },
    DeviceConnect {
        speed: Speed,
        device_class: u8,
        device_subclass: u8,
        device_protocol: u8,
        vendor_id: u16,
        product_id: u16,
        device_version_bcd: u16,
    },
    DeviceDisconnect,
    InterfaceInfo {
        interface_count: u32,
        interface: [u8; 32],
        interface_class: [u8; 32],
        interface_subclass: [u8; 32],
        interface_protocol: [u8; 32],
    },
    EpInfo {
        ep_type: [TransferType; 32],
        interval: [u8; 32],
        interface: [u8; 32],
        max_packet_size: [u16; 32],
        max_streams: [u32; 32],
    },
    FilterReject,
    FilterFilter {
        rules: Vec<FilterRule>,
    },
    DeviceDisconnectAck,

    // With id, no data
    Reset {
        id: u64,
    },
    SetConfiguration {
        id: u64,
        configuration: u8,
    },
    GetConfiguration {
        id: u64,
    },
    ConfigurationStatus {
        id: u64,
        status: Status,
        configuration: u8,
    },
    SetAltSetting {
        id: u64,
        interface: u8,
        alt: u8,
    },
    GetAltSetting {
        id: u64,
        interface: u8,
    },
    AltSettingStatus {
        id: u64,
        status: Status,
        interface: u8,
        alt: u8,
    },
    StartIsoStream {
        id: u64,
        endpoint: Endpoint,
        pkts_per_urb: u8,
        no_urbs: u8,
    },
    StopIsoStream {
        id: u64,
        endpoint: Endpoint,
    },
    IsoStreamStatus {
        id: u64,
        status: Status,
        endpoint: Endpoint,
    },
    StartInterruptReceiving {
        id: u64,
        endpoint: Endpoint,
    },
    StopInterruptReceiving {
        id: u64,
        endpoint: Endpoint,
    },
    InterruptReceivingStatus {
        id: u64,
        status: Status,
        endpoint: Endpoint,
    },
    AllocBulkStreams {
        id: u64,
        endpoints: u32,
        no_streams: u32,
    },
    FreeBulkStreams {
        id: u64,
        endpoints: u32,
    },
    BulkStreamsStatus {
        id: u64,
        endpoints: u32,
        no_streams: u32,
        status: Status,
    },
    CancelDataPacket {
        id: u64,
    },
    StartBulkReceiving {
        id: u64,
        stream_id: u32,
        bytes_per_transfer: u32,
        endpoint: Endpoint,
        no_transfers: u8,
    },
    StopBulkReceiving {
        id: u64,
        stream_id: u32,
        endpoint: Endpoint,
    },
    BulkReceivingStatus {
        id: u64,
        stream_id: u32,
        endpoint: Endpoint,
        status: Status,
    },

    // Data packets (id + header fields + payload)
    ControlPacket {
        id: u64,
        endpoint: Endpoint,
        request: u8,
        requesttype: u8,
        status: Status,
        value: u16,
        index: u16,
        length: u16,
        data: Bytes,
    },
    BulkPacket {
        id: u64,
        endpoint: Endpoint,
        status: Status,
        length: u32,
        stream_id: u32,
        data: Bytes,
    },
    IsoPacket {
        id: u64,
        endpoint: Endpoint,
        status: Status,
        length: u16,
        data: Bytes,
    },
    InterruptPacket {
        id: u64,
        endpoint: Endpoint,
        status: Status,
        length: u16,
        data: Bytes,
    },
    BufferedBulkPacket {
        id: u64,
        stream_id: u32,
        length: u32,
        endpoint: Endpoint,
        status: Status,
        data: Bytes,
    },
}

impl std::fmt::Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Packet::Hello { version, .. } => write!(f, "Hello(version={version:?})"),
            Packet::DeviceConnect { speed, vendor_id, product_id, .. } => {
                write!(f, "DeviceConnect(speed={speed:?}, vid={vendor_id:#06x}, pid={product_id:#06x})")
            }
            Packet::DeviceDisconnect => write!(f, "DeviceDisconnect"),
            Packet::InterfaceInfo { interface_count, .. } => {
                write!(f, "InterfaceInfo(count={interface_count})")
            }
            Packet::EpInfo { .. } => write!(f, "EpInfo"),
            Packet::FilterReject => write!(f, "FilterReject"),
            Packet::FilterFilter { rules } => write!(f, "FilterFilter(rules={})", rules.len()),
            Packet::DeviceDisconnectAck => write!(f, "DeviceDisconnectAck"),
            Packet::Reset { id } => write!(f, "Reset(id={id})"),
            Packet::SetConfiguration { id, configuration } => {
                write!(f, "SetConfiguration(id={id}, config={configuration})")
            }
            Packet::GetConfiguration { id } => write!(f, "GetConfiguration(id={id})"),
            Packet::ConfigurationStatus { id, status, configuration } => {
                write!(f, "ConfigurationStatus(id={id}, status={status:?}, config={configuration})")
            }
            Packet::SetAltSetting { id, interface, alt } => {
                write!(f, "SetAltSetting(id={id}, iface={interface}, alt={alt})")
            }
            Packet::GetAltSetting { id, interface } => {
                write!(f, "GetAltSetting(id={id}, iface={interface})")
            }
            Packet::AltSettingStatus { id, status, interface, alt } => {
                write!(f, "AltSettingStatus(id={id}, status={status:?}, iface={interface}, alt={alt})")
            }
            Packet::StartIsoStream { id, endpoint, .. } => {
                write!(f, "StartIsoStream(id={id}, {endpoint})")
            }
            Packet::StopIsoStream { id, endpoint } => {
                write!(f, "StopIsoStream(id={id}, {endpoint})")
            }
            Packet::IsoStreamStatus { id, status, endpoint } => {
                write!(f, "IsoStreamStatus(id={id}, status={status:?}, {endpoint})")
            }
            Packet::StartInterruptReceiving { id, endpoint } => {
                write!(f, "StartInterruptReceiving(id={id}, {endpoint})")
            }
            Packet::StopInterruptReceiving { id, endpoint } => {
                write!(f, "StopInterruptReceiving(id={id}, {endpoint})")
            }
            Packet::InterruptReceivingStatus { id, status, endpoint } => {
                write!(f, "InterruptReceivingStatus(id={id}, status={status:?}, {endpoint})")
            }
            Packet::AllocBulkStreams { id, endpoints, no_streams } => {
                write!(f, "AllocBulkStreams(id={id}, eps={endpoints:#x}, streams={no_streams})")
            }
            Packet::FreeBulkStreams { id, endpoints } => {
                write!(f, "FreeBulkStreams(id={id}, eps={endpoints:#x})")
            }
            Packet::BulkStreamsStatus { id, status, endpoints, no_streams } => {
                write!(f, "BulkStreamsStatus(id={id}, status={status:?}, eps={endpoints:#x}, streams={no_streams})")
            }
            Packet::CancelDataPacket { id } => write!(f, "CancelDataPacket(id={id})"),
            Packet::StartBulkReceiving { id, endpoint, stream_id, .. } => {
                write!(f, "StartBulkReceiving(id={id}, {endpoint}, stream={stream_id})")
            }
            Packet::StopBulkReceiving { id, endpoint, stream_id } => {
                write!(f, "StopBulkReceiving(id={id}, {endpoint}, stream={stream_id})")
            }
            Packet::BulkReceivingStatus { id, status, endpoint, stream_id } => {
                write!(f, "BulkReceivingStatus(id={id}, status={status:?}, {endpoint}, stream={stream_id})")
            }
            Packet::ControlPacket { id, endpoint, status, data, .. } => {
                write!(f, "ControlPacket(id={id}, {endpoint}, status={status:?}, data={}B)", data.len())
            }
            Packet::BulkPacket { id, endpoint, status, data, .. } => {
                write!(f, "BulkPacket(id={id}, {endpoint}, status={status:?}, data={}B)", data.len())
            }
            Packet::IsoPacket { id, endpoint, status, data, .. } => {
                write!(f, "IsoPacket(id={id}, {endpoint}, status={status:?}, data={}B)", data.len())
            }
            Packet::InterruptPacket { id, endpoint, status, data, .. } => {
                write!(f, "InterruptPacket(id={id}, {endpoint}, status={status:?}, data={}B)", data.len())
            }
            Packet::BufferedBulkPacket { id, endpoint, status, data, .. } => {
                write!(f, "BufferedBulkPacket(id={id}, {endpoint}, status={status:?}, data={}B)", data.len())
            }
        }
    }
}

impl Packet {
    /// Returns the wire packet type ID for this variant.
    #[must_use]
    pub fn packet_type(&self) -> u32 {
        use crate::proto::pkt_type::*;
        match self {
            Packet::Hello { .. } => HELLO,
            Packet::DeviceConnect { .. } => DEVICE_CONNECT,
            Packet::DeviceDisconnect => DEVICE_DISCONNECT,
            Packet::InterfaceInfo { .. } => INTERFACE_INFO,
            Packet::EpInfo { .. } => EP_INFO,
            Packet::FilterReject => FILTER_REJECT,
            Packet::FilterFilter { .. } => FILTER_FILTER,
            Packet::DeviceDisconnectAck => DEVICE_DISCONNECT_ACK,
            Packet::Reset { .. } => RESET,
            Packet::SetConfiguration { .. } => SET_CONFIGURATION,
            Packet::GetConfiguration { .. } => GET_CONFIGURATION,
            Packet::ConfigurationStatus { .. } => CONFIGURATION_STATUS,
            Packet::SetAltSetting { .. } => SET_ALT_SETTING,
            Packet::GetAltSetting { .. } => GET_ALT_SETTING,
            Packet::AltSettingStatus { .. } => ALT_SETTING_STATUS,
            Packet::StartIsoStream { .. } => START_ISO_STREAM,
            Packet::StopIsoStream { .. } => STOP_ISO_STREAM,
            Packet::IsoStreamStatus { .. } => ISO_STREAM_STATUS,
            Packet::StartInterruptReceiving { .. } => START_INTERRUPT_RECEIVING,
            Packet::StopInterruptReceiving { .. } => STOP_INTERRUPT_RECEIVING,
            Packet::InterruptReceivingStatus { .. } => INTERRUPT_RECEIVING_STATUS,
            Packet::AllocBulkStreams { .. } => ALLOC_BULK_STREAMS,
            Packet::FreeBulkStreams { .. } => FREE_BULK_STREAMS,
            Packet::BulkStreamsStatus { .. } => BULK_STREAMS_STATUS,
            Packet::CancelDataPacket { .. } => CANCEL_DATA_PACKET,
            Packet::StartBulkReceiving { .. } => START_BULK_RECEIVING,
            Packet::StopBulkReceiving { .. } => STOP_BULK_RECEIVING,
            Packet::BulkReceivingStatus { .. } => BULK_RECEIVING_STATUS,
            Packet::ControlPacket { .. } => CONTROL_PACKET,
            Packet::BulkPacket { .. } => BULK_PACKET,
            Packet::IsoPacket { .. } => ISO_PACKET,
            Packet::InterruptPacket { .. } => INTERRUPT_PACKET,
            Packet::BufferedBulkPacket { .. } => BUFFERED_BULK_PACKET,
        }
    }

    /// Returns the packet's correlation ID (0 for connectionwide messages).
    #[must_use]
    pub fn id(&self) -> u64 {
        match self {
            Packet::Hello { .. }
            | Packet::DeviceConnect { .. }
            | Packet::DeviceDisconnect
            | Packet::InterfaceInfo { .. }
            | Packet::EpInfo { .. }
            | Packet::FilterReject
            | Packet::FilterFilter { .. }
            | Packet::DeviceDisconnectAck => 0,
            Packet::Reset { id, .. }
            | Packet::SetConfiguration { id, .. }
            | Packet::GetConfiguration { id, .. }
            | Packet::ConfigurationStatus { id, .. }
            | Packet::SetAltSetting { id, .. }
            | Packet::GetAltSetting { id, .. }
            | Packet::AltSettingStatus { id, .. }
            | Packet::StartIsoStream { id, .. }
            | Packet::StopIsoStream { id, .. }
            | Packet::IsoStreamStatus { id, .. }
            | Packet::StartInterruptReceiving { id, .. }
            | Packet::StopInterruptReceiving { id, .. }
            | Packet::InterruptReceivingStatus { id, .. }
            | Packet::AllocBulkStreams { id, .. }
            | Packet::FreeBulkStreams { id, .. }
            | Packet::BulkStreamsStatus { id, .. }
            | Packet::CancelDataPacket { id, .. }
            | Packet::StartBulkReceiving { id, .. }
            | Packet::StopBulkReceiving { id, .. }
            | Packet::BulkReceivingStatus { id, .. }
            | Packet::ControlPacket { id, .. }
            | Packet::BulkPacket { id, .. }
            | Packet::IsoPacket { id, .. }
            | Packet::InterruptPacket { id, .. }
            | Packet::BufferedBulkPacket { id, .. } => *id,
        }
    }

    // -- Helper constructors --

    /// Create a Hello packet.
    #[must_use]
    pub fn hello(version: impl Into<String>, caps: Caps) -> Self {
        Self::Hello { version: version.into(), caps }
    }

    /// Create a DeviceConnect packet.
    #[must_use]
    pub fn device_connect(
        speed: Speed,
        device_class: u8,
        device_subclass: u8,
        device_protocol: u8,
        vendor_id: u16,
        product_id: u16,
        device_version_bcd: u16,
    ) -> Self {
        Self::DeviceConnect {
            speed, device_class, device_subclass, device_protocol,
            vendor_id, product_id, device_version_bcd,
        }
    }

    /// Create an InterfaceInfo packet.
    #[must_use]
    pub fn interface_info(
        interface_count: u32,
        interface: [u8; 32],
        interface_class: [u8; 32],
        interface_subclass: [u8; 32],
        interface_protocol: [u8; 32],
    ) -> Self {
        Self::InterfaceInfo {
            interface_count, interface, interface_class,
            interface_subclass, interface_protocol,
        }
    }

    /// Create an EpInfo packet.
    #[must_use]
    pub fn ep_info(
        ep_type: [TransferType; 32],
        interval: [u8; 32],
        interface: [u8; 32],
        max_packet_size: [u16; 32],
        max_streams: [u32; 32],
    ) -> Self {
        Self::EpInfo { ep_type, interval, interface, max_packet_size, max_streams }
    }

    /// Create a FilterFilter packet.
    #[must_use]
    pub fn filter_filter(rules: Vec<FilterRule>) -> Self {
        Self::FilterFilter { rules }
    }

    /// Create a Reset packet.
    #[must_use]
    pub fn reset(id: u64) -> Self {
        Self::Reset { id }
    }

    /// Create a SetConfiguration packet.
    #[must_use]
    pub fn set_configuration(id: u64, configuration: u8) -> Self {
        Self::SetConfiguration { id, configuration }
    }

    /// Create a GetConfiguration packet.
    #[must_use]
    pub fn get_configuration(id: u64) -> Self {
        Self::GetConfiguration { id }
    }

    /// Create a ConfigurationStatus packet.
    #[must_use]
    pub fn configuration_status(id: u64, status: Status, configuration: u8) -> Self {
        Self::ConfigurationStatus { id, status, configuration }
    }

    /// Create a SetAltSetting packet.
    #[must_use]
    pub fn set_alt_setting(id: u64, interface: u8, alt: u8) -> Self {
        Self::SetAltSetting { id, interface, alt }
    }

    /// Create a GetAltSetting packet.
    #[must_use]
    pub fn get_alt_setting(id: u64, interface: u8) -> Self {
        Self::GetAltSetting { id, interface }
    }

    /// Create an AltSettingStatus packet.
    #[must_use]
    pub fn alt_setting_status(id: u64, status: Status, interface: u8, alt: u8) -> Self {
        Self::AltSettingStatus { id, status, interface, alt }
    }

    /// Create a StartIsoStream packet.
    #[must_use]
    pub fn start_iso_stream(id: u64, endpoint: Endpoint, pkts_per_urb: u8, no_urbs: u8) -> Self {
        Self::StartIsoStream { id, endpoint, pkts_per_urb, no_urbs }
    }

    /// Create a StopIsoStream packet.
    #[must_use]
    pub fn stop_iso_stream(id: u64, endpoint: Endpoint) -> Self {
        Self::StopIsoStream { id, endpoint }
    }

    /// Create an IsoStreamStatus packet.
    #[must_use]
    pub fn iso_stream_status(id: u64, status: Status, endpoint: Endpoint) -> Self {
        Self::IsoStreamStatus { id, status, endpoint }
    }

    /// Create a StartInterruptReceiving packet.
    #[must_use]
    pub fn start_interrupt_receiving(id: u64, endpoint: Endpoint) -> Self {
        Self::StartInterruptReceiving { id, endpoint }
    }

    /// Create a StopInterruptReceiving packet.
    #[must_use]
    pub fn stop_interrupt_receiving(id: u64, endpoint: Endpoint) -> Self {
        Self::StopInterruptReceiving { id, endpoint }
    }

    /// Create an InterruptReceivingStatus packet.
    #[must_use]
    pub fn interrupt_receiving_status(id: u64, status: Status, endpoint: Endpoint) -> Self {
        Self::InterruptReceivingStatus { id, status, endpoint }
    }

    /// Create an AllocBulkStreams packet.
    #[must_use]
    pub fn alloc_bulk_streams(id: u64, endpoints: u32, no_streams: u32) -> Self {
        Self::AllocBulkStreams { id, endpoints, no_streams }
    }

    /// Create a FreeBulkStreams packet.
    #[must_use]
    pub fn free_bulk_streams(id: u64, endpoints: u32) -> Self {
        Self::FreeBulkStreams { id, endpoints }
    }

    /// Create a BulkStreamsStatus packet.
    #[must_use]
    pub fn bulk_streams_status(id: u64, endpoints: u32, no_streams: u32, status: Status) -> Self {
        Self::BulkStreamsStatus { id, endpoints, no_streams, status }
    }

    /// Create a CancelDataPacket packet.
    #[must_use]
    pub fn cancel_data_packet(id: u64) -> Self {
        Self::CancelDataPacket { id }
    }

    /// Create a StartBulkReceiving packet.
    #[must_use]
    pub fn start_bulk_receiving(
        id: u64,
        stream_id: u32,
        bytes_per_transfer: u32,
        endpoint: Endpoint,
        no_transfers: u8,
    ) -> Self {
        Self::StartBulkReceiving { id, stream_id, bytes_per_transfer, endpoint, no_transfers }
    }

    /// Create a StopBulkReceiving packet.
    #[must_use]
    pub fn stop_bulk_receiving(id: u64, stream_id: u32, endpoint: Endpoint) -> Self {
        Self::StopBulkReceiving { id, stream_id, endpoint }
    }

    /// Create a BulkReceivingStatus packet.
    #[must_use]
    pub fn bulk_receiving_status(id: u64, stream_id: u32, endpoint: Endpoint, status: Status) -> Self {
        Self::BulkReceivingStatus { id, stream_id, endpoint, status }
    }

    /// Create a ControlPacket.
    #[must_use]
    pub fn control_packet(
        id: u64,
        endpoint: Endpoint,
        request: u8,
        requesttype: u8,
        status: Status,
        value: u16,
        index: u16,
        length: u16,
        data: impl Into<Bytes>,
    ) -> Self {
        Self::ControlPacket {
            id, endpoint, request, requesttype, status,
            value, index, length, data: data.into(),
        }
    }

    /// Create a BulkPacket.
    #[must_use]
    pub fn bulk_packet(
        id: u64,
        endpoint: Endpoint,
        status: Status,
        length: u32,
        stream_id: u32,
        data: impl Into<Bytes>,
    ) -> Self {
        Self::BulkPacket { id, endpoint, status, length, stream_id, data: data.into() }
    }

    /// Create an IsoPacket.
    #[must_use]
    pub fn iso_packet(
        id: u64,
        endpoint: Endpoint,
        status: Status,
        length: u16,
        data: impl Into<Bytes>,
    ) -> Self {
        Self::IsoPacket { id, endpoint, status, length, data: data.into() }
    }

    /// Create an InterruptPacket.
    #[must_use]
    pub fn interrupt_packet(
        id: u64,
        endpoint: Endpoint,
        status: Status,
        length: u16,
        data: impl Into<Bytes>,
    ) -> Self {
        Self::InterruptPacket { id, endpoint, status, length, data: data.into() }
    }

    /// Create a BufferedBulkPacket.
    #[must_use]
    pub fn buffered_bulk_packet(
        id: u64,
        stream_id: u32,
        length: u32,
        endpoint: Endpoint,
        status: Status,
        data: impl Into<Bytes>,
    ) -> Self {
        Self::BufferedBulkPacket { id, stream_id, length, endpoint, status, data: data.into() }
    }
}
