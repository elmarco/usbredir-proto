use bytes::Bytes;

use crate::caps::Caps;
use crate::filter::FilterRule;
use crate::proto::{Speed, Status, TransferType};

/// A decoded usbredir protocol packet.
///
/// Variants without an `id` field are connectionwide control messages.
/// Variants with `id` carry a request/response correlation identifier.
/// Data packet variants additionally carry a `data: Bytes` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        endpoint: u8,
        pkts_per_urb: u8,
        no_urbs: u8,
    },
    StopIsoStream {
        id: u64,
        endpoint: u8,
    },
    IsoStreamStatus {
        id: u64,
        status: Status,
        endpoint: u8,
    },
    StartInterruptReceiving {
        id: u64,
        endpoint: u8,
    },
    StopInterruptReceiving {
        id: u64,
        endpoint: u8,
    },
    InterruptReceivingStatus {
        id: u64,
        status: Status,
        endpoint: u8,
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
        endpoint: u8,
        no_transfers: u8,
    },
    StopBulkReceiving {
        id: u64,
        stream_id: u32,
        endpoint: u8,
    },
    BulkReceivingStatus {
        id: u64,
        stream_id: u32,
        endpoint: u8,
        status: Status,
    },

    // Data packets (id + header fields + payload)
    ControlPacket {
        id: u64,
        endpoint: u8,
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
        endpoint: u8,
        status: Status,
        length: u32,
        stream_id: u32,
        data: Bytes,
    },
    IsoPacket {
        id: u64,
        endpoint: u8,
        status: Status,
        length: u16,
        data: Bytes,
    },
    InterruptPacket {
        id: u64,
        endpoint: u8,
        status: Status,
        length: u16,
        data: Bytes,
    },
    BufferedBulkPacket {
        id: u64,
        stream_id: u32,
        length: u32,
        endpoint: u8,
        status: Status,
        data: Bytes,
    },
}

impl Packet {
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
}
