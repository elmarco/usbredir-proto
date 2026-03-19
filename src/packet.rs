use alloc::string::String;
use alloc::vec::Vec;

use bytes::Bytes;

use crate::caps::Caps;
use crate::filter::FilterRule;
use crate::proto::{Endpoint, Speed, Status, TransferType};

/// The type-specific part of a data transfer packet.
///
/// Each USB transfer type has its own header fields beyond the shared
/// [`DataPacket`] fields (`id`, `endpoint`, `status`, `data`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataKind {
    /// USB control transfer (endpoint 0 setup transactions).
    ///
    /// `request`, `requesttype`, `value`, and `index` map directly to the
    /// fields of a USB SETUP packet (see [USB 2.0 spec §9.3][setup]).
    ///
    /// [setup]: https://www.usb.org/document-library/usb-20-specification
    Control {
        request: u8,
        requesttype: u8,
        value: u16,
        index: u16,
        length: u16,
    },
    /// USB bulk transfer. Used for large, reliable transfers with no latency
    /// guarantee (e.g. mass storage, printing).
    Bulk { length: u32, stream_id: u32 },
    /// USB isochronous transfer. Used for real-time data (e.g. audio/video)
    /// where occasional data loss is acceptable.
    Iso { length: u16 },
    /// USB interrupt transfer. Used for small, latency-sensitive transfers
    /// (e.g. keyboard/mouse input).
    Interrupt { length: u16 },
    /// Host-buffered bulk IN transfer. Requires
    /// [`Cap::BulkReceiving`](crate::Cap::BulkReceiving).
    BufferedBulk { stream_id: u32, length: u32 },
}

impl DataKind {
    /// Returns the wire packet type ID for this data kind.
    #[must_use]
    pub fn packet_type(&self) -> u32 {
        use crate::proto::pkt_type::*;
        match self {
            DataKind::Control { .. } => CONTROL_PACKET,
            DataKind::Bulk { .. } => BULK_PACKET,
            DataKind::Iso { .. } => ISO_PACKET,
            DataKind::Interrupt { .. } => INTERRUPT_PACKET,
            DataKind::BufferedBulk { .. } => BUFFERED_BULK_PACKET,
        }
    }

    /// Returns the `length` field from the type-specific header.
    #[must_use]
    pub fn length(&self) -> u32 {
        match self {
            DataKind::Control { length, .. } => *length as u32,
            DataKind::Bulk { length, .. } => *length,
            DataKind::Iso { length, .. } => *length as u32,
            DataKind::Interrupt { length, .. } => *length as u32,
            DataKind::BufferedBulk { length, .. } => *length,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            DataKind::Control { .. } => "ControlPacket",
            DataKind::Bulk { .. } => "BulkPacket",
            DataKind::Iso { .. } => "IsoPacket",
            DataKind::Interrupt { .. } => "InterruptPacket",
            DataKind::BufferedBulk { .. } => "BufferedBulkPacket",
        }
    }
}

/// A USB data transfer packet, with shared fields and a type-specific [`DataKind`].
///
/// All data packets carry an `id` (correlation identifier), `endpoint`,
/// `status`, variable-length `data`, and type-specific header fields in `kind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    /// Correlation identifier chosen by the requester.
    pub id: u64,
    /// USB endpoint address.
    pub endpoint: Endpoint,
    /// Transfer completion status.
    pub status: Status,
    /// Type-specific header fields.
    pub kind: DataKind,
    /// Payload bytes.
    pub data: Bytes,
}

impl core::fmt::Display for DataPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}(id={}, {}, status={:?}, data={}B)",
            self.kind.label(),
            self.id,
            self.endpoint,
            self.status,
            self.data.len()
        )
    }
}

impl DataPacket {
    /// Create a control transfer packet.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn control(
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
        Self {
            id,
            endpoint,
            status,
            kind: DataKind::Control {
                request,
                requesttype,
                value,
                index,
                length,
            },
            data: data.into(),
        }
    }

    /// Create a bulk transfer packet.
    #[must_use]
    pub fn bulk(
        id: u64,
        endpoint: Endpoint,
        status: Status,
        length: u32,
        stream_id: u32,
        data: impl Into<Bytes>,
    ) -> Self {
        Self {
            id,
            endpoint,
            status,
            kind: DataKind::Bulk { length, stream_id },
            data: data.into(),
        }
    }

    /// Create an isochronous transfer packet.
    #[must_use]
    pub fn iso(
        id: u64,
        endpoint: Endpoint,
        status: Status,
        length: u16,
        data: impl Into<Bytes>,
    ) -> Self {
        Self {
            id,
            endpoint,
            status,
            kind: DataKind::Iso { length },
            data: data.into(),
        }
    }

    /// Create an interrupt transfer packet.
    #[must_use]
    pub fn interrupt(
        id: u64,
        endpoint: Endpoint,
        status: Status,
        length: u16,
        data: impl Into<Bytes>,
    ) -> Self {
        Self {
            id,
            endpoint,
            status,
            kind: DataKind::Interrupt { length },
            data: data.into(),
        }
    }

    /// Create a buffered bulk transfer packet.
    #[must_use]
    pub fn buffered_bulk(
        id: u64,
        stream_id: u32,
        length: u32,
        endpoint: Endpoint,
        status: Status,
        data: impl Into<Bytes>,
    ) -> Self {
        Self {
            id,
            endpoint,
            status,
            kind: DataKind::BufferedBulk { stream_id, length },
            data: data.into(),
        }
    }
}

/// A decoded usbredir protocol packet.
///
/// The protocol uses a request/response model between a **host** (physical USB
/// device) and a **guest** (e.g. a VM). Some packets flow in only one
/// direction; data packets are bidirectional.
///
/// # Packet categories
///
/// | Category | `id` field | `data` field | Examples |
/// |----------|-----------|-------------|----------|
/// | **Connection-wide** | No | No | `Hello`, `DeviceConnect`, `DeviceDisconnect` |
/// | **Request/response** | Yes | No | `SetConfiguration` / `ConfigurationStatus` |
/// | **Data** | Yes | Yes | [`Data`](Self::Data) ([`DataKind::Control`], [`DataKind::Bulk`], etc.) |
///
/// The `id` is a correlation identifier chosen by the requester so that
/// responses can be matched to requests.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Packet {
    // ── Connection-wide (no id) ─────────────────────────────────────────
    /// Initial handshake, exchanged by both sides. Carries a version string
    /// and the sender's capability bitmask. Automatically sent on
    /// [`Parser::new()`](crate::Parser::new) unless `no_hello` is set.
    Hello { version: String, caps: Caps },
    /// Host → guest: a USB device has been connected.
    ///
    /// `device_class` / `device_subclass` / `device_protocol` are the USB
    /// [class codes](https://www.usb.org/defined-class-codes).
    /// `vendor_id` and `product_id` identify the device manufacturer/product.
    /// `device_version_bcd` is the BCD-encoded device release number (requires
    /// [`Cap::ConnectDeviceVersion`](crate::Cap::ConnectDeviceVersion)).
    DeviceConnect {
        speed: Speed,
        device_class: u8,
        device_subclass: u8,
        device_protocol: u8,
        vendor_id: u16,
        product_id: u16,
        device_version_bcd: u16,
    },
    /// Host → guest: the USB device has been disconnected.
    DeviceDisconnect,
    /// Host → guest: describes the device's USB interfaces (up to 32).
    ///
    /// Arrays are indexed by interface number. Only the first
    /// `interface_count` entries are meaningful.
    InterfaceInfo {
        interface_count: u32,
        interface: [u8; 32],
        interface_class: [u8; 32],
        interface_subclass: [u8; 32],
        interface_protocol: [u8; 32],
    },
    /// Host → guest: describes all 32 endpoint slots.
    ///
    /// USB devices have up to 16 endpoints × 2 directions = 32 slots
    /// (indexed 0x00–0x0F for OUT, 0x80–0x8F for IN). Unused slots have
    /// `ep_type` set to [`TransferType::Invalid`].
    EpInfo {
        ep_type: [TransferType; 32],
        interval: [u8; 32],
        interface: [u8; 32],
        max_packet_size: [u16; 32],
        max_streams: [u32; 32],
    },
    /// Guest → host: the guest rejected the device (e.g. due to filter rules).
    /// Requires [`Cap::Filter`](crate::Cap::Filter).
    FilterReject,
    /// Bidirectional: transmit a set of device filter rules. Requires [`Cap::Filter`](crate::Cap::Filter).
    FilterFilter { rules: Vec<FilterRule> },
    /// Guest → host: acknowledges a `DeviceDisconnect`. Requires [`Cap::DeviceDisconnectAck`](crate::Cap::DeviceDisconnectAck).
    DeviceDisconnectAck,

    // ── Request/response (with id, no data) ─────────────────────────────
    /// Guest → host: reset the USB device.
    Reset { id: u64 },
    /// Guest → host: select a USB configuration.
    SetConfiguration { id: u64, configuration: u8 },
    /// Guest → host: query the current USB configuration.
    GetConfiguration { id: u64 },
    /// Host → guest: response to `SetConfiguration` or `GetConfiguration`.
    ConfigurationStatus {
        id: u64,
        status: Status,
        configuration: u8,
    },
    /// Guest → host: select an alternate setting for an interface.
    SetAltSetting { id: u64, interface: u8, alt: u8 },
    /// Guest → host: query the current alternate setting for an interface.
    GetAltSetting { id: u64, interface: u8 },
    /// Host → guest: response to `SetAltSetting` or `GetAltSetting`.
    AltSettingStatus {
        id: u64,
        status: Status,
        interface: u8,
        alt: u8,
    },
    /// Guest → host: start an isochronous stream on the given endpoint.
    ///
    /// `pkts_per_urb` and `no_urbs` control host-side buffering (URB =
    /// USB Request Block, the kernel's unit of USB I/O).
    StartIsoStream {
        id: u64,
        endpoint: Endpoint,
        pkts_per_urb: u8,
        no_urbs: u8,
    },
    /// Guest → host: stop an isochronous stream.
    StopIsoStream { id: u64, endpoint: Endpoint },
    /// Host → guest: response to `StartIsoStream` or `StopIsoStream`.
    IsoStreamStatus {
        id: u64,
        status: Status,
        endpoint: Endpoint,
    },
    /// Guest → host: start forwarding interrupt IN transfers from this endpoint.
    StartInterruptReceiving { id: u64, endpoint: Endpoint },
    /// Guest → host: stop forwarding interrupt IN transfers.
    StopInterruptReceiving { id: u64, endpoint: Endpoint },
    /// Host → guest: response to `StartInterruptReceiving` / `StopInterruptReceiving`.
    InterruptReceivingStatus {
        id: u64,
        status: Status,
        endpoint: Endpoint,
    },
    /// Guest → host: allocate USB 3.0 bulk streams on a set of endpoints.
    /// `endpoints` is a bitmask. Requires [`Cap::BulkStreams`](crate::Cap::BulkStreams).
    AllocBulkStreams {
        id: u64,
        endpoints: u32,
        no_streams: u32,
    },
    /// Guest → host: free previously allocated bulk streams.
    FreeBulkStreams { id: u64, endpoints: u32 },
    /// Host → guest: response to `AllocBulkStreams` / `FreeBulkStreams`.
    BulkStreamsStatus {
        id: u64,
        endpoints: u32,
        no_streams: u32,
        status: Status,
    },
    /// Guest → host: cancel a pending data transfer identified by `id`.
    CancelDataPacket { id: u64 },
    /// Guest → host: start host-buffered bulk IN receiving. Requires [`Cap::BulkReceiving`](crate::Cap::BulkReceiving).
    StartBulkReceiving {
        id: u64,
        stream_id: u32,
        bytes_per_transfer: u32,
        endpoint: Endpoint,
        no_transfers: u8,
    },
    /// Guest → host: stop host-buffered bulk IN receiving.
    StopBulkReceiving {
        id: u64,
        stream_id: u32,
        endpoint: Endpoint,
    },
    /// Host → guest: response to `StartBulkReceiving` / `StopBulkReceiving`.
    BulkReceivingStatus {
        id: u64,
        stream_id: u32,
        endpoint: Endpoint,
        status: Status,
    },

    // ── Data packets (id + header fields + payload) ─────────────────────
    /// A USB data transfer packet (control, bulk, isochronous, interrupt,
    /// or buffered bulk). See [`DataPacket`] and [`DataKind`] for details.
    Data(DataPacket),
}

impl core::fmt::Display for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Packet::Hello { version, .. } => write!(f, "Hello(version={version:?})"),
            Packet::DeviceConnect {
                speed,
                vendor_id,
                product_id,
                ..
            } => {
                write!(
                    f,
                    "DeviceConnect(speed={speed:?}, vid={vendor_id:#06x}, pid={product_id:#06x})"
                )
            }
            Packet::DeviceDisconnect => write!(f, "DeviceDisconnect"),
            Packet::InterfaceInfo {
                interface_count, ..
            } => {
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
            Packet::ConfigurationStatus {
                id,
                status,
                configuration,
            } => {
                write!(
                    f,
                    "ConfigurationStatus(id={id}, status={status:?}, config={configuration})"
                )
            }
            Packet::SetAltSetting { id, interface, alt } => {
                write!(f, "SetAltSetting(id={id}, iface={interface}, alt={alt})")
            }
            Packet::GetAltSetting { id, interface } => {
                write!(f, "GetAltSetting(id={id}, iface={interface})")
            }
            Packet::AltSettingStatus {
                id,
                status,
                interface,
                alt,
            } => {
                write!(
                    f,
                    "AltSettingStatus(id={id}, status={status:?}, iface={interface}, alt={alt})"
                )
            }
            Packet::StartIsoStream { id, endpoint, .. } => {
                write!(f, "StartIsoStream(id={id}, {endpoint})")
            }
            Packet::StopIsoStream { id, endpoint } => {
                write!(f, "StopIsoStream(id={id}, {endpoint})")
            }
            Packet::IsoStreamStatus {
                id,
                status,
                endpoint,
            } => {
                write!(f, "IsoStreamStatus(id={id}, status={status:?}, {endpoint})")
            }
            Packet::StartInterruptReceiving { id, endpoint } => {
                write!(f, "StartInterruptReceiving(id={id}, {endpoint})")
            }
            Packet::StopInterruptReceiving { id, endpoint } => {
                write!(f, "StopInterruptReceiving(id={id}, {endpoint})")
            }
            Packet::InterruptReceivingStatus {
                id,
                status,
                endpoint,
            } => {
                write!(
                    f,
                    "InterruptReceivingStatus(id={id}, status={status:?}, {endpoint})"
                )
            }
            Packet::AllocBulkStreams {
                id,
                endpoints,
                no_streams,
            } => {
                write!(
                    f,
                    "AllocBulkStreams(id={id}, eps={endpoints:#x}, streams={no_streams})"
                )
            }
            Packet::FreeBulkStreams { id, endpoints } => {
                write!(f, "FreeBulkStreams(id={id}, eps={endpoints:#x})")
            }
            Packet::BulkStreamsStatus {
                id,
                status,
                endpoints,
                no_streams,
            } => {
                write!(f, "BulkStreamsStatus(id={id}, status={status:?}, eps={endpoints:#x}, streams={no_streams})")
            }
            Packet::CancelDataPacket { id } => write!(f, "CancelDataPacket(id={id})"),
            Packet::StartBulkReceiving {
                id,
                endpoint,
                stream_id,
                ..
            } => {
                write!(
                    f,
                    "StartBulkReceiving(id={id}, {endpoint}, stream={stream_id})"
                )
            }
            Packet::StopBulkReceiving {
                id,
                endpoint,
                stream_id,
            } => {
                write!(
                    f,
                    "StopBulkReceiving(id={id}, {endpoint}, stream={stream_id})"
                )
            }
            Packet::BulkReceivingStatus {
                id,
                status,
                endpoint,
                stream_id,
            } => {
                write!(f, "BulkReceivingStatus(id={id}, status={status:?}, {endpoint}, stream={stream_id})")
            }
            Packet::Data(d) => d.fmt(f),
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
            Packet::Data(d) => d.kind.packet_type(),
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
            | Packet::BulkReceivingStatus { id, .. } => *id,
            Packet::Data(d) => d.id,
        }
    }

    /// Returns the endpoint address, if this packet type carries one.
    #[must_use]
    pub fn endpoint(&self) -> Option<Endpoint> {
        match self {
            Packet::StartIsoStream { endpoint, .. }
            | Packet::StopIsoStream { endpoint, .. }
            | Packet::IsoStreamStatus { endpoint, .. }
            | Packet::StartInterruptReceiving { endpoint, .. }
            | Packet::StopInterruptReceiving { endpoint, .. }
            | Packet::InterruptReceivingStatus { endpoint, .. }
            | Packet::StartBulkReceiving { endpoint, .. }
            | Packet::StopBulkReceiving { endpoint, .. }
            | Packet::BulkReceivingStatus { endpoint, .. } => Some(*endpoint),
            Packet::Data(d) => Some(d.endpoint),
            _ => None,
        }
    }

    /// Returns the status field, if this packet type carries one.
    #[must_use]
    pub fn status(&self) -> Option<Status> {
        match self {
            Packet::ConfigurationStatus { status, .. }
            | Packet::AltSettingStatus { status, .. }
            | Packet::IsoStreamStatus { status, .. }
            | Packet::InterruptReceivingStatus { status, .. }
            | Packet::BulkStreamsStatus { status, .. }
            | Packet::BulkReceivingStatus { status, .. } => Some(*status),
            Packet::Data(d) => Some(d.status),
            _ => None,
        }
    }

    /// Returns the data payload, if this is a data packet.
    #[must_use]
    pub fn data(&self) -> Option<&Bytes> {
        match self {
            Packet::Data(d) => Some(&d.data),
            _ => None,
        }
    }

    /// Returns a reference to the [`DataPacket`], if this is a data packet.
    #[must_use]
    pub fn as_data(&self) -> Option<&DataPacket> {
        match self {
            Packet::Data(d) => Some(d),
            _ => None,
        }
    }

    // -- Helper constructors --

    /// Create a Hello packet.
    #[must_use]
    pub fn hello(version: impl Into<String>, caps: Caps) -> Self {
        Self::Hello {
            version: version.into(),
            caps,
        }
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
            speed,
            device_class,
            device_subclass,
            device_protocol,
            vendor_id,
            product_id,
            device_version_bcd,
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
            interface_count,
            interface,
            interface_class,
            interface_subclass,
            interface_protocol,
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
        Self::EpInfo {
            ep_type,
            interval,
            interface,
            max_packet_size,
            max_streams,
        }
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
        Self::ConfigurationStatus {
            id,
            status,
            configuration,
        }
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
        Self::AltSettingStatus {
            id,
            status,
            interface,
            alt,
        }
    }

    /// Create a StartIsoStream packet.
    #[must_use]
    pub fn start_iso_stream(id: u64, endpoint: Endpoint, pkts_per_urb: u8, no_urbs: u8) -> Self {
        Self::StartIsoStream {
            id,
            endpoint,
            pkts_per_urb,
            no_urbs,
        }
    }

    /// Create a StopIsoStream packet.
    #[must_use]
    pub fn stop_iso_stream(id: u64, endpoint: Endpoint) -> Self {
        Self::StopIsoStream { id, endpoint }
    }

    /// Create an IsoStreamStatus packet.
    #[must_use]
    pub fn iso_stream_status(id: u64, status: Status, endpoint: Endpoint) -> Self {
        Self::IsoStreamStatus {
            id,
            status,
            endpoint,
        }
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
        Self::InterruptReceivingStatus {
            id,
            status,
            endpoint,
        }
    }

    /// Create an AllocBulkStreams packet.
    #[must_use]
    pub fn alloc_bulk_streams(id: u64, endpoints: u32, no_streams: u32) -> Self {
        Self::AllocBulkStreams {
            id,
            endpoints,
            no_streams,
        }
    }

    /// Create a FreeBulkStreams packet.
    #[must_use]
    pub fn free_bulk_streams(id: u64, endpoints: u32) -> Self {
        Self::FreeBulkStreams { id, endpoints }
    }

    /// Create a BulkStreamsStatus packet.
    #[must_use]
    pub fn bulk_streams_status(id: u64, endpoints: u32, no_streams: u32, status: Status) -> Self {
        Self::BulkStreamsStatus {
            id,
            endpoints,
            no_streams,
            status,
        }
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
        Self::StartBulkReceiving {
            id,
            stream_id,
            bytes_per_transfer,
            endpoint,
            no_transfers,
        }
    }

    /// Create a StopBulkReceiving packet.
    #[must_use]
    pub fn stop_bulk_receiving(id: u64, stream_id: u32, endpoint: Endpoint) -> Self {
        Self::StopBulkReceiving {
            id,
            stream_id,
            endpoint,
        }
    }

    /// Create a BulkReceivingStatus packet.
    #[must_use]
    pub fn bulk_receiving_status(
        id: u64,
        stream_id: u32,
        endpoint: Endpoint,
        status: Status,
    ) -> Self {
        Self::BulkReceivingStatus {
            id,
            stream_id,
            endpoint,
            status,
        }
    }

    /// Create a ControlPacket.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
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
        Self::Data(DataPacket::control(
            id,
            endpoint,
            request,
            requesttype,
            status,
            value,
            index,
            length,
            data,
        ))
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
        Self::Data(DataPacket::bulk(id, endpoint, status, length, stream_id, data))
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
        Self::Data(DataPacket::iso(id, endpoint, status, length, data))
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
        Self::Data(DataPacket::interrupt(id, endpoint, status, length, data))
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
        Self::Data(DataPacket::buffered_bulk(
            id, stream_id, length, endpoint, status, data,
        ))
    }
}
