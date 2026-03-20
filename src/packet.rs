use alloc::string::String;
use alloc::vec::Vec;

use bytes::Bytes;

use crate::caps::Caps;
use crate::filter::FilterRule;
use crate::proto::{Endpoint, PktType, Speed, Status, TransferType};

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
    /// Returns the wire packet type for this data kind.
    #[must_use]
    pub fn packet_type(&self) -> PktType {
        match self {
            DataKind::Control { .. } => PktType::ControlPacket,
            DataKind::Bulk { .. } => PktType::BulkPacket,
            DataKind::Iso { .. } => PktType::IsoPacket,
            DataKind::Interrupt { .. } => PktType::InterruptPacket,
            DataKind::BufferedBulk { .. } => PktType::BufferedBulkPacket,
        }
    }

    /// Returns the `length` field from the type-specific header.
    ///
    /// This is the transfer length declared in the wire header, not the
    /// length of the `data` payload (which may differ, e.g. for requests
    /// where data hasn't arrived yet).
    #[must_use]
    pub fn transfer_length(&self) -> u32 {
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



/// The type-specific part of a request/response packet.
///
/// Request packets always carry a correlation `id` (stored in [`RequestPacket`])
/// but no variable-length data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestKind {
    /// Guest → host: reset the USB device.
    Reset,
    /// Guest → host: select a USB configuration.
    SetConfiguration { configuration: u8 },
    /// Guest → host: query the current USB configuration.
    GetConfiguration,
    /// Host → guest: response to `SetConfiguration` or `GetConfiguration`.
    ConfigurationStatus {
        status: Status,
        configuration: u8,
    },
    /// Guest → host: select an alternate setting for an interface.
    SetAltSetting { interface: u8, alt: u8 },
    /// Guest → host: query the current alternate setting for an interface.
    GetAltSetting { interface: u8 },
    /// Host → guest: response to `SetAltSetting` or `GetAltSetting`.
    AltSettingStatus {
        status: Status,
        interface: u8,
        alt: u8,
    },
    /// Guest → host: start an isochronous stream on the given endpoint.
    ///
    /// `pkts_per_urb` and `no_urbs` control host-side buffering (URB =
    /// USB Request Block, the kernel's unit of USB I/O).
    StartIsoStream {
        endpoint: Endpoint,
        pkts_per_urb: u8,
        no_urbs: u8,
    },
    /// Guest → host: stop an isochronous stream.
    StopIsoStream { endpoint: Endpoint },
    /// Host → guest: response to `StartIsoStream` or `StopIsoStream`.
    IsoStreamStatus {
        status: Status,
        endpoint: Endpoint,
    },
    /// Guest → host: start forwarding interrupt IN transfers from this endpoint.
    StartInterruptReceiving { endpoint: Endpoint },
    /// Guest → host: stop forwarding interrupt IN transfers.
    StopInterruptReceiving { endpoint: Endpoint },
    /// Host → guest: response to `StartInterruptReceiving` / `StopInterruptReceiving`.
    InterruptReceivingStatus {
        status: Status,
        endpoint: Endpoint,
    },
    /// Guest → host: allocate USB 3.0 bulk streams on a set of endpoints.
    /// `endpoints` is a bitmask. Requires [`Cap::BulkStreams`](crate::Cap::BulkStreams).
    AllocBulkStreams {
        endpoints: u32,
        no_streams: u32,
    },
    /// Guest → host: free previously allocated bulk streams.
    FreeBulkStreams { endpoints: u32 },
    /// Host → guest: response to `AllocBulkStreams` / `FreeBulkStreams`.
    BulkStreamsStatus {
        endpoints: u32,
        no_streams: u32,
        status: Status,
    },
    /// Guest → host: cancel a pending data transfer.
    CancelDataPacket,
    /// Guest → host: start host-buffered bulk IN receiving. Requires [`Cap::BulkReceiving`](crate::Cap::BulkReceiving).
    StartBulkReceiving {
        stream_id: u32,
        bytes_per_transfer: u32,
        endpoint: Endpoint,
        no_transfers: u8,
    },
    /// Guest → host: stop host-buffered bulk IN receiving.
    StopBulkReceiving {
        stream_id: u32,
        endpoint: Endpoint,
    },
    /// Host → guest: response to `StartBulkReceiving` / `StopBulkReceiving`.
    BulkReceivingStatus {
        stream_id: u32,
        endpoint: Endpoint,
        status: Status,
    },
}

impl RequestKind {
    /// Returns the wire packet type for this request kind.
    #[must_use]
    pub fn packet_type(&self) -> PktType {
        match self {
            RequestKind::Reset => PktType::Reset,
            RequestKind::SetConfiguration { .. } => PktType::SetConfiguration,
            RequestKind::GetConfiguration => PktType::GetConfiguration,
            RequestKind::ConfigurationStatus { .. } => PktType::ConfigurationStatus,
            RequestKind::SetAltSetting { .. } => PktType::SetAltSetting,
            RequestKind::GetAltSetting { .. } => PktType::GetAltSetting,
            RequestKind::AltSettingStatus { .. } => PktType::AltSettingStatus,
            RequestKind::StartIsoStream { .. } => PktType::StartIsoStream,
            RequestKind::StopIsoStream { .. } => PktType::StopIsoStream,
            RequestKind::IsoStreamStatus { .. } => PktType::IsoStreamStatus,
            RequestKind::StartInterruptReceiving { .. } => PktType::StartInterruptReceiving,
            RequestKind::StopInterruptReceiving { .. } => PktType::StopInterruptReceiving,
            RequestKind::InterruptReceivingStatus { .. } => PktType::InterruptReceivingStatus,
            RequestKind::AllocBulkStreams { .. } => PktType::AllocBulkStreams,
            RequestKind::FreeBulkStreams { .. } => PktType::FreeBulkStreams,
            RequestKind::BulkStreamsStatus { .. } => PktType::BulkStreamsStatus,
            RequestKind::CancelDataPacket => PktType::CancelDataPacket,
            RequestKind::StartBulkReceiving { .. } => PktType::StartBulkReceiving,
            RequestKind::StopBulkReceiving { .. } => PktType::StopBulkReceiving,
            RequestKind::BulkReceivingStatus { .. } => PktType::BulkReceivingStatus,
        }
    }

    /// Returns the endpoint address, if this request kind carries one.
    #[must_use]
    pub fn endpoint(&self) -> Option<Endpoint> {
        match self {
            RequestKind::StartIsoStream { endpoint, .. }
            | RequestKind::StopIsoStream { endpoint, .. }
            | RequestKind::IsoStreamStatus { endpoint, .. }
            | RequestKind::StartInterruptReceiving { endpoint, .. }
            | RequestKind::StopInterruptReceiving { endpoint, .. }
            | RequestKind::InterruptReceivingStatus { endpoint, .. }
            | RequestKind::StartBulkReceiving { endpoint, .. }
            | RequestKind::StopBulkReceiving { endpoint, .. }
            | RequestKind::BulkReceivingStatus { endpoint, .. } => Some(*endpoint),
            _ => None,
        }
    }

    /// Returns the status field, if this request kind carries one.
    #[must_use]
    pub fn status(&self) -> Option<Status> {
        match self {
            RequestKind::ConfigurationStatus { status, .. }
            | RequestKind::AltSettingStatus { status, .. }
            | RequestKind::IsoStreamStatus { status, .. }
            | RequestKind::InterruptReceivingStatus { status, .. }
            | RequestKind::BulkStreamsStatus { status, .. }
            | RequestKind::BulkReceivingStatus { status, .. } => Some(*status),
            _ => None,
        }
    }
}

impl core::fmt::Display for RequestKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RequestKind::Reset => write!(f, "Reset"),
            RequestKind::SetConfiguration { configuration } => {
                write!(f, "SetConfiguration(config={configuration})")
            }
            RequestKind::GetConfiguration => write!(f, "GetConfiguration"),
            RequestKind::ConfigurationStatus {
                status,
                configuration,
            } => {
                write!(
                    f,
                    "ConfigurationStatus(status={status:?}, config={configuration})"
                )
            }
            RequestKind::SetAltSetting { interface, alt } => {
                write!(f, "SetAltSetting(iface={interface}, alt={alt})")
            }
            RequestKind::GetAltSetting { interface } => {
                write!(f, "GetAltSetting(iface={interface})")
            }
            RequestKind::AltSettingStatus {
                status,
                interface,
                alt,
            } => {
                write!(
                    f,
                    "AltSettingStatus(status={status:?}, iface={interface}, alt={alt})"
                )
            }
            RequestKind::StartIsoStream { endpoint, .. } => {
                write!(f, "StartIsoStream({endpoint})")
            }
            RequestKind::StopIsoStream { endpoint } => {
                write!(f, "StopIsoStream({endpoint})")
            }
            RequestKind::IsoStreamStatus { status, endpoint } => {
                write!(f, "IsoStreamStatus(status={status:?}, {endpoint})")
            }
            RequestKind::StartInterruptReceiving { endpoint } => {
                write!(f, "StartInterruptReceiving({endpoint})")
            }
            RequestKind::StopInterruptReceiving { endpoint } => {
                write!(f, "StopInterruptReceiving({endpoint})")
            }
            RequestKind::InterruptReceivingStatus { status, endpoint } => {
                write!(
                    f,
                    "InterruptReceivingStatus(status={status:?}, {endpoint})"
                )
            }
            RequestKind::AllocBulkStreams {
                endpoints,
                no_streams,
            } => {
                write!(
                    f,
                    "AllocBulkStreams(eps={endpoints:#x}, streams={no_streams})"
                )
            }
            RequestKind::FreeBulkStreams { endpoints } => {
                write!(f, "FreeBulkStreams(eps={endpoints:#x})")
            }
            RequestKind::BulkStreamsStatus {
                status,
                endpoints,
                no_streams,
            } => {
                write!(f, "BulkStreamsStatus(status={status:?}, eps={endpoints:#x}, streams={no_streams})")
            }
            RequestKind::CancelDataPacket => write!(f, "CancelDataPacket"),
            RequestKind::StartBulkReceiving {
                endpoint,
                stream_id,
                ..
            } => {
                write!(
                    f,
                    "StartBulkReceiving({endpoint}, stream={stream_id})"
                )
            }
            RequestKind::StopBulkReceiving {
                endpoint,
                stream_id,
            } => {
                write!(
                    f,
                    "StopBulkReceiving({endpoint}, stream={stream_id})"
                )
            }
            RequestKind::BulkReceivingStatus {
                status,
                endpoint,
                stream_id,
            } => {
                write!(f, "BulkReceivingStatus(status={status:?}, {endpoint}, stream={stream_id})")
            }
        }
    }
}

/// A request/response packet with a correlation ID.
///
/// All request packets carry an `id` chosen by the requester so that
/// responses can be matched to requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPacket {
    /// Correlation identifier chosen by the requester.
    pub id: u64,
    /// Type-specific request fields.
    pub kind: RequestKind,
}

impl core::fmt::Display for RequestPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}(id={})", self.kind, self.id)
    }
}

/// Information about a connected USB device, sent in a [`DeviceConnect`](Packet::DeviceConnect) packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConnectInfo {
    /// USB device speed class.
    pub speed: Speed,
    /// USB device class code ([class codes](https://www.usb.org/defined-class-codes)).
    pub device_class: u8,
    /// USB device subclass code.
    pub device_subclass: u8,
    /// USB device protocol code.
    pub device_protocol: u8,
    /// USB vendor ID (idVendor).
    pub vendor_id: u16,
    /// USB product ID (idProduct).
    pub product_id: u16,
    /// BCD-encoded device release number (bcdDevice).
    /// Requires [`Cap::ConnectDeviceVersion`](crate::Cap::ConnectDeviceVersion).
    pub device_version_bcd: u16,
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
/// | **Request/response** | Yes | No | [`Request`](Self::Request) ([`RequestKind::SetConfiguration`], etc.) |
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
    DeviceConnect(DeviceConnectInfo),
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
    /// A request or response packet with a correlation ID. See [`RequestKind`]
    /// for the specific packet types.
    Request(RequestPacket),

    // ── Data packets (id + header fields + payload) ─────────────────────
    /// A USB data transfer packet (control, bulk, isochronous, interrupt,
    /// or buffered bulk). See [`DataPacket`] and [`DataKind`] for details.
    Data(DataPacket),
}

impl core::fmt::Display for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Packet::Hello { version, .. } => write!(f, "Hello(version={version:?})"),
            Packet::DeviceConnect(info) => {
                write!(
                    f,
                    "DeviceConnect(speed={:?}, vid={:#06x}, pid={:#06x})",
                    info.speed, info.vendor_id, info.product_id
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
            Packet::Request(req) => req.fmt(f),
            Packet::Data(d) => d.fmt(f),
        }
    }
}

impl Packet {
    /// Returns the wire packet type for this variant.
    #[must_use]
    pub fn packet_type(&self) -> PktType {
        match self {
            Packet::Hello { .. } => PktType::Hello,
            Packet::DeviceConnect(_) => PktType::DeviceConnect,
            Packet::DeviceDisconnect => PktType::DeviceDisconnect,
            Packet::InterfaceInfo { .. } => PktType::InterfaceInfo,
            Packet::EpInfo { .. } => PktType::EpInfo,
            Packet::FilterReject => PktType::FilterReject,
            Packet::FilterFilter { .. } => PktType::FilterFilter,
            Packet::DeviceDisconnectAck => PktType::DeviceDisconnectAck,
            Packet::Request(req) => req.kind.packet_type(),
            Packet::Data(d) => d.kind.packet_type(),
        }
    }

    /// Returns the packet's correlation ID, or `None` for connection-wide
    /// packets that don't carry one (`Hello`, `DeviceConnect`,
    /// `DeviceDisconnect`, `InterfaceInfo`, `EpInfo`, `FilterReject`,
    /// `FilterFilter`, `DeviceDisconnectAck`).
    #[must_use]
    pub fn id(&self) -> Option<u64> {
        match self {
            Packet::Hello { .. }
            | Packet::DeviceConnect(_)
            | Packet::DeviceDisconnect
            | Packet::InterfaceInfo { .. }
            | Packet::EpInfo { .. }
            | Packet::FilterReject
            | Packet::FilterFilter { .. }
            | Packet::DeviceDisconnectAck => None,
            Packet::Request(req) => Some(req.id),
            Packet::Data(d) => Some(d.id),
        }
    }

    /// Returns the endpoint address, if this packet type carries one.
    #[must_use]
    pub fn endpoint(&self) -> Option<Endpoint> {
        match self {
            Packet::Request(req) => req.kind.endpoint(),
            Packet::Data(d) => Some(d.endpoint),
            _ => None,
        }
    }

    /// Returns the status field, if this packet type carries one.
    #[must_use]
    pub fn status(&self) -> Option<Status> {
        match self {
            Packet::Request(req) => req.kind.status(),
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

    /// Returns a reference to the [`RequestPacket`], if this is a request packet.
    #[must_use]
    pub fn as_request(&self) -> Option<&RequestPacket> {
        match self {
            Packet::Request(req) => Some(req),
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
    pub fn device_connect(info: DeviceConnectInfo) -> Self {
        Self::DeviceConnect(info)
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
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::Reset,
        })
    }

    /// Create a SetConfiguration packet.
    #[must_use]
    pub fn set_configuration(id: u64, configuration: u8) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::SetConfiguration { configuration },
        })
    }

    /// Create a GetConfiguration packet.
    #[must_use]
    pub fn get_configuration(id: u64) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::GetConfiguration,
        })
    }

    /// Create a ConfigurationStatus packet.
    #[must_use]
    pub fn configuration_status(id: u64, status: Status, configuration: u8) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::ConfigurationStatus {
                status,
                configuration,
            },
        })
    }

    /// Create a SetAltSetting packet.
    #[must_use]
    pub fn set_alt_setting(id: u64, interface: u8, alt: u8) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::SetAltSetting { interface, alt },
        })
    }

    /// Create a GetAltSetting packet.
    #[must_use]
    pub fn get_alt_setting(id: u64, interface: u8) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::GetAltSetting { interface },
        })
    }

    /// Create an AltSettingStatus packet.
    #[must_use]
    pub fn alt_setting_status(id: u64, status: Status, interface: u8, alt: u8) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::AltSettingStatus {
                status,
                interface,
                alt,
            },
        })
    }

    /// Create a StartIsoStream packet.
    #[must_use]
    pub fn start_iso_stream(id: u64, endpoint: Endpoint, pkts_per_urb: u8, no_urbs: u8) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::StartIsoStream {
                endpoint,
                pkts_per_urb,
                no_urbs,
            },
        })
    }

    /// Create a StopIsoStream packet.
    #[must_use]
    pub fn stop_iso_stream(id: u64, endpoint: Endpoint) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::StopIsoStream { endpoint },
        })
    }

    /// Create an IsoStreamStatus packet.
    #[must_use]
    pub fn iso_stream_status(id: u64, status: Status, endpoint: Endpoint) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::IsoStreamStatus { status, endpoint },
        })
    }

    /// Create a StartInterruptReceiving packet.
    #[must_use]
    pub fn start_interrupt_receiving(id: u64, endpoint: Endpoint) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::StartInterruptReceiving { endpoint },
        })
    }

    /// Create a StopInterruptReceiving packet.
    #[must_use]
    pub fn stop_interrupt_receiving(id: u64, endpoint: Endpoint) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::StopInterruptReceiving { endpoint },
        })
    }

    /// Create an InterruptReceivingStatus packet.
    #[must_use]
    pub fn interrupt_receiving_status(id: u64, status: Status, endpoint: Endpoint) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::InterruptReceivingStatus { status, endpoint },
        })
    }

    /// Create an AllocBulkStreams packet.
    #[must_use]
    pub fn alloc_bulk_streams(id: u64, endpoints: u32, no_streams: u32) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::AllocBulkStreams {
                endpoints,
                no_streams,
            },
        })
    }

    /// Create a FreeBulkStreams packet.
    #[must_use]
    pub fn free_bulk_streams(id: u64, endpoints: u32) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::FreeBulkStreams { endpoints },
        })
    }

    /// Create a BulkStreamsStatus packet.
    #[must_use]
    pub fn bulk_streams_status(id: u64, endpoints: u32, no_streams: u32, status: Status) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::BulkStreamsStatus {
                endpoints,
                no_streams,
                status,
            },
        })
    }

    /// Create a CancelDataPacket packet.
    #[must_use]
    pub fn cancel_data_packet(id: u64) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::CancelDataPacket,
        })
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
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::StartBulkReceiving {
                stream_id,
                bytes_per_transfer,
                endpoint,
                no_transfers,
            },
        })
    }

    /// Create a StopBulkReceiving packet.
    #[must_use]
    pub fn stop_bulk_receiving(id: u64, stream_id: u32, endpoint: Endpoint) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::StopBulkReceiving {
                stream_id,
                endpoint,
            },
        })
    }

    /// Create a BulkReceivingStatus packet.
    #[must_use]
    pub fn bulk_receiving_status(
        id: u64,
        stream_id: u32,
        endpoint: Endpoint,
        status: Status,
    ) -> Self {
        Self::Request(RequestPacket {
            id,
            kind: RequestKind::BulkReceivingStatus {
                stream_id,
                endpoint,
                status,
            },
        })
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
        Self::Data(DataPacket {
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
        })
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
        Self::Data(DataPacket {
            id,
            endpoint,
            status,
            kind: DataKind::Bulk { length, stream_id },
            data: data.into(),
        })
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
        Self::Data(DataPacket {
            id,
            endpoint,
            status,
            kind: DataKind::Iso { length },
            data: data.into(),
        })
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
        Self::Data(DataPacket {
            id,
            endpoint,
            status,
            kind: DataKind::Interrupt { length },
            data: data.into(),
        })
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
        Self::Data(DataPacket {
            id,
            endpoint,
            status,
            kind: DataKind::BufferedBulk { stream_id, length },
            data: data.into(),
        })
    }
}
