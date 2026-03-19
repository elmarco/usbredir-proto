use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// Main header (64-bit id)
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct Header {
    pub type_: U32,
    pub length: U32,
    pub id: U64,
}

// Legacy 32-bit id header
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct Header32 {
    pub type_: U32,
    pub length: U32,
    pub id: U32,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct HelloHeader {
    pub version: [u8; 64],
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct DeviceConnectHeader {
    pub speed: u8,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub vendor_id: U16,
    pub product_id: U16,
    pub device_version_bcd: U16,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct DeviceConnectHeaderNoVersion {
    pub speed: u8,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub vendor_id: U16,
    pub product_id: U16,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct InterfaceInfoHeader {
    pub interface_count: U32,
    pub interface: [u8; 32],
    pub interface_class: [u8; 32],
    pub interface_subclass: [u8; 32],
    pub interface_protocol: [u8; 32],
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct EpInfoHeader {
    pub ep_type: [u8; 32],
    pub interval: [u8; 32],
    pub interface: [u8; 32],
    pub max_packet_size: [U16; 32],
    pub max_streams: [U32; 32],
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct EpInfoHeaderNoMaxStreams {
    pub ep_type: [u8; 32],
    pub interval: [u8; 32],
    pub interface: [u8; 32],
    pub max_packet_size: [U16; 32],
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct EpInfoHeaderNoMaxPktsz {
    pub ep_type: [u8; 32],
    pub interval: [u8; 32],
    pub interface: [u8; 32],
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct SetConfigurationHeader {
    pub configuration: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct ConfigurationStatusHeader {
    pub status: u8,
    pub configuration: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct SetAltSettingHeader {
    pub interface: u8,
    pub alt: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct GetAltSettingHeader {
    pub interface: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct AltSettingStatusHeader {
    pub status: u8,
    pub interface: u8,
    pub alt: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct StartIsoStreamHeader {
    pub endpoint: u8,
    pub pkts_per_urb: u8,
    pub no_urbs: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct StopIsoStreamHeader {
    pub endpoint: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct IsoStreamStatusHeader {
    pub status: u8,
    pub endpoint: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct StartInterruptReceivingHeader {
    pub endpoint: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct StopInterruptReceivingHeader {
    pub endpoint: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct InterruptReceivingStatusHeader {
    pub status: u8,
    pub endpoint: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct AllocBulkStreamsHeader {
    pub endpoints: U32,
    pub no_streams: U32,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct FreeBulkStreamsHeader {
    pub endpoints: U32,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct BulkStreamsStatusHeader {
    pub endpoints: U32,
    pub no_streams: U32,
    pub status: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct StartBulkReceivingHeader {
    pub stream_id: U32,
    pub bytes_per_transfer: U32,
    pub endpoint: u8,
    pub no_transfers: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct StopBulkReceivingHeader {
    pub stream_id: U32,
    pub endpoint: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct BulkReceivingStatusHeader {
    pub stream_id: U32,
    pub endpoint: u8,
    pub status: u8,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct ControlPacketHeader {
    pub endpoint: u8,
    pub request: u8,
    pub requesttype: u8,
    pub status: u8,
    pub value: U16,
    pub index: U16,
    pub length: U16,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct BulkPacketHeader {
    pub endpoint: u8,
    pub status: u8,
    pub length: U16,
    pub stream_id: U32,
    pub length_high: U16,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct BulkPacketHeader16BitLength {
    pub endpoint: u8,
    pub status: u8,
    pub length: U16,
    pub stream_id: U32,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct IsoPacketHeader {
    pub endpoint: u8,
    pub status: u8,
    pub length: U16,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct InterruptPacketHeader {
    pub endpoint: u8,
    pub status: u8,
    pub length: U16,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct BufferedBulkPacketHeader {
    pub stream_id: U32,
    pub length: U32,
    pub endpoint: u8,
    pub status: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn struct_sizes() {
        assert_eq!(size_of::<Header>(), 16);
        assert_eq!(size_of::<Header32>(), 12);
        assert_eq!(size_of::<HelloHeader>(), 64);
        assert_eq!(size_of::<DeviceConnectHeader>(), 10);
        assert_eq!(size_of::<DeviceConnectHeaderNoVersion>(), 8);
        assert_eq!(size_of::<InterfaceInfoHeader>(), 132);
        assert_eq!(size_of::<EpInfoHeader>(), 32 + 32 + 32 + 64 + 128);
        assert_eq!(size_of::<EpInfoHeaderNoMaxStreams>(), 32 + 32 + 32 + 64);
        assert_eq!(size_of::<EpInfoHeaderNoMaxPktsz>(), 32 + 32 + 32);
        assert_eq!(size_of::<SetConfigurationHeader>(), 1);
        assert_eq!(size_of::<ConfigurationStatusHeader>(), 2);
        assert_eq!(size_of::<SetAltSettingHeader>(), 2);
        assert_eq!(size_of::<GetAltSettingHeader>(), 1);
        assert_eq!(size_of::<AltSettingStatusHeader>(), 3);
        assert_eq!(size_of::<StartIsoStreamHeader>(), 3);
        assert_eq!(size_of::<StopIsoStreamHeader>(), 1);
        assert_eq!(size_of::<IsoStreamStatusHeader>(), 2);
        assert_eq!(size_of::<StartInterruptReceivingHeader>(), 1);
        assert_eq!(size_of::<StopInterruptReceivingHeader>(), 1);
        assert_eq!(size_of::<InterruptReceivingStatusHeader>(), 2);
        assert_eq!(size_of::<AllocBulkStreamsHeader>(), 8);
        assert_eq!(size_of::<FreeBulkStreamsHeader>(), 4);
        assert_eq!(size_of::<BulkStreamsStatusHeader>(), 9);
        assert_eq!(size_of::<StartBulkReceivingHeader>(), 10);
        assert_eq!(size_of::<StopBulkReceivingHeader>(), 5);
        assert_eq!(size_of::<BulkReceivingStatusHeader>(), 6);
        assert_eq!(size_of::<ControlPacketHeader>(), 10);
        assert_eq!(size_of::<BulkPacketHeader>(), 10);
        assert_eq!(size_of::<BulkPacketHeader16BitLength>(), 8);
        assert_eq!(size_of::<IsoPacketHeader>(), 4);
        assert_eq!(size_of::<InterruptPacketHeader>(), 4);
        assert_eq!(size_of::<BufferedBulkPacketHeader>(), 10);
    }
}
