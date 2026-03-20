/// Number of u32 words in the capabilities bitset.
pub const CAPS_SIZE: usize = 1;

/// Individual protocol capability flags, negotiated via the Hello exchange.
///
/// A capability is only *active* when both the host and guest advertise it.
/// Some capabilities change the wire format of certain packets (e.g. header
/// size, field widths), so both sides must agree before using the extended
/// encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Cap {
    /// USB 3.0 bulk streams support. Adds `max_streams` to `EpInfo`.
    /// Requires [`EpInfoMaxPacketSize`](Self::EpInfoMaxPacketSize).
    BulkStreams = 0,
    /// Include `device_version_bcd` in `DeviceConnect` packets.
    ConnectDeviceVersion = 1,
    /// Enable `FilterFilter` and `FilterReject` packets for device filtering.
    Filter = 2,
    /// Guest acknowledges device disconnection with `DeviceDisconnectAck`.
    DeviceDisconnectAck = 3,
    /// Include `max_packet_size` in `EpInfo` packets.
    EpInfoMaxPacketSize = 4,
    /// Use 64-bit packet IDs (16-byte header) instead of 32-bit (12-byte header).
    Ids64Bits = 5,
    /// Use 32-bit bulk transfer lengths instead of 16-bit. Allows transfers > 64 KiB.
    BulkLength32Bits = 6,
    /// Enable `StartBulkReceiving` / `BufferedBulkPacket` for host-buffered bulk IN transfers.
    BulkReceiving = 7,
}

/// Bitset of protocol capabilities, exchanged during the Hello handshake.
///
/// Both sides advertise their caps; a capability is "negotiated" (active)
/// only when both peers have it set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    bits: [u32; CAPS_SIZE],
}

impl Caps {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable a capability, returning `self` for chaining.
    ///
    /// Setting [`Cap::BulkStreams`] automatically enables
    /// [`Cap::EpInfoMaxPacketSize`], which is a prerequisite.
    #[must_use]
    pub fn with(mut self, cap: Cap) -> Self {
        self.set(cap);
        self
    }

    /// Enable a capability.
    ///
    /// Setting [`Cap::BulkStreams`] automatically enables
    /// [`Cap::EpInfoMaxPacketSize`], which is a prerequisite.
    pub fn set(&mut self, cap: Cap) {
        let idx = cap as u32;
        self.bits[(idx / 32) as usize] |= 1 << (idx % 32);
        if matches!(cap, Cap::BulkStreams) {
            self.set(Cap::EpInfoMaxPacketSize);
        }
    }

    #[must_use]
    pub fn has(&self, cap: Cap) -> bool {
        let idx = cap as u32;
        (self.bits[(idx / 32) as usize] & (1 << (idx % 32))) != 0
    }

    #[must_use]
    pub fn negotiated(&self, peer: &Caps, cap: Cap) -> bool {
        self.has(cap) && peer.has(cap)
    }

    /// Decode capabilities from little-endian wire bytes.
    ///
    /// Unknown/unrecognized bits are silently preserved for forward compatibility
    /// — a newer peer may advertise capabilities this version doesn't know about.
    /// They are stored in the bitset and will be included when re-serialized, but
    /// `negotiated()` will never activate them since our side won't set them.
    #[must_use]
    pub fn from_le_bytes(data: &[u8]) -> Self {
        let mut caps = Self::default();
        let len = data.len().min(CAPS_SIZE * 4);
        let words = len / 4;
        for i in 0..words {
            caps.bits[i] = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
        }
        caps
    }

    #[must_use]
    pub fn to_le_bytes(&self) -> [u8; CAPS_SIZE * 4] {
        let mut out = [0u8; CAPS_SIZE * 4];
        for (i, word) in self.bits.iter().enumerate() {
            let bytes = word.to_le_bytes();
            out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        out
    }

    #[must_use]
    pub fn raw_bits(&self) -> &[u32; CAPS_SIZE] {
        &self.bits
    }

    #[must_use]
    pub fn from_raw_bits(bits: [u32; CAPS_SIZE]) -> Self {
        Self { bits }
    }

    /// Return a copy with inconsistent caps fixed.
    ///
    /// Currently strips [`Cap::BulkStreams`] when
    /// [`Cap::EpInfoMaxPacketSize`] is absent (the former requires the latter).
    /// This is mainly useful when receiving peer caps from the wire, where the
    /// invariant enforced by [`set()`](Self::set) may not hold.
    #[must_use]
    pub fn verified(mut self) -> Self {
        if self.has(Cap::BulkStreams) && !self.has(Cap::EpInfoMaxPacketSize) {
            let idx = Cap::BulkStreams as u32;
            self.bits[(idx / 32) as usize] &= !(1 << (idx % 32));
        }
        self
    }

    /// Check if a subset of `other` caps (i.e., `self` has no caps that `other` doesn't)
    #[must_use]
    pub fn is_subset_of(&self, other: &Caps) -> bool {
        for i in 0..CAPS_SIZE {
            if self.bits[i] & !other.bits[i] != 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get() {
        let mut caps = Caps::new();
        assert!(!caps.has(Cap::Filter));
        caps.set(Cap::Filter);
        assert!(caps.has(Cap::Filter));
        assert!(!caps.has(Cap::BulkStreams));
    }

    #[test]
    fn negotiated() {
        let mut ours = Caps::new();
        let mut peer = Caps::new();
        ours.set(Cap::Ids64Bits);
        assert!(!ours.negotiated(&peer, Cap::Ids64Bits));
        peer.set(Cap::Ids64Bits);
        assert!(ours.negotiated(&peer, Cap::Ids64Bits));
    }

    #[test]
    fn roundtrip_bytes() {
        let mut caps = Caps::new();
        caps.set(Cap::Filter);
        caps.set(Cap::Ids64Bits);
        let bytes = caps.to_le_bytes();
        let caps2 = Caps::from_le_bytes(&bytes);
        assert_eq!(caps, caps2);
    }

    #[test]
    fn set_bulk_streams_auto_sets_ep_info_max_packet_size() {
        let caps = Caps::new().with(Cap::BulkStreams);
        assert!(caps.has(Cap::EpInfoMaxPacketSize));
    }

    #[test]
    fn verified_strips_bulk_streams_without_ep_info() {
        // Simulate receiving inconsistent caps from the wire
        let caps = Caps::from_raw_bits([1 << Cap::BulkStreams as u32]);
        assert!(caps.has(Cap::BulkStreams));
        assert!(!caps.has(Cap::EpInfoMaxPacketSize));
        let caps = caps.verified();
        assert!(!caps.has(Cap::BulkStreams));
    }
}
