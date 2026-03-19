pub const CAPS_SIZE: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Cap {
    BulkStreams = 0,
    ConnectDeviceVersion = 1,
    Filter = 2,
    DeviceDisconnectAck = 3,
    EpInfoMaxPacketSize = 4,
    Ids64Bits = 5,
    BulkLength32Bits = 6,
    BulkReceiving = 7,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    bits: [u32; CAPS_SIZE],
}

impl Caps {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, cap: Cap) {
        let idx = cap as u32;
        self.bits[(idx / 32) as usize] |= 1 << (idx % 32);
    }

    pub fn has(&self, cap: Cap) -> bool {
        let idx = cap as u32;
        (self.bits[(idx / 32) as usize] & (1 << (idx % 32))) != 0
    }

    pub fn negotiated(&self, peer: &Caps, cap: Cap) -> bool {
        self.has(cap) && peer.has(cap)
    }

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

    pub fn to_le_bytes(&self) -> [u8; CAPS_SIZE * 4] {
        let mut out = [0u8; CAPS_SIZE * 4];
        for (i, word) in self.bits.iter().enumerate() {
            let bytes = word.to_le_bytes();
            out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        out
    }

    pub fn raw_bits(&self) -> &[u32; CAPS_SIZE] {
        &self.bits
    }

    pub fn from_raw_bits(bits: [u32; CAPS_SIZE]) -> Self {
        Self { bits }
    }

    /// Verify caps consistency (bulk_streams requires ep_info_max_packet_size)
    pub fn verify(&mut self) {
        if self.has(Cap::BulkStreams) && !self.has(Cap::EpInfoMaxPacketSize) {
            let idx = Cap::BulkStreams as u32;
            self.bits[(idx / 32) as usize] &= !(1 << (idx % 32));
        }
    }

    /// Check if a subset of `other` caps (i.e., `self` has no caps that `other` doesn't)
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
    fn verify_strips_bulk_streams() {
        let mut caps = Caps::new();
        caps.set(Cap::BulkStreams);
        caps.verify();
        assert!(!caps.has(Cap::BulkStreams));
    }
}
