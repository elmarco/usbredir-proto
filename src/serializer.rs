//! C-compatible serialization/unserialization (magic 0x55525031 "URP1")
//!
//! Format:
//!   u32 MAGIC (0x55525031)
//!   u32 total_length
//!   u32 our_caps_len + our_caps bytes
//!   u32 peer_caps_len + peer_caps bytes
//!   u32 to_skip
//!   u32 header_read_len + header bytes
//!   u32 type_header_read_len + type_header bytes
//!   u32 data_read_len + data bytes
//!   u32 write_buf_count
//!     (for each write buf: u32 len + bytes)

use alloc::format;
use alloc::vec::Vec;

use bytes::Bytes;

use crate::caps::Caps;
use crate::error::{Error, Result};
use crate::parser::{Parser, ParserConfig};

const SERIALIZE_MAGIC: u32 = 0x55525031;

impl Parser {
    /// Serialize the parser state to a byte buffer (C-compatible format, magic `0x55525031`).
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();

        // Magic
        write_u32(&mut out, SERIALIZE_MAGIC);
        // Placeholder for length
        let len_pos = out.len();
        write_u32(&mut out, 0);

        // our_caps
        let caps_bytes = self.our_caps().to_le_bytes();
        write_data(&mut out, &caps_bytes);

        // peer_caps
        if let Some(peer) = self.peer_caps() {
            let peer_bytes = peer.to_le_bytes();
            write_data(&mut out, &peer_bytes);
        } else {
            write_u32(&mut out, 0); // peer_caps_len = 0
        }

        // to_skip
        write_u32(&mut out, self.to_skip() as u32);

        // Partial parse state: the C format stores partially-read header/type_header/data
        // separately. In our parser, after the header phase completes the header bytes have
        // been consumed from `input` and the parsed fields are stored in ParseState::Body.
        // If we're in Body phase, we must reconstruct the header bytes so that the
        // unserialized parser (or C) can re-parse from the beginning of the packet.
        if let crate::parser::ParseState::Body {
            pkt_type,
            pkt_length,
            pkt_id,
            ..
        } = *self.parse_state()
        {
            // Reconstruct the consumed header so the deserializer sees the full packet
            let mut hdr_bytes = Vec::new();
            if self.is_using_32bit_ids() {
                let hdr = crate::wire::Header32 {
                    type_: pkt_type.into(),
                    length: pkt_length.into(),
                    id: (pkt_id as u32).into(),
                };
                hdr_bytes.extend_from_slice(zerocopy::IntoBytes::as_bytes(&hdr));
            } else {
                let hdr = crate::wire::Header {
                    type_: pkt_type.into(),
                    length: pkt_length.into(),
                    id: pkt_id.into(),
                };
                hdr_bytes.extend_from_slice(zerocopy::IntoBytes::as_bytes(&hdr));
            }
            write_data(&mut out, &hdr_bytes); // header
        } else {
            write_data(&mut out, &[]); // header (0 bytes — still in header phase)
        }
        write_data(&mut out, &[]); // type_header (0 bytes)
        write_data(&mut out, &[]); // data (0 bytes)

        // write_buf_count
        let bufs = self.output_bufs();
        write_u32(&mut out, bufs.len() as u32);
        for buf in bufs {
            write_data(&mut out, buf);
        }

        // Patch length
        let total_len = out.len() as u32;
        out[len_pos..len_pos + 4].copy_from_slice(&total_len.to_le_bytes());

        Ok(out)
    }

    /// Restore a parser from serialized state. The `config` must have at least
    /// the same capabilities as the original parser.
    pub fn unserialize(config: ParserConfig, data: &[u8]) -> Result<Self> {
        let mut pos = 0;

        let magic = read_u32(data, &mut pos)?;
        if magic != SERIALIZE_MAGIC {
            return Err(Error::Deserialize("magic mismatch".into()));
        }

        let total_len = read_u32(data, &mut pos)?;
        if total_len as usize != data.len() {
            return Err(Error::Deserialize("length mismatch".into()));
        }

        // our_caps
        let our_caps_data = read_data(data, &mut pos)?;
        let our_caps = Caps::from_le_bytes(our_caps_data);

        // Verify our_caps is a subset of config.caps
        if !our_caps.is_subset_of(&config.caps) {
            return Err(Error::Deserialize(
                "caps mismatch: source has caps we don't".into(),
            ));
        }

        // peer_caps
        let peer_caps_data = read_data(data, &mut pos)?;
        let peer_caps = if !peer_caps_data.is_empty() {
            Some(Caps::from_le_bytes(peer_caps_data))
        } else {
            None
        };

        // to_skip
        let to_skip = read_u32(data, &mut pos)? as usize;

        // header (partial parse state — we feed it back into input)
        let header_data = read_data(data, &mut pos)?;
        // type_header
        let type_header_data = read_data(data, &mut pos)?;
        // packet data
        let pkt_data = read_data(data, &mut pos)?;

        // write_buf_count
        let write_buf_count = read_u32(data, &mut pos)?;

        // Create parser with no_hello (we're restoring state)
        let mut restored_config = config;
        restored_config.no_hello = true;
        // Override caps with the serialized ones
        restored_config.caps = our_caps;
        let mut parser = Parser::new(restored_config);

        if let Some(pc) = peer_caps {
            parser.set_peer_caps(pc);
        }
        parser.set_to_skip(to_skip);

        // Restore partial parse input
        if !header_data.is_empty() {
            parser.restore_input(header_data);
        }
        if !type_header_data.is_empty() {
            parser.restore_input(type_header_data);
        }
        if !pkt_data.is_empty() {
            parser.restore_input(pkt_data);
        }

        // Restore write buffers
        for _ in 0..write_buf_count {
            let buf_data = read_data(data, &mut pos)?;
            if buf_data.is_empty() {
                return Err(Error::Deserialize("empty write buffer".into()));
            }
            parser.restore_output(Bytes::copy_from_slice(buf_data));
        }

        if pos != data.len() {
            return Err(Error::Deserialize(format!(
                "extraneous data: {} bytes remaining",
                data.len() - pos
            )));
        }

        Ok(parser)
    }
}

fn write_u32(out: &mut Vec<u8>, val: u32) {
    out.extend_from_slice(&val.to_le_bytes());
}

fn write_data(out: &mut Vec<u8>, data: &[u8]) {
    write_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > data.len() {
        return Err(Error::Deserialize("buffer underrun reading u32".into()));
    }
    let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

fn read_data<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = read_u32(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(Error::Deserialize("buffer underrun reading data".into()));
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::{Cap, Caps};

    fn make_config() -> ParserConfig {
        let mut caps = Caps::new();
        caps.set(Cap::ConnectDeviceVersion);
        caps.set(Cap::Filter);
        caps.set(Cap::DeviceDisconnectAck);
        caps.set(Cap::EpInfoMaxPacketSize);
        caps.set(Cap::Ids64Bits);
        caps.set(Cap::BulkLength32Bits);
        caps.set(Cap::BulkReceiving);
        ParserConfig {
            version: "test".to_string(),
            caps,
            is_host: true,
            no_hello: false,
        }
    }

    #[test]
    fn serialize_roundtrip() {
        let parser = Parser::new(make_config());
        let data = parser.serialize().unwrap();

        // Check magic
        assert_eq!(
            u32::from_le_bytes(data[0..4].try_into().unwrap()),
            0x55525031
        );

        let restored = Parser::unserialize(make_config(), &data).unwrap();
        assert_eq!(restored.our_caps(), parser.our_caps());
    }

    #[test]
    fn unserialize_bad_magic() {
        let mut data = vec![0u8; 12];
        // wrong magic
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data[4..8].copy_from_slice(&12u32.to_le_bytes());
        assert!(Parser::unserialize(make_config(), &data).is_err());
    }
}
