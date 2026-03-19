use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};
use zerocopy::FromBytes;

use crate::caps::{Cap, Caps};
use crate::error::{Error, Result};
use crate::filter;
use crate::packet::Packet;
use crate::proto::pkt_type;
use crate::proto::{Speed, Status, TransferType, MAX_PACKET_SIZE};
use crate::wire;

/// Configuration for constructing a [`Parser`].
///
/// Use struct literal syntax or the builder methods:
/// ```
/// # use usbredir_proto::{ParserConfig, Caps, Cap};
/// let config = ParserConfig::new("my-app 1.0")
///     .is_host(true)
///     .cap(Cap::Ids64Bits);
/// ```
#[derive(Debug, Clone)]
pub struct ParserConfig {
    /// Version string sent in the Hello packet.
    pub version: String,
    /// Our advertised capabilities.
    pub caps: Caps,
    /// Whether this parser represents the USB host side.
    pub is_host: bool,
    /// If true, suppress the automatic Hello packet on construction.
    pub no_hello: bool,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            version: String::new(),
            caps: Caps::new(),
            is_host: false,
            no_hello: false,
        }
    }
}

impl ParserConfig {
    /// Create a config with the given version string and defaults
    /// (guest side, all caps disabled, hello enabled).
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            ..Self::default()
        }
    }

    /// Set whether this is the USB host side.
    #[must_use]
    pub fn is_host(mut self, is_host: bool) -> Self {
        self.is_host = is_host;
        self
    }

    /// Enable a capability.
    #[must_use]
    pub fn cap(mut self, cap: Cap) -> Self {
        self.caps.set(cap);
        self
    }

    /// Set the full capabilities bitset.
    #[must_use]
    pub fn caps(mut self, caps: Caps) -> Self {
        self.caps = caps;
        self
    }

    /// Suppress the automatic Hello packet on construction.
    #[must_use]
    pub fn no_hello(mut self, no_hello: bool) -> Self {
        self.no_hello = no_hello;
        self
    }
}

/// Severity level for log messages emitted by the parser.
#[derive(Debug)]
#[non_exhaustive]
pub enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
}

/// An event produced by [`Parser::poll()`] or [`Parser::events()`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    Packet(Packet),
    ParseError(Error),
    Log { level: LogLevel, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParsePhase {
    Header,
    Body,
}

/// Sans-IO usbredir protocol parser and encoder.
///
/// Feed raw bytes with [`feed()`](Self::feed), then pull decoded packets
/// with [`poll()`](Self::poll) or [`events()`](Self::events).
/// Encode outgoing packets with [`send()`](Self::send), then pull the
/// wire bytes with [`drain()`](Self::drain) or [`drain_output()`](Self::drain_output).
pub struct Parser {
    config: ParserConfig,
    our_caps: Caps,
    peer_caps: Option<Caps>,

    // Input buffer
    input: BytesMut,

    // Parse state
    phase: ParsePhase,
    to_skip: usize,
    // Parsed header fields (set after header phase completes)
    pkt_type: u32,
    pkt_length: u32,
    pkt_id: u64,
    type_header_len: usize,

    // Output
    events: VecDeque<Event>,
    output: VecDeque<Bytes>,
    output_total_size: u64,
}

impl Parser {
    /// Create a new parser. Unless `config.no_hello` is set, a Hello packet
    /// is automatically queued for output.
    pub fn new(config: ParserConfig) -> Self {
        let mut our_caps = config.caps;
        // Guest side automatically sets device_disconnect_ack
        if !config.is_host {
            our_caps.set(Cap::DeviceDisconnectAck);
        }
        our_caps.verify();

        let mut parser = Self {
            config: config.clone(),
            our_caps,
            peer_caps: None,
            input: BytesMut::new(),
            phase: ParsePhase::Header,
            to_skip: 0,
            pkt_type: 0,
            pkt_length: 0,
            pkt_id: 0,
            type_header_len: 0,
            events: VecDeque::new(),
            output: VecDeque::new(),
            output_total_size: 0,
        };

        if !config.no_hello {
            let hello = Packet::Hello {
                version: config.version,
                caps: our_caps,
            };
            let _ = parser.send(hello);
        }

        parser
    }

    /// Returns whether our side advertises the given capability.
    pub fn have_cap(&self, cap: Cap) -> bool {
        self.our_caps.has(cap)
    }

    /// Returns whether the peer's Hello has been received yet.
    pub fn have_peer_caps(&self) -> bool {
        self.peer_caps.is_some()
    }

    /// Returns whether the peer advertises the given capability.
    pub fn peer_has_cap(&self, cap: Cap) -> bool {
        self.peer_caps.map_or(false, |p| p.has(cap))
    }

    fn using_32bit_ids(&self) -> bool {
        !self.have_cap(Cap::Ids64Bits) || !self.peer_has_cap(Cap::Ids64Bits)
    }

    fn header_len(&self) -> usize {
        if self.using_32bit_ids() {
            std::mem::size_of::<wire::Header32>()
        } else {
            std::mem::size_of::<wire::Header>()
        }
    }

    fn negotiated(&self, cap: Cap) -> bool {
        self.peer_caps
            .map_or(false, |p| self.our_caps.negotiated(&p, cap))
    }

    fn get_type_header_len(&self, pkt_type: u32, sending: bool) -> Result<usize> {
        let mut command_for_host = self.config.is_host;
        if sending {
            command_for_host = !command_for_host;
        }

        let len = match pkt_type {
            pkt_type::HELLO => std::mem::size_of::<wire::HelloHeader>(),
            pkt_type::DEVICE_CONNECT => {
                if !command_for_host {
                    if self.negotiated(Cap::ConnectDeviceVersion) {
                        std::mem::size_of::<wire::DeviceConnectHeader>()
                    } else {
                        std::mem::size_of::<wire::DeviceConnectHeaderNoVersion>()
                    }
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::DEVICE_DISCONNECT => {
                if !command_for_host {
                    0
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::RESET => {
                if command_for_host {
                    0
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::INTERFACE_INFO => {
                if !command_for_host {
                    std::mem::size_of::<wire::InterfaceInfoHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::EP_INFO => {
                if !command_for_host {
                    if self.negotiated(Cap::BulkStreams) {
                        std::mem::size_of::<wire::EpInfoHeader>()
                    } else if self.negotiated(Cap::EpInfoMaxPacketSize) {
                        std::mem::size_of::<wire::EpInfoHeaderNoMaxStreams>()
                    } else {
                        std::mem::size_of::<wire::EpInfoHeaderNoMaxPktsz>()
                    }
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::SET_CONFIGURATION => {
                if command_for_host {
                    std::mem::size_of::<wire::SetConfigurationHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::GET_CONFIGURATION => {
                if command_for_host {
                    0
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::CONFIGURATION_STATUS => {
                if !command_for_host {
                    std::mem::size_of::<wire::ConfigurationStatusHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::SET_ALT_SETTING => {
                if command_for_host {
                    std::mem::size_of::<wire::SetAltSettingHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::GET_ALT_SETTING => {
                if command_for_host {
                    std::mem::size_of::<wire::GetAltSettingHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::ALT_SETTING_STATUS => {
                if !command_for_host {
                    std::mem::size_of::<wire::AltSettingStatusHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::START_ISO_STREAM => {
                if command_for_host {
                    std::mem::size_of::<wire::StartIsoStreamHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::STOP_ISO_STREAM => {
                if command_for_host {
                    std::mem::size_of::<wire::StopIsoStreamHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::ISO_STREAM_STATUS => {
                if !command_for_host {
                    std::mem::size_of::<wire::IsoStreamStatusHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::START_INTERRUPT_RECEIVING => {
                if command_for_host {
                    std::mem::size_of::<wire::StartInterruptReceivingHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::STOP_INTERRUPT_RECEIVING => {
                if command_for_host {
                    std::mem::size_of::<wire::StopInterruptReceivingHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::INTERRUPT_RECEIVING_STATUS => {
                if !command_for_host {
                    std::mem::size_of::<wire::InterruptReceivingStatusHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::ALLOC_BULK_STREAMS => {
                if command_for_host {
                    std::mem::size_of::<wire::AllocBulkStreamsHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::FREE_BULK_STREAMS => {
                if command_for_host {
                    std::mem::size_of::<wire::FreeBulkStreamsHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::BULK_STREAMS_STATUS => {
                if !command_for_host {
                    std::mem::size_of::<wire::BulkStreamsStatusHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::CANCEL_DATA_PACKET => {
                if command_for_host {
                    0
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::FILTER_REJECT => {
                if command_for_host {
                    0
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::FILTER_FILTER => 0,
            pkt_type::DEVICE_DISCONNECT_ACK => {
                if command_for_host {
                    0
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::START_BULK_RECEIVING => {
                if command_for_host {
                    std::mem::size_of::<wire::StartBulkReceivingHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::STOP_BULK_RECEIVING => {
                if command_for_host {
                    std::mem::size_of::<wire::StopBulkReceivingHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::BULK_RECEIVING_STATUS => {
                if !command_for_host {
                    std::mem::size_of::<wire::BulkReceivingStatusHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            pkt_type::CONTROL_PACKET => std::mem::size_of::<wire::ControlPacketHeader>(),
            pkt_type::BULK_PACKET => {
                if self.negotiated(Cap::BulkLength32Bits) {
                    std::mem::size_of::<wire::BulkPacketHeader>()
                } else {
                    std::mem::size_of::<wire::BulkPacketHeader16BitLength>()
                }
            }
            pkt_type::ISO_PACKET => std::mem::size_of::<wire::IsoPacketHeader>(),
            pkt_type::INTERRUPT_PACKET => std::mem::size_of::<wire::InterruptPacketHeader>(),
            pkt_type::BUFFERED_BULK_PACKET => {
                if !command_for_host {
                    std::mem::size_of::<wire::BufferedBulkPacketHeader>()
                } else {
                    return Err(Error::WrongDirectionPacket);
                }
            }
            _ => return Err(Error::UnknownPacketType(pkt_type)),
        };

        Ok(len)
    }

    fn expects_extra_data(pkt_type: u32) -> bool {
        matches!(
            pkt_type,
            pkt_type::HELLO
                | pkt_type::FILTER_FILTER
                | pkt_type::CONTROL_PACKET
                | pkt_type::BULK_PACKET
                | pkt_type::ISO_PACKET
                | pkt_type::INTERRUPT_PACKET
                | pkt_type::BUFFERED_BULK_PACKET
        )
    }

    /// Push received bytes into the parser. Decoded packets become available
    /// via [`poll()`](Self::poll) or [`events()`](Self::events).
    pub fn feed(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
        self.do_parse();
    }

    /// Pull the next decoded event, or `None` if the queue is empty.
    pub fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Returns an iterator that drains all pending events.
    pub fn events(&mut self) -> impl Iterator<Item = Event> + '_ {
        std::iter::from_fn(move || self.events.pop_front())
    }

    fn do_parse(&mut self) {
        loop {
            // Skip phase (error recovery)
            if self.to_skip > 0 {
                let skip = self.to_skip.min(self.input.len());
                let _ = self.input.split_to(skip);
                self.to_skip -= skip;
                if self.to_skip > 0 {
                    return;
                }
            }

            match self.phase {
                ParsePhase::Header => {
                    let hlen = self.header_len();
                    if self.input.len() < hlen {
                        return;
                    }

                    // Parse header
                    if self.using_32bit_ids() {
                        let hdr =
                            wire::Header32::read_from_bytes(&self.input[..hlen]).unwrap();
                        self.pkt_type = hdr.type_.get();
                        self.pkt_length = hdr.length.get();
                        self.pkt_id = hdr.id.get() as u64;
                    } else {
                        let hdr =
                            wire::Header::read_from_bytes(&self.input[..hlen]).unwrap();
                        self.pkt_type = hdr.type_.get();
                        self.pkt_length = hdr.length.get();
                        self.pkt_id = hdr.id.get();
                    }

                    // Validate type
                    let type_header_len = match self.get_type_header_len(self.pkt_type, false) {
                        Ok(len) => len,
                        Err(e) => {
                            let _ = self.input.split_to(hlen);
                            self.to_skip = self.pkt_length as usize;
                            self.events.push_back(Event::ParseError(e));
                            continue;
                        }
                    };

                    // Validate length
                    if self.pkt_length > MAX_PACKET_SIZE {
                        let _ = self.input.split_to(hlen);
                        self.to_skip = self.pkt_length as usize;
                        self.events.push_back(Event::ParseError(Error::PacketTooLarge {
                            length: self.pkt_length,
                            max: MAX_PACKET_SIZE,
                        }));
                        continue;
                    }

                    if (self.pkt_length as usize) < type_header_len
                        || ((self.pkt_length as usize) > type_header_len
                            && !Self::expects_extra_data(self.pkt_type))
                    {
                        let _ = self.input.split_to(hlen);
                        self.to_skip = self.pkt_length as usize;
                        self.events
                            .push_back(Event::ParseError(Error::InvalidPacketLength {
                                packet_type: self.pkt_type,
                                length: self.pkt_length,
                            }));
                        continue;
                    }

                    self.type_header_len = type_header_len;
                    let _ = self.input.split_to(hlen);
                    self.phase = ParsePhase::Body;
                }
                ParsePhase::Body => {
                    let body_len = self.pkt_length as usize;
                    if self.input.len() < body_len {
                        return;
                    }

                    let body = self.input.split_to(body_len);
                    let type_header = &body[..self.type_header_len];
                    let data = &body[self.type_header_len..];

                    match self.decode_packet(type_header, data)
                        .and_then(|packet| {
                            self.verify_packet(&packet, false)?;
                            Ok(packet)
                        })
                    {
                        Ok(packet) => {
                            // Intercept hello to store peer caps
                            if let Packet::Hello { ref caps, ref version, .. } = packet {
                                if self.peer_caps.is_some() {
                                    self.events.push_back(Event::Log {
                                        level: LogLevel::Error,
                                        message: "Received second hello message, ignoring"
                                            .to_string(),
                                    });
                                } else {
                                    let mut peer_caps = *caps;
                                    peer_caps.verify();
                                    self.peer_caps = Some(peer_caps);
                                    self.events.push_back(Event::Log {
                                        level: LogLevel::Info,
                                        message: format!(
                                            "Peer version: {}, using {}-bits ids",
                                            version,
                                            if self.using_32bit_ids() { 32 } else { 64 }
                                        ),
                                    });
                                }
                            }
                            self.events.push_back(Event::Packet(packet));
                        }
                        Err(e) => {
                            self.events.push_back(Event::ParseError(e));
                        }
                    }

                    self.phase = ParsePhase::Header;
                }
            }
        }
    }

    /// Verify a decoded packet, matching C's usbredirparser_verify_type_header.
    /// Called on both the receive path (after decode) and the send path (before encode).
    fn verify_packet(&self, packet: &Packet, sending: bool) -> Result<()> {
        let mut command_for_host = self.config.is_host;
        if sending {
            command_for_host = !command_for_host;
        }

        match packet {
            Packet::InterfaceInfo { interface_count, .. } => {
                if *interface_count > 32 {
                    return Err(Error::InterfaceCountTooLarge(*interface_count));
                }
            }
            Packet::StartInterruptReceiving { endpoint, .. }
            | Packet::StopInterruptReceiving { endpoint, .. }
            | Packet::InterruptReceivingStatus { endpoint, .. } => {
                if *endpoint & 0x80 == 0 {
                    return Err(Error::NonInputEndpoint { endpoint: *endpoint });
                }
            }
            Packet::FilterReject | Packet::FilterFilter { .. } => {
                if sending {
                    if !self.peer_has_cap(Cap::Filter) {
                        return Err(Error::MissingCapability { cap: Cap::Filter });
                    }
                } else if !self.have_cap(Cap::Filter) {
                    return Err(Error::MissingCapability { cap: Cap::Filter });
                }
            }
            Packet::DeviceDisconnectAck => {
                if sending {
                    if !self.peer_has_cap(Cap::DeviceDisconnectAck) {
                        return Err(Error::MissingCapability {
                            cap: Cap::DeviceDisconnectAck,
                        });
                    }
                } else if !self.have_cap(Cap::DeviceDisconnectAck) {
                    return Err(Error::MissingCapability {
                        cap: Cap::DeviceDisconnectAck,
                    });
                }
            }
            Packet::StartBulkReceiving {
                endpoint,
                bytes_per_transfer,
                ..
            } => {
                self.verify_bulk_recv_cap(sending)?;
                if *bytes_per_transfer > crate::proto::MAX_BULK_TRANSFER_SIZE {
                    return Err(Error::BulkTransferTooLarge {
                        length: *bytes_per_transfer,
                        max: crate::proto::MAX_BULK_TRANSFER_SIZE,
                    });
                }
                if *endpoint & 0x80 == 0 {
                    return Err(Error::NonInputEndpoint { endpoint: *endpoint });
                }
            }
            Packet::StopBulkReceiving { endpoint, .. } => {
                self.verify_bulk_recv_cap(sending)?;
                if *endpoint & 0x80 == 0 {
                    return Err(Error::NonInputEndpoint { endpoint: *endpoint });
                }
            }
            Packet::BulkReceivingStatus { endpoint, .. } => {
                self.verify_bulk_recv_cap(sending)?;
                if *endpoint & 0x80 == 0 {
                    return Err(Error::NonInputEndpoint { endpoint: *endpoint });
                }
            }
            Packet::ControlPacket {
                endpoint,
                length,
                data,
                ..
            } => {
                self.verify_data_packet_direction(
                    *endpoint,
                    command_for_host,
                    *length as usize,
                    data.len(),
                    pkt_type::CONTROL_PACKET,
                )?;
            }
            Packet::BulkPacket {
                endpoint,
                length,
                data,
                ..
            } => {
                if *length > crate::proto::MAX_BULK_TRANSFER_SIZE {
                    return Err(Error::BulkTransferTooLarge {
                        length: *length,
                        max: crate::proto::MAX_BULK_TRANSFER_SIZE,
                    });
                }
                self.verify_data_packet_direction(
                    *endpoint,
                    command_for_host,
                    *length as usize,
                    data.len(),
                    pkt_type::BULK_PACKET,
                )?;
            }
            Packet::IsoPacket {
                endpoint,
                length,
                data,
                ..
            } => {
                self.verify_data_packet_direction(
                    *endpoint,
                    command_for_host,
                    *length as usize,
                    data.len(),
                    pkt_type::ISO_PACKET,
                )?;
            }
            Packet::InterruptPacket {
                endpoint,
                length,
                data,
                ..
            } => {
                self.verify_data_packet_direction(
                    *endpoint,
                    command_for_host,
                    *length as usize,
                    data.len(),
                    pkt_type::INTERRUPT_PACKET,
                )?;
            }
            Packet::BufferedBulkPacket {
                endpoint,
                length,
                data,
                ..
            } => {
                self.verify_bulk_recv_cap(sending)?;
                if *length > crate::proto::MAX_BULK_TRANSFER_SIZE {
                    return Err(Error::BulkTransferTooLarge {
                        length: *length,
                        max: crate::proto::MAX_BULK_TRANSFER_SIZE,
                    });
                }
                self.verify_data_packet_direction(
                    *endpoint,
                    command_for_host,
                    *length as usize,
                    data.len(),
                    pkt_type::BUFFERED_BULK_PACKET,
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    fn verify_bulk_recv_cap(&self, sending: bool) -> Result<()> {
        if sending {
            if !self.peer_has_cap(Cap::BulkReceiving) {
                return Err(Error::MissingCapability {
                    cap: Cap::BulkReceiving,
                });
            }
        } else if !self.have_cap(Cap::BulkReceiving) {
            return Err(Error::MissingCapability {
                cap: Cap::BulkReceiving,
            });
        }
        Ok(())
    }

    /// Verify data packet direction and data length, matching C logic.
    ///
    /// For data packets (control, bulk, iso, interrupt, buffered_bulk):
    /// - If endpoint IN (0x80 set) and command NOT for host → data expected
    /// - If endpoint OUT (0x80 clear) and command for host → data expected
    /// - Otherwise: no data expected (and some types reject this outright)
    fn verify_data_packet_direction(
        &self,
        endpoint: u8,
        command_for_host: bool,
        header_length: usize,
        data_len: usize,
        pkt_type: u32,
    ) -> Result<()> {
        let expect_data = ((endpoint & 0x80) != 0 && !command_for_host)
            || ((endpoint & 0x80) == 0 && command_for_host);

        if expect_data {
            if data_len != header_length {
                return Err(Error::DataLengthMismatch {
                    data_len,
                    header_len: header_length as u32,
                });
            }
        } else {
            if data_len != 0 {
                return Err(Error::WrongDirection { endpoint });
            }
            // Some types unconditionally reject wrong-direction
            match pkt_type {
                pkt_type::ISO_PACKET => {
                    return Err(Error::WrongDirection { endpoint });
                }
                pkt_type::INTERRUPT_PACKET => {
                    if command_for_host {
                        return Err(Error::WrongDirection { endpoint });
                    }
                }
                pkt_type::BUFFERED_BULK_PACKET => {
                    return Err(Error::WrongDirection { endpoint });
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn decode_packet(&self, type_header: &[u8], data: &[u8]) -> Result<Packet> {
        let id = self.pkt_id;

        match self.pkt_type {
            pkt_type::HELLO => {
                let hdr = wire::HelloHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("hello header".into()))?;
                let version_bytes = &hdr.version;
                let version = std::str::from_utf8(version_bytes)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string();
                let caps = Caps::from_le_bytes(data);
                Ok(Packet::Hello { version, caps })
            }
            pkt_type::DEVICE_CONNECT => {
                if self.negotiated(Cap::ConnectDeviceVersion) {
                    let hdr = wire::DeviceConnectHeader::read_from_bytes(type_header)
                        .map_err(|_| Error::Deserialize("device connect".into()))?;
                    Ok(Packet::DeviceConnect {
                        speed: Speed::try_from(hdr.speed).map_err(Error::InvalidEnumValue)?,
                        device_class: hdr.device_class,
                        device_subclass: hdr.device_subclass,
                        device_protocol: hdr.device_protocol,
                        vendor_id: hdr.vendor_id.get(),
                        product_id: hdr.product_id.get(),
                        device_version_bcd: hdr.device_version_bcd.get(),
                    })
                } else {
                    let hdr = wire::DeviceConnectHeaderNoVersion::read_from_bytes(type_header)
                        .map_err(|_| Error::Deserialize("device connect no ver".into()))?;
                    Ok(Packet::DeviceConnect {
                        speed: Speed::try_from(hdr.speed).map_err(Error::InvalidEnumValue)?,
                        device_class: hdr.device_class,
                        device_subclass: hdr.device_subclass,
                        device_protocol: hdr.device_protocol,
                        vendor_id: hdr.vendor_id.get(),
                        product_id: hdr.product_id.get(),
                        device_version_bcd: 0,
                    })
                }
            }
            pkt_type::DEVICE_DISCONNECT => Ok(Packet::DeviceDisconnect),
            pkt_type::RESET => Ok(Packet::Reset { id }),
            pkt_type::INTERFACE_INFO => {
                let hdr = wire::InterfaceInfoHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("interface info".into()))?;
                Ok(Packet::InterfaceInfo {
                    interface_count: hdr.interface_count.get(),
                    interface: hdr.interface,
                    interface_class: hdr.interface_class,
                    interface_subclass: hdr.interface_subclass,
                    interface_protocol: hdr.interface_protocol,
                })
            }
            pkt_type::EP_INFO => {
                let mut ep_type = [TransferType::Invalid; 32];
                let mut interval = [0u8; 32];
                let mut interface = [0u8; 32];
                let mut max_packet_size = [0u16; 32];
                let mut max_streams = [0u32; 32];

                if self.negotiated(Cap::BulkStreams) {
                    let hdr = wire::EpInfoHeader::read_from_bytes(type_header)
                        .map_err(|_| Error::Deserialize("ep info".into()))?;
                    for i in 0..32 {
                        ep_type[i] = TransferType::try_from(hdr.ep_type[i]).map_err(Error::InvalidEnumValue)?;
                        interval[i] = hdr.interval[i];
                        interface[i] = hdr.interface[i];
                        max_packet_size[i] = hdr.max_packet_size[i].get();
                        max_streams[i] = hdr.max_streams[i].get();
                    }
                } else if self.negotiated(Cap::EpInfoMaxPacketSize) {
                    let hdr = wire::EpInfoHeaderNoMaxStreams::read_from_bytes(type_header)
                        .map_err(|_| Error::Deserialize("ep info no streams".into()))?;
                    for i in 0..32 {
                        ep_type[i] = TransferType::try_from(hdr.ep_type[i]).map_err(Error::InvalidEnumValue)?;
                        interval[i] = hdr.interval[i];
                        interface[i] = hdr.interface[i];
                        max_packet_size[i] = hdr.max_packet_size[i].get();
                    }
                } else {
                    let hdr = wire::EpInfoHeaderNoMaxPktsz::read_from_bytes(type_header)
                        .map_err(|_| Error::Deserialize("ep info no pktsz".into()))?;
                    for i in 0..32 {
                        ep_type[i] = TransferType::try_from(hdr.ep_type[i]).map_err(Error::InvalidEnumValue)?;
                        interval[i] = hdr.interval[i];
                        interface[i] = hdr.interface[i];
                    }
                }

                Ok(Packet::EpInfo {
                    ep_type,
                    interval,
                    interface,
                    max_packet_size,
                    max_streams,
                })
            }
            pkt_type::SET_CONFIGURATION => {
                let hdr = wire::SetConfigurationHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("set config".into()))?;
                Ok(Packet::SetConfiguration {
                    id,
                    configuration: hdr.configuration,
                })
            }
            pkt_type::GET_CONFIGURATION => Ok(Packet::GetConfiguration { id }),
            pkt_type::CONFIGURATION_STATUS => {
                let hdr = wire::ConfigurationStatusHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("config status".into()))?;
                Ok(Packet::ConfigurationStatus {
                    id,
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    configuration: hdr.configuration,
                })
            }
            pkt_type::SET_ALT_SETTING => {
                let hdr = wire::SetAltSettingHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("set alt".into()))?;
                Ok(Packet::SetAltSetting {
                    id,
                    interface: hdr.interface,
                    alt: hdr.alt,
                })
            }
            pkt_type::GET_ALT_SETTING => {
                let hdr = wire::GetAltSettingHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("get alt".into()))?;
                Ok(Packet::GetAltSetting {
                    id,
                    interface: hdr.interface,
                })
            }
            pkt_type::ALT_SETTING_STATUS => {
                let hdr = wire::AltSettingStatusHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("alt status".into()))?;
                Ok(Packet::AltSettingStatus {
                    id,
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    interface: hdr.interface,
                    alt: hdr.alt,
                })
            }
            pkt_type::START_ISO_STREAM => {
                let hdr = wire::StartIsoStreamHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("start iso".into()))?;
                Ok(Packet::StartIsoStream {
                    id,
                    endpoint: hdr.endpoint,
                    pkts_per_urb: hdr.pkts_per_urb,
                    no_urbs: hdr.no_urbs,
                })
            }
            pkt_type::STOP_ISO_STREAM => {
                let hdr = wire::StopIsoStreamHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("stop iso".into()))?;
                Ok(Packet::StopIsoStream {
                    id,
                    endpoint: hdr.endpoint,
                })
            }
            pkt_type::ISO_STREAM_STATUS => {
                let hdr = wire::IsoStreamStatusHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("iso status".into()))?;
                Ok(Packet::IsoStreamStatus {
                    id,
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    endpoint: hdr.endpoint,
                })
            }
            pkt_type::START_INTERRUPT_RECEIVING => {
                let hdr = wire::StartInterruptReceivingHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("start int recv".into()))?;
                Ok(Packet::StartInterruptReceiving {
                    id,
                    endpoint: hdr.endpoint,
                })
            }
            pkt_type::STOP_INTERRUPT_RECEIVING => {
                let hdr = wire::StopInterruptReceivingHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("stop int recv".into()))?;
                Ok(Packet::StopInterruptReceiving {
                    id,
                    endpoint: hdr.endpoint,
                })
            }
            pkt_type::INTERRUPT_RECEIVING_STATUS => {
                let hdr = wire::InterruptReceivingStatusHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("int recv status".into()))?;
                Ok(Packet::InterruptReceivingStatus {
                    id,
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    endpoint: hdr.endpoint,
                })
            }
            pkt_type::ALLOC_BULK_STREAMS => {
                let hdr = wire::AllocBulkStreamsHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("alloc streams".into()))?;
                Ok(Packet::AllocBulkStreams {
                    id,
                    endpoints: hdr.endpoints.get(),
                    no_streams: hdr.no_streams.get(),
                })
            }
            pkt_type::FREE_BULK_STREAMS => {
                let hdr = wire::FreeBulkStreamsHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("free streams".into()))?;
                Ok(Packet::FreeBulkStreams {
                    id,
                    endpoints: hdr.endpoints.get(),
                })
            }
            pkt_type::BULK_STREAMS_STATUS => {
                let hdr = wire::BulkStreamsStatusHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("streams status".into()))?;
                Ok(Packet::BulkStreamsStatus {
                    id,
                    endpoints: hdr.endpoints.get(),
                    no_streams: hdr.no_streams.get(),
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                })
            }
            pkt_type::CANCEL_DATA_PACKET => Ok(Packet::CancelDataPacket { id }),
            pkt_type::FILTER_REJECT => Ok(Packet::FilterReject),
            pkt_type::FILTER_FILTER => {
                // Data is a null-terminated string of filter rules
                let s = if !data.is_empty() && data[data.len() - 1] == 0 {
                    std::str::from_utf8(&data[..data.len() - 1])
                        .map_err(|_| Error::Deserialize("filter string".into()))?
                } else {
                    return Err(Error::Deserialize("filter not null-terminated".into()));
                };
                let rules = filter::parse_rules(s, ",", "|")?;
                Ok(Packet::FilterFilter { rules })
            }
            pkt_type::DEVICE_DISCONNECT_ACK => Ok(Packet::DeviceDisconnectAck),
            pkt_type::START_BULK_RECEIVING => {
                let hdr = wire::StartBulkReceivingHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("start bulk recv".into()))?;
                Ok(Packet::StartBulkReceiving {
                    id,
                    stream_id: hdr.stream_id.get(),
                    bytes_per_transfer: hdr.bytes_per_transfer.get(),
                    endpoint: hdr.endpoint,
                    no_transfers: hdr.no_transfers,
                })
            }
            pkt_type::STOP_BULK_RECEIVING => {
                let hdr = wire::StopBulkReceivingHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("stop bulk recv".into()))?;
                Ok(Packet::StopBulkReceiving {
                    id,
                    stream_id: hdr.stream_id.get(),
                    endpoint: hdr.endpoint,
                })
            }
            pkt_type::BULK_RECEIVING_STATUS => {
                let hdr = wire::BulkReceivingStatusHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("bulk recv status".into()))?;
                Ok(Packet::BulkReceivingStatus {
                    id,
                    stream_id: hdr.stream_id.get(),
                    endpoint: hdr.endpoint,
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                })
            }
            pkt_type::CONTROL_PACKET => {
                let hdr = wire::ControlPacketHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("control pkt".into()))?;
                Ok(Packet::ControlPacket {
                    id,
                    endpoint: hdr.endpoint,
                    request: hdr.request,
                    requesttype: hdr.requesttype,
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    value: hdr.value.get(),
                    index: hdr.index.get(),
                    length: hdr.length.get(),
                    data: Bytes::copy_from_slice(data),
                })
            }
            pkt_type::BULK_PACKET => {
                if self.negotiated(Cap::BulkLength32Bits) {
                    let hdr = wire::BulkPacketHeader::read_from_bytes(type_header)
                        .map_err(|_| Error::Deserialize("bulk pkt".into()))?;
                    let length =
                        ((hdr.length_high.get() as u32) << 16) | (hdr.length.get() as u32);
                    Ok(Packet::BulkPacket {
                        id,
                        endpoint: hdr.endpoint,
                        status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                        length,
                        stream_id: hdr.stream_id.get(),
                        data: Bytes::copy_from_slice(data),
                    })
                } else {
                    let hdr = wire::BulkPacketHeader16BitLength::read_from_bytes(type_header)
                        .map_err(|_| Error::Deserialize("bulk pkt 16".into()))?;
                    Ok(Packet::BulkPacket {
                        id,
                        endpoint: hdr.endpoint,
                        status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                        length: hdr.length.get() as u32,
                        stream_id: hdr.stream_id.get(),
                        data: Bytes::copy_from_slice(data),
                    })
                }
            }
            pkt_type::ISO_PACKET => {
                let hdr = wire::IsoPacketHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("iso pkt".into()))?;
                Ok(Packet::IsoPacket {
                    id,
                    endpoint: hdr.endpoint,
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    length: hdr.length.get(),
                    data: Bytes::copy_from_slice(data),
                })
            }
            pkt_type::INTERRUPT_PACKET => {
                let hdr = wire::InterruptPacketHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("interrupt pkt".into()))?;
                Ok(Packet::InterruptPacket {
                    id,
                    endpoint: hdr.endpoint,
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    length: hdr.length.get(),
                    data: Bytes::copy_from_slice(data),
                })
            }
            pkt_type::BUFFERED_BULK_PACKET => {
                let hdr = wire::BufferedBulkPacketHeader::read_from_bytes(type_header)
                    .map_err(|_| Error::Deserialize("buffered bulk".into()))?;
                Ok(Packet::BufferedBulkPacket {
                    id,
                    stream_id: hdr.stream_id.get(),
                    length: hdr.length.get(),
                    endpoint: hdr.endpoint,
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    data: Bytes::copy_from_slice(data),
                })
            }
            _ => Err(Error::UnknownPacketType(self.pkt_type)),
        }
    }

    // Sans-IO output
    /// Encode and enqueue a packet for output. The wire bytes become available
    /// via [`drain()`](Self::drain) or [`drain_output()`](Self::drain_output).
    pub fn send(&mut self, packet: Packet) -> Result<()> {
        let pkt_type = packet.packet_type();
        let id = packet.id();
        let type_header_len = self.get_type_header_len(pkt_type, true)?;

        self.verify_packet(&packet, true)?;

        let header_len = self.header_len();
        let mut buf = BytesMut::with_capacity(header_len + type_header_len + 64);

        // Reserve space for the header (we'll patch the length after encoding)
        let header_start = buf.len();
        buf.extend_from_slice(&[0u8; 16][..header_len]);

        self.encode_packet_into(&packet, &mut buf)?;

        // Patch the header now that we know the body length
        let pkt_body_len = (buf.len() - header_start - header_len) as u32;
        if self.using_32bit_ids() {
            let hdr = wire::Header32 {
                type_: pkt_type.into(),
                length: pkt_body_len.into(),
                id: (id as u32).into(),
            };
            buf[header_start..header_start + header_len]
                .copy_from_slice(zerocopy::IntoBytes::as_bytes(&hdr));
        } else {
            let hdr = wire::Header {
                type_: pkt_type.into(),
                length: pkt_body_len.into(),
                id: id.into(),
            };
            buf[header_start..header_start + header_len]
                .copy_from_slice(zerocopy::IntoBytes::as_bytes(&hdr));
        }

        let bytes = buf.freeze();
        self.output_total_size += bytes.len() as u64;
        self.output.push_back(bytes);

        Ok(())
    }

    fn encode_packet_into(&self, packet: &Packet, buf: &mut BytesMut) -> Result<()> {
        macro_rules! write_hdr {
            ($hdr:expr) => {
                buf.extend_from_slice(zerocopy::IntoBytes::as_bytes(&$hdr));
            };
        }

        match packet {
            Packet::Hello { version, caps } => {
                let mut hdr = wire::HelloHeader { version: [0; 64] };
                let vbytes = version.as_bytes();
                let len = vbytes.len().min(63);
                hdr.version[..len].copy_from_slice(&vbytes[..len]);
                write_hdr!(hdr);
                buf.extend_from_slice(&caps.to_le_bytes());
            }
            Packet::DeviceConnect {
                speed,
                device_class,
                device_subclass,
                device_protocol,
                vendor_id,
                product_id,
                device_version_bcd,
            } => {
                if self.negotiated(Cap::ConnectDeviceVersion) {
                    write_hdr!(wire::DeviceConnectHeader {
                        speed: *speed as u8,
                        device_class: *device_class,
                        device_subclass: *device_subclass,
                        device_protocol: *device_protocol,
                        vendor_id: (*vendor_id).into(),
                        product_id: (*product_id).into(),
                        device_version_bcd: (*device_version_bcd).into(),
                    });
                } else {
                    write_hdr!(wire::DeviceConnectHeaderNoVersion {
                        speed: *speed as u8,
                        device_class: *device_class,
                        device_subclass: *device_subclass,
                        device_protocol: *device_protocol,
                        vendor_id: (*vendor_id).into(),
                        product_id: (*product_id).into(),
                    });
                }
            }
            Packet::DeviceDisconnect => {}
            Packet::InterfaceInfo {
                interface_count,
                interface,
                interface_class,
                interface_subclass,
                interface_protocol,
            } => {
                write_hdr!(wire::InterfaceInfoHeader {
                    interface_count: (*interface_count).into(),
                    interface: *interface,
                    interface_class: *interface_class,
                    interface_subclass: *interface_subclass,
                    interface_protocol: *interface_protocol,
                });
            }
            Packet::EpInfo {
                ep_type,
                interval,
                interface,
                max_packet_size,
                max_streams,
            } => {
                if self.negotiated(Cap::BulkStreams) {
                    let mut hdr = wire::EpInfoHeader {
                        ep_type: [0; 32],
                        interval: *interval,
                        interface: *interface,
                        max_packet_size: [0u16.into(); 32],
                        max_streams: [0u32.into(); 32],
                    };
                    for i in 0..32 {
                        hdr.ep_type[i] = ep_type[i] as u8;
                        hdr.max_packet_size[i] = max_packet_size[i].into();
                        hdr.max_streams[i] = max_streams[i].into();
                    }
                    write_hdr!(hdr);
                } else if self.negotiated(Cap::EpInfoMaxPacketSize) {
                    let mut hdr = wire::EpInfoHeaderNoMaxStreams {
                        ep_type: [0; 32],
                        interval: *interval,
                        interface: *interface,
                        max_packet_size: [0u16.into(); 32],
                    };
                    for i in 0..32 {
                        hdr.ep_type[i] = ep_type[i] as u8;
                        hdr.max_packet_size[i] = max_packet_size[i].into();
                    }
                    write_hdr!(hdr);
                } else {
                    let mut hdr = wire::EpInfoHeaderNoMaxPktsz {
                        ep_type: [0; 32],
                        interval: *interval,
                        interface: *interface,
                    };
                    for i in 0..32 {
                        hdr.ep_type[i] = ep_type[i] as u8;
                    }
                    write_hdr!(hdr);
                }
            }
            Packet::SetConfiguration { configuration, .. } => {
                write_hdr!(wire::SetConfigurationHeader {
                    configuration: *configuration,
                });
            }
            Packet::GetConfiguration { .. } => {}
            Packet::ConfigurationStatus {
                status,
                configuration,
                ..
            } => {
                write_hdr!(wire::ConfigurationStatusHeader {
                    status: *status as u8,
                    configuration: *configuration,
                });
            }
            Packet::SetAltSetting {
                interface, alt, ..
            } => {
                write_hdr!(wire::SetAltSettingHeader {
                    interface: *interface,
                    alt: *alt,
                });
            }
            Packet::GetAltSetting { interface, .. } => {
                write_hdr!(wire::GetAltSettingHeader {
                    interface: *interface,
                });
            }
            Packet::AltSettingStatus {
                status,
                interface,
                alt,
                ..
            } => {
                write_hdr!(wire::AltSettingStatusHeader {
                    status: *status as u8,
                    interface: *interface,
                    alt: *alt,
                });
            }
            Packet::StartIsoStream {
                endpoint,
                pkts_per_urb,
                no_urbs,
                ..
            } => {
                write_hdr!(wire::StartIsoStreamHeader {
                    endpoint: *endpoint,
                    pkts_per_urb: *pkts_per_urb,
                    no_urbs: *no_urbs,
                });
            }
            Packet::StopIsoStream { endpoint, .. } => {
                write_hdr!(wire::StopIsoStreamHeader {
                    endpoint: *endpoint,
                });
            }
            Packet::IsoStreamStatus {
                status, endpoint, ..
            } => {
                write_hdr!(wire::IsoStreamStatusHeader {
                    status: *status as u8,
                    endpoint: *endpoint,
                });
            }
            Packet::StartInterruptReceiving { endpoint, .. } => {
                write_hdr!(wire::StartInterruptReceivingHeader {
                    endpoint: *endpoint,
                });
            }
            Packet::StopInterruptReceiving { endpoint, .. } => {
                write_hdr!(wire::StopInterruptReceivingHeader {
                    endpoint: *endpoint,
                });
            }
            Packet::InterruptReceivingStatus {
                status, endpoint, ..
            } => {
                write_hdr!(wire::InterruptReceivingStatusHeader {
                    status: *status as u8,
                    endpoint: *endpoint,
                });
            }
            Packet::AllocBulkStreams {
                endpoints,
                no_streams,
                ..
            } => {
                write_hdr!(wire::AllocBulkStreamsHeader {
                    endpoints: (*endpoints).into(),
                    no_streams: (*no_streams).into(),
                });
            }
            Packet::FreeBulkStreams { endpoints, .. } => {
                write_hdr!(wire::FreeBulkStreamsHeader {
                    endpoints: (*endpoints).into(),
                });
            }
            Packet::BulkStreamsStatus {
                endpoints,
                no_streams,
                status,
                ..
            } => {
                write_hdr!(wire::BulkStreamsStatusHeader {
                    endpoints: (*endpoints).into(),
                    no_streams: (*no_streams).into(),
                    status: *status as u8,
                });
            }
            Packet::CancelDataPacket { .. } => {}
            Packet::Reset { .. } => {}
            Packet::FilterReject => {}
            Packet::FilterFilter { rules } => {
                let s = filter::rules_to_string(rules, ",", "|")
                    .map_err(|e| Error::Serialize(e.to_string()))?;
                buf.extend_from_slice(s.as_bytes());
                buf.extend_from_slice(&[0]); // null terminator
            }
            Packet::DeviceDisconnectAck => {}
            Packet::StartBulkReceiving {
                stream_id,
                bytes_per_transfer,
                endpoint,
                no_transfers,
                ..
            } => {
                write_hdr!(wire::StartBulkReceivingHeader {
                    stream_id: (*stream_id).into(),
                    bytes_per_transfer: (*bytes_per_transfer).into(),
                    endpoint: *endpoint,
                    no_transfers: *no_transfers,
                });
            }
            Packet::StopBulkReceiving {
                stream_id,
                endpoint,
                ..
            } => {
                write_hdr!(wire::StopBulkReceivingHeader {
                    stream_id: (*stream_id).into(),
                    endpoint: *endpoint,
                });
            }
            Packet::BulkReceivingStatus {
                stream_id,
                endpoint,
                status,
                ..
            } => {
                write_hdr!(wire::BulkReceivingStatusHeader {
                    stream_id: (*stream_id).into(),
                    endpoint: *endpoint,
                    status: *status as u8,
                });
            }
            Packet::ControlPacket {
                endpoint,
                request,
                requesttype,
                status,
                value,
                index,
                length,
                data: pdata,
                ..
            } => {
                write_hdr!(wire::ControlPacketHeader {
                    endpoint: *endpoint,
                    request: *request,
                    requesttype: *requesttype,
                    status: *status as u8,
                    value: (*value).into(),
                    index: (*index).into(),
                    length: (*length).into(),
                });
                buf.extend_from_slice(pdata);
            }
            Packet::BulkPacket {
                endpoint,
                status,
                length,
                stream_id,
                data: pdata,
                ..
            } => {
                if self.negotiated(Cap::BulkLength32Bits) {
                    write_hdr!(wire::BulkPacketHeader {
                        endpoint: *endpoint,
                        status: *status as u8,
                        length: (*length as u16).into(),
                        stream_id: (*stream_id).into(),
                        length_high: ((*length >> 16) as u16).into(),
                    });
                } else {
                    write_hdr!(wire::BulkPacketHeader16BitLength {
                        endpoint: *endpoint,
                        status: *status as u8,
                        length: (*length as u16).into(),
                        stream_id: (*stream_id).into(),
                    });
                }
                buf.extend_from_slice(pdata);
            }
            Packet::IsoPacket {
                endpoint,
                status,
                length,
                data: pdata,
                ..
            } => {
                write_hdr!(wire::IsoPacketHeader {
                    endpoint: *endpoint,
                    status: *status as u8,
                    length: (*length).into(),
                });
                buf.extend_from_slice(pdata);
            }
            Packet::InterruptPacket {
                endpoint,
                status,
                length,
                data: pdata,
                ..
            } => {
                write_hdr!(wire::InterruptPacketHeader {
                    endpoint: *endpoint,
                    status: *status as u8,
                    length: (*length).into(),
                });
                buf.extend_from_slice(pdata);
            }
            Packet::BufferedBulkPacket {
                stream_id,
                length,
                endpoint,
                status,
                data: pdata,
                ..
            } => {
                write_hdr!(wire::BufferedBulkPacketHeader {
                    stream_id: (*stream_id).into(),
                    length: (*length).into(),
                    endpoint: *endpoint,
                    status: *status as u8,
                });
                buf.extend_from_slice(pdata);
            }
        }

        Ok(())
    }

    /// Returns `true` if there are encoded bytes waiting to be drained.
    pub fn has_data_to_write(&self) -> bool {
        !self.output.is_empty()
    }

    /// Total byte count of buffered output not yet drained.
    pub fn buffered_output_size(&self) -> u64 {
        self.output_total_size
    }

    /// Pull the next chunk of encoded output bytes, or `None` if empty.
    pub fn drain(&mut self) -> Option<Bytes> {
        if let Some(buf) = self.output.pop_front() {
            self.output_total_size -= buf.len() as u64;
            Some(buf)
        } else {
            None
        }
    }

    /// Returns an iterator that drains all pending output buffers.
    pub fn drain_output(&mut self) -> impl Iterator<Item = Bytes> + '_ {
        std::iter::from_fn(move || self.drain())
    }

    // Serialization accessors for serializer module
    pub(crate) fn our_caps(&self) -> &Caps {
        &self.our_caps
    }

    pub(crate) fn peer_caps(&self) -> Option<&Caps> {
        self.peer_caps.as_ref()
    }

    pub(crate) fn to_skip(&self) -> usize {
        self.to_skip
    }

    #[allow(dead_code)]
    pub(crate) fn phase(&self) -> ParsePhase {
        self.phase
    }

    #[allow(dead_code)]
    pub(crate) fn input_buf(&self) -> &[u8] {
        &self.input
    }

    pub(crate) fn output_bufs(&self) -> &VecDeque<Bytes> {
        &self.output
    }

    #[allow(dead_code)]
    pub(crate) fn config(&self) -> &ParserConfig {
        &self.config
    }

    pub(crate) fn set_peer_caps(&mut self, caps: Caps) {
        self.peer_caps = Some(caps);
    }

    pub(crate) fn set_to_skip(&mut self, skip: usize) {
        self.to_skip = skip;
    }

    pub(crate) fn restore_input(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
    }

    pub(crate) fn restore_output(&mut self, buf: Bytes) {
        self.output_total_size += buf.len() as u64;
        self.output.push_back(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::{Cap, Caps};

    fn make_config(is_host: bool) -> ParserConfig {
        let mut caps = Caps::new();
        caps.set(Cap::ConnectDeviceVersion);
        caps.set(Cap::Filter);
        caps.set(Cap::DeviceDisconnectAck);
        caps.set(Cap::EpInfoMaxPacketSize);
        caps.set(Cap::Ids64Bits);
        caps.set(Cap::BulkLength32Bits);
        caps.set(Cap::BulkReceiving);
        ParserConfig {
            version: "test-0.1".to_string(),
            caps,
            is_host,
            no_hello: false,
        }
    }

    #[test]
    fn hello_roundtrip() {
        let mut host = Parser::new(make_config(true));
        let mut guest = Parser::new(make_config(false));

        // Host drains its hello packet
        let host_hello = host.drain().unwrap();

        // Guest feeds it
        guest.feed(&host_hello);

        // Guest should emit a Log (peer info) + the hello Packet
        let mut got_hello = false;
        while let Some(event) = guest.poll() {
            if let Event::Packet(Packet::Hello { version, caps }) = event {
                assert!(version.starts_with("test"));
                assert!(caps.has(Cap::Ids64Bits));
                got_hello = true;
            }
        }
        assert!(got_hello);
    }

    #[test]
    fn partial_feed() {
        let mut host = Parser::new(make_config(true));
        let mut guest = Parser::new(make_config(false));

        let host_hello = host.drain().unwrap();

        // Feed one byte at a time
        for byte in host_hello.iter() {
            guest.feed(&[*byte]);
        }

        let mut got_hello = false;
        while let Some(event) = guest.poll() {
            if let Event::Packet(Packet::Hello { .. }) = event {
                got_hello = true;
            }
        }
        assert!(got_hello);
    }

    #[test]
    fn bidirectional_hello_then_set_config() {
        let mut host = Parser::new(make_config(true));
        let mut guest = Parser::new(make_config(false));

        // Exchange hellos
        let host_hello = host.drain().unwrap();
        let guest_hello = guest.drain().unwrap();

        guest.feed(&host_hello);
        host.feed(&guest_hello);

        // Drain events
        while guest.poll().is_some() {}
        while host.poll().is_some() {}

        // Now guest sends set_configuration (guest is NOT host, so SetConfiguration
        // is command_for_host=true when sending from guest)
        guest
            .send(Packet::SetConfiguration {
                id: 42,
                configuration: 1,
            })
            .unwrap();

        let pkt_bytes = guest.drain().unwrap();
        host.feed(&pkt_bytes);

        let mut found = false;
        while let Some(event) = host.poll() {
            if let Event::Packet(Packet::SetConfiguration {
                id, configuration, ..
            }) = event
            {
                assert_eq!(id, 42);
                assert_eq!(configuration, 1);
                found = true;
            }
        }
        assert!(found);
    }
}
