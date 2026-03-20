use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use core::marker::PhantomData;

use bytes::{Bytes, BytesMut};
use zerocopy::FromBytes;

use crate::caps::{Cap, Caps};
use crate::error::{Error, Result};
use crate::filter;
use crate::packet::Packet;
use crate::proto::{Endpoint, PktType, Speed, Status, TransferType, MAX_PACKET_SIZE};
use crate::wire;

mod sealed {
    pub trait Sealed {}
}

/// Marker trait for the parser role (host or guest).
///
/// The usbredir protocol enforces directionality: some packets can only be
/// sent by the host, others only by the guest. This trait encodes the role
/// at the type level so that [`Parser<Host>`] and [`Parser<Guest>`] are
/// distinct types.
///
/// This trait is sealed and cannot be implemented outside this crate.
pub trait Role: sealed::Sealed + 'static {
    /// Whether this role represents the USB host side.
    const IS_HOST: bool;

    /// The opposite role: [`Guest`] for [`Host`], [`Host`] for [`Guest`].
    type Peer: Role;
}

/// Marker type for the USB host side.
///
/// A `Parser<Host>` can send host-originated packets (e.g. `DeviceConnect`,
/// status responses) and receives guest-originated packets (e.g. `Reset`,
/// `SetConfiguration`).
#[derive(Debug, Clone, Copy)]
pub struct Host;

/// Marker type for the USB guest side.
///
/// A `Parser<Guest>` can send guest-originated packets (e.g. `Reset`,
/// `SetConfiguration`) and receives host-originated packets (e.g.
/// `DeviceConnect`, status responses).
#[derive(Debug, Clone, Copy)]
pub struct Guest;

impl sealed::Sealed for Host {}
impl sealed::Sealed for Guest {}

impl Role for Host {
    const IS_HOST: bool = true;
    type Peer = Guest;
}

impl Role for Guest {
    const IS_HOST: bool = false;
    type Peer = Host;
}

/// Configuration for constructing a [`Parser`].
///
/// Use struct literal syntax or the builder methods:
/// ```
/// # use usbredir_proto::{ParserConfig, Caps, Cap, Parser, Host};
/// let config = ParserConfig::new("my-app 1.0")
///     .cap(Cap::Ids64Bits);
/// let parser = Parser::<Host>::new(config);
/// ```
#[derive(Debug, Clone)]
pub struct ParserConfig {
    /// Version string sent in the Hello packet (e.g. `"my-app 1.0"`).
    pub version: String,
    /// Our advertised capabilities.
    pub caps: Caps,
    /// If true, suppress the automatic Hello packet on construction.
    /// Useful when restoring a parser from serialized state.
    pub no_hello: bool,
    /// Maximum number of bytes allowed in the input buffer before `feed()`
    /// returns an error. `None` means unlimited (default).
    ///
    /// This protects against a malicious peer sending headers that claim
    /// very large bodies (up to ~128 MiB), causing unbounded memory growth.
    pub max_input_buffer: Option<usize>,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            version: String::new(),
            caps: Caps::new(),
            no_hello: false,
            max_input_buffer: None,
        }
    }
}

impl ParserConfig {
    /// Create a config with the given version string and defaults
    /// (all caps disabled, hello enabled).
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            ..Self::default()
        }
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

    /// Set the maximum input buffer size (in bytes).
    ///
    /// If set, [`Parser::feed()`] will return an error when the input buffer
    /// would exceed this limit. `None` means unlimited (default).
    #[must_use]
    pub fn max_input_buffer(mut self, max: usize) -> Self {
        self.max_input_buffer = Some(max);
        self
    }
}

/// An event produced by [`Parser::poll()`] or [`Parser::events()`].
///
/// `Packet` is boxed because the `EpInfo` variant is ~288 bytes; without boxing,
/// every `VecDeque` slot in the event queue would be that large. Common
/// hot-path packets (`Data`, `Request`) are much smaller but share the enum.
#[derive(Debug)]
pub enum Event {
    /// A successfully decoded packet.
    Packet(Box<Packet>),
    /// A parse error encountered during decoding.
    Error(Error),
}

/// Parse state machine: tracks whether we're waiting for a packet header
/// or already have a parsed header and are waiting for the body bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseState {
    Header,
    Body {
        pkt_type: PktType,
        pkt_length: u32,
        pkt_id: u64,
        type_header_len: usize,
    },
}

/// Sans-IO usbredir protocol parser and encoder.
///
/// The type parameter `R` determines whether this parser operates as
/// the USB [`Host`] or [`Guest`] side. This controls which packets may
/// be sent and received.
///
/// Feed raw bytes with [`feed()`](Self::feed), then pull decoded packets
/// with [`poll()`](Self::poll) or [`events()`](Self::events).
/// Encode outgoing packets with [`send()`](Self::send), then pull the
/// wire bytes with [`drain()`](Self::drain) or [`drain_output()`](Self::drain_output).
pub struct Parser<R: Role> {
    _role: PhantomData<R>,
    our_caps: Caps,
    peer_caps: Option<Caps>,

    // Input buffer
    input: BytesMut,
    max_input_buffer: Option<usize>,

    // Parse state
    state: ParseState,
    to_skip: usize,

    // Output
    events: VecDeque<Event>,
    output: VecDeque<Bytes>,
    output_total_size: u64,
}

impl<R: Role> core::fmt::Debug for Parser<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Parser")
            .field("is_host", &R::IS_HOST)
            .field("our_caps", &self.our_caps)
            .field("peer_caps", &self.peer_caps)
            .field("state", &self.state)
            .field("input_bytes", &self.input.len())
            .field("pending_events", &self.events.len())
            .field("output_bufs", &self.output.len())
            .field("output_bytes", &self.output_total_size)
            .finish()
    }
}

impl<R: Role> Parser<R> {
    /// Create a new parser. Unless `config.no_hello` is set, a Hello packet
    /// is automatically queued for output.
    pub fn new(config: ParserConfig) -> Self {
        let mut our_caps = config.caps;
        // Guest side automatically sets device_disconnect_ack
        if !R::IS_HOST {
            our_caps.set(Cap::DeviceDisconnectAck);
        }
        our_caps = our_caps.verified();

        let no_hello = config.no_hello;
        let version = config.version;
        let mut parser = Self {
            _role: PhantomData,
            our_caps,
            peer_caps: None,
            input: BytesMut::new(),
            max_input_buffer: config.max_input_buffer,
            state: ParseState::Header,
            to_skip: 0,
            events: VecDeque::new(),
            output: VecDeque::new(),
            output_total_size: 0,
        };

        #[cfg(feature = "tracing")]
        tracing::info!(
            role = if R::IS_HOST { "host" } else { "guest" },
            ?our_caps,
            "Parser created"
        );

        if !no_hello {
            let hello = Packet::Hello {
                version,
                caps: our_caps,
            };
            parser
                .send(&hello)
                .expect("Hello send cannot fail before negotiation");
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
        self.peer_caps.is_some_and(|p| p.has(cap))
    }

    fn using_32bit_ids(&self) -> bool {
        !self.have_cap(Cap::Ids64Bits) || !self.peer_has_cap(Cap::Ids64Bits)
    }

    fn header_len(&self) -> usize {
        if self.using_32bit_ids() {
            core::mem::size_of::<wire::Header32>()
        } else {
            core::mem::size_of::<wire::Header>()
        }
    }

    fn negotiated(&self, cap: Cap) -> bool {
        self.peer_caps
            .is_some_and(|p| self.our_caps.negotiated(&p, cap))
    }

    fn get_type_header_len(&self, pkt_type: PktType, sending: bool) -> Result<usize> {
        use crate::proto::Direction;

        // Check direction constraint. When sending, the expected direction is
        // the opposite of our role (we send commands *to* the peer).
        let command_for_host = R::IS_HOST ^ sending;
        match pkt_type.direction() {
            Direction::ToHost if !command_for_host => return Err(Error::WrongDirectionPacket),
            Direction::ToGuest if command_for_host => return Err(Error::WrongDirectionPacket),
            _ => {}
        }

        let len = match pkt_type {
            PktType::Hello => core::mem::size_of::<wire::HelloHeader>(),
            PktType::DeviceConnect => {
                if self.negotiated(Cap::ConnectDeviceVersion) {
                    core::mem::size_of::<wire::DeviceConnectHeader>()
                } else {
                    core::mem::size_of::<wire::DeviceConnectHeaderNoVersion>()
                }
            }
            PktType::EpInfo => {
                if self.negotiated(Cap::BulkStreams) {
                    core::mem::size_of::<wire::EpInfoHeader>()
                } else if self.negotiated(Cap::EpInfoMaxPacketSize) {
                    core::mem::size_of::<wire::EpInfoHeaderNoMaxStreams>()
                } else {
                    core::mem::size_of::<wire::EpInfoHeaderNoMaxPktsz>()
                }
            }
            PktType::InterfaceInfo => core::mem::size_of::<wire::InterfaceInfoHeader>(),
            PktType::SetConfiguration => core::mem::size_of::<wire::SetConfigurationHeader>(),
            PktType::ConfigurationStatus => core::mem::size_of::<wire::ConfigurationStatusHeader>(),
            PktType::SetAltSetting => core::mem::size_of::<wire::SetAltSettingHeader>(),
            PktType::GetAltSetting => core::mem::size_of::<wire::GetAltSettingHeader>(),
            PktType::AltSettingStatus => core::mem::size_of::<wire::AltSettingStatusHeader>(),
            PktType::StartIsoStream => core::mem::size_of::<wire::StartIsoStreamHeader>(),
            PktType::StopIsoStream => core::mem::size_of::<wire::StopIsoStreamHeader>(),
            PktType::IsoStreamStatus => core::mem::size_of::<wire::IsoStreamStatusHeader>(),
            PktType::StartInterruptReceiving => {
                core::mem::size_of::<wire::StartInterruptReceivingHeader>()
            }
            PktType::StopInterruptReceiving => {
                core::mem::size_of::<wire::StopInterruptReceivingHeader>()
            }
            PktType::InterruptReceivingStatus => {
                core::mem::size_of::<wire::InterruptReceivingStatusHeader>()
            }
            PktType::AllocBulkStreams => core::mem::size_of::<wire::AllocBulkStreamsHeader>(),
            PktType::FreeBulkStreams => core::mem::size_of::<wire::FreeBulkStreamsHeader>(),
            PktType::BulkStreamsStatus => core::mem::size_of::<wire::BulkStreamsStatusHeader>(),
            PktType::StartBulkReceiving => core::mem::size_of::<wire::StartBulkReceivingHeader>(),
            PktType::StopBulkReceiving => core::mem::size_of::<wire::StopBulkReceivingHeader>(),
            PktType::BulkReceivingStatus => core::mem::size_of::<wire::BulkReceivingStatusHeader>(),
            PktType::ControlPacket => core::mem::size_of::<wire::ControlPacketHeader>(),
            PktType::BulkPacket => {
                if self.negotiated(Cap::BulkLength32Bits) {
                    core::mem::size_of::<wire::BulkPacketHeader>()
                } else {
                    core::mem::size_of::<wire::BulkPacketHeader16BitLength>()
                }
            }
            PktType::IsoPacket => core::mem::size_of::<wire::IsoPacketHeader>(),
            PktType::InterruptPacket => core::mem::size_of::<wire::InterruptPacketHeader>(),
            PktType::BufferedBulkPacket => core::mem::size_of::<wire::BufferedBulkPacketHeader>(),
            PktType::DeviceDisconnect
            | PktType::Reset
            | PktType::GetConfiguration
            | PktType::CancelDataPacket
            | PktType::FilterReject
            | PktType::FilterFilter
            | PktType::DeviceDisconnectAck => 0,
        };

        Ok(len)
    }

    fn expects_extra_data(pkt_type: PktType) -> bool {
        matches!(
            pkt_type,
            PktType::Hello
                | PktType::FilterFilter
                | PktType::ControlPacket
                | PktType::BulkPacket
                | PktType::IsoPacket
                | PktType::InterruptPacket
                | PktType::BufferedBulkPacket
        )
    }

    /// Push received bytes into the parser. Decoded packets become available
    /// via [`poll()`](Self::poll) or [`events()`](Self::events).
    ///
    /// Returns an error if the input buffer would exceed the configured
    /// [`max_input_buffer`](ParserConfig::max_input_buffer) limit. In that case
    /// no bytes are consumed.
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        if let Some(max) = self.max_input_buffer {
            if self.input.len() + data.len() > max {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    current = self.input.len(),
                    incoming = data.len(),
                    max,
                    "input buffer full"
                );
                return Err(Error::InputBufferFull {
                    current: self.input.len(),
                    incoming: data.len(),
                    max,
                });
            }
        }
        self.input.extend_from_slice(data);
        #[cfg(feature = "tracing")]
        tracing::trace!(len = data.len(), buffered = self.input.len(), "feed");
        self.do_parse();
        Ok(())
    }

    /// Returns `true` if there are pending events to consume via [`poll()`](Self::poll).
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    /// Pull the next decoded event, or `None` if the queue is empty.
    pub fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Pull the next decoded packet, skipping any parse errors.
    ///
    /// This is a convenience wrapper around [`poll()`](Self::poll) for callers
    /// that don't need to handle parse errors. Errors (unknown packet types,
    /// malformed headers, direction violations, duplicate Hello, etc.) are
    /// **silently discarded**. Prefer [`poll()`](Self::poll) or
    /// [`events()`](Self::events) in production code to avoid missing protocol
    /// violations or connection-level errors.
    #[deprecated(
        since = "0.2.0",
        note = "silently discards errors; use poll() or events() instead"
    )]
    pub fn poll_packet(&mut self) -> Option<Box<Packet>> {
        loop {
            match self.events.pop_front()? {
                Event::Packet(p) => return Some(p),
                Event::Error(_) => continue,
            }
        }
    }

    /// Returns an iterator that drains all pending events.
    pub fn events(&mut self) -> impl Iterator<Item = Event> + '_ {
        core::iter::from_fn(move || self.events.pop_front())
    }

    fn do_parse(&mut self) {
        loop {
            // Skip phase (error recovery): after a malformed packet, we skip
            // `pkt_length` bytes (the body declared by the header). This can be up
            // to MAX_PACKET_SIZE (~128 MiB + 1 KiB). The skip is drained
            // incrementally via split_to so memory usage stays bounded by the
            // amount of data actually buffered, not by the skip target.
            if self.to_skip > 0 {
                let skip = self.to_skip.min(self.input.len());
                let _ = self.input.split_to(skip);
                self.to_skip -= skip;
                if self.to_skip > 0 {
                    return;
                }
            }

            match self.state {
                ParseState::Header => {
                    let hlen = self.header_len();
                    if self.input.len() < hlen {
                        return;
                    }

                    // Parse header
                    let (pkt_type_raw, pkt_length, pkt_id);
                    if self.using_32bit_ids() {
                        let hdr = wire::Header32::read_from_bytes(&self.input[..hlen]).unwrap();
                        pkt_type_raw = hdr.type_.get();
                        pkt_length = hdr.length.get();
                        pkt_id = hdr.id.get() as u64;
                    } else {
                        let hdr = wire::Header::read_from_bytes(&self.input[..hlen]).unwrap();
                        pkt_type_raw = hdr.type_.get();
                        pkt_length = hdr.length.get();
                        pkt_id = hdr.id.get();
                    }

                    // Convert wire u32 to PktType
                    let pkt_type = match PktType::try_from(pkt_type_raw) {
                        Ok(t) => t,
                        Err(_) => {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(pkt_type_raw, pkt_length, "unknown packet type, skipping");
                            let _ = self.input.split_to(hlen);
                            self.to_skip = pkt_length as usize;
                            self.events
                                .push_back(Event::Error(Error::UnknownPacketType(pkt_type_raw)));
                            continue;
                        }
                    };

                    // Validate type (direction check)
                    let type_header_len = match self.get_type_header_len(pkt_type, false) {
                        Ok(len) => len,
                        Err(e) => {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(?pkt_type, ?e, "direction check failed, skipping");
                            let _ = self.input.split_to(hlen);
                            self.to_skip = pkt_length as usize;
                            self.events.push_back(Event::Error(e));
                            continue;
                        }
                    };

                    // Validate length
                    if pkt_length > MAX_PACKET_SIZE {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(?pkt_type, pkt_length, "packet too large, skipping");
                        let _ = self.input.split_to(hlen);
                        self.to_skip = pkt_length as usize;
                        self.events.push_back(Event::Error(Error::PacketTooLarge {
                            length: pkt_length,
                            max: MAX_PACKET_SIZE,
                        }));
                        continue;
                    }

                    if (pkt_length as usize) < type_header_len
                        || ((pkt_length as usize) > type_header_len
                            && !Self::expects_extra_data(pkt_type))
                    {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(?pkt_type, pkt_length, type_header_len, "invalid packet length, skipping");
                        let _ = self.input.split_to(hlen);
                        self.to_skip = pkt_length as usize;
                        self.events
                            .push_back(Event::Error(Error::InvalidPacketLength {
                                packet_type: pkt_type,
                                length: pkt_length,
                            }));
                        continue;
                    }

                    let _ = self.input.split_to(hlen);
                    #[cfg(feature = "tracing")]
                    tracing::debug!(?pkt_type, pkt_id, pkt_length, "header parsed");
                    self.state = ParseState::Body {
                        pkt_type,
                        pkt_length,
                        pkt_id,
                        type_header_len,
                    };
                }
                ParseState::Body {
                    pkt_type,
                    pkt_length,
                    pkt_id,
                    type_header_len,
                } => {
                    let body_len = pkt_length as usize;
                    if self.input.len() < body_len {
                        return;
                    }

                    let body = self.input.split_to(body_len).freeze();
                    let type_header = &body[..type_header_len];
                    let data = body.slice(type_header_len..);

                    match self
                        .decode_packet(pkt_type, pkt_id, type_header, data)
                        .and_then(|packet| {
                            self.verify_packet(&packet, false)?;
                            Ok(packet)
                        }) {
                        Ok(packet) => {
                            // Intercept hello to store peer caps
                            if let Packet::Hello {
                                ref caps,
                                #[cfg(feature = "tracing")]
                                ref version,
                                ..
                            } = packet
                            {
                                if self.peer_caps.is_some() {
                                    #[cfg(feature = "tracing")]
                                    tracing::warn!("duplicate hello received");
                                    self.events.push_back(Event::Error(Error::DuplicateHello));
                                    self.state = ParseState::Header;
                                    continue;
                                }
                                let peer_caps = caps.verified();
                                self.peer_caps = Some(peer_caps);
                                #[cfg(feature = "tracing")]
                                {
                                    let id_bits = if self.using_32bit_ids() { 32 } else { 64 };
                                    tracing::info!(
                                        peer_version = %version,
                                        ?peer_caps,
                                        id_bits,
                                        "peer hello received"
                                    );
                                }
                            }
                            #[cfg(feature = "tracing")]
                            tracing::debug!(?pkt_type, pkt_id, "packet decoded");
                            self.events.push_back(Event::Packet(Box::new(packet)));
                        }
                        Err(e) => {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(?pkt_type, pkt_id, ?e, "packet decode failed");
                            self.events.push_back(Event::Error(e));
                        }
                    }

                    self.state = ParseState::Header;
                }
            }
        }
    }

    /// Verify a decoded packet, matching C's usbredirparser_verify_type_header.
    /// Called on both the receive path (after decode) and the send path (before encode).
    fn verify_packet(&self, packet: &Packet, sending: bool) -> Result<()> {
        let command_for_host = R::IS_HOST ^ sending;

        match packet {
            Packet::InterfaceInfo(info) => {
                if info.interface_count > 32 {
                    return Err(Error::InterfaceCountTooLarge(info.interface_count));
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
            Packet::Request(req) => {
                use crate::packet::RequestKind;
                match &req.kind {
                    RequestKind::StartInterruptReceiving { endpoint, .. }
                    | RequestKind::StopInterruptReceiving { endpoint, .. }
                    | RequestKind::InterruptReceivingStatus { endpoint, .. } => {
                        if endpoint.is_output() {
                            return Err(Error::NonInputEndpoint {
                                endpoint: *endpoint,
                            });
                        }
                    }
                    RequestKind::StartBulkReceiving {
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
                        if endpoint.is_output() {
                            return Err(Error::NonInputEndpoint {
                                endpoint: *endpoint,
                            });
                        }
                    }
                    RequestKind::StopBulkReceiving { endpoint, .. } => {
                        self.verify_bulk_recv_cap(sending)?;
                        if endpoint.is_output() {
                            return Err(Error::NonInputEndpoint {
                                endpoint: *endpoint,
                            });
                        }
                    }
                    RequestKind::BulkReceivingStatus { endpoint, .. } => {
                        self.verify_bulk_recv_cap(sending)?;
                        if endpoint.is_output() {
                            return Err(Error::NonInputEndpoint {
                                endpoint: *endpoint,
                            });
                        }
                    }
                    _ => {}
                }
            }
            Packet::Data(d) => {
                use crate::packet::DataKind;
                let wire_type = d.kind.packet_type();
                let header_length = d.kind.transfer_length() as usize;

                match &d.kind {
                    DataKind::Bulk { length, .. } => {
                        if *length > crate::proto::MAX_BULK_TRANSFER_SIZE {
                            return Err(Error::BulkTransferTooLarge {
                                length: *length,
                                max: crate::proto::MAX_BULK_TRANSFER_SIZE,
                            });
                        }
                    }
                    DataKind::BufferedBulk { length, .. } => {
                        self.verify_bulk_recv_cap(sending)?;
                        if *length > crate::proto::MAX_BULK_TRANSFER_SIZE {
                            return Err(Error::BulkTransferTooLarge {
                                length: *length,
                                max: crate::proto::MAX_BULK_TRANSFER_SIZE,
                            });
                        }
                    }
                    _ => {}
                }

                self.verify_data_packet_direction(
                    &d.endpoint,
                    command_for_host,
                    header_length,
                    d.data.len(),
                    wire_type,
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
        endpoint: &Endpoint,
        command_for_host: bool,
        header_length: usize,
        data_len: usize,
        pkt_type: PktType,
    ) -> Result<()> {
        let expect_data = (endpoint.is_input() && !command_for_host)
            || (endpoint.is_output() && command_for_host);

        if expect_data {
            if data_len != header_length {
                return Err(Error::DataLengthMismatch {
                    data_len,
                    header_len: header_length as u32,
                });
            }
        } else {
            if data_len != 0 {
                return Err(Error::WrongDirection {
                    endpoint: *endpoint,
                });
            }
            // Some types unconditionally reject wrong-direction
            match pkt_type {
                PktType::IsoPacket => {
                    return Err(Error::WrongDirection {
                        endpoint: *endpoint,
                    });
                }
                PktType::InterruptPacket => {
                    if command_for_host {
                        return Err(Error::WrongDirection {
                            endpoint: *endpoint,
                        });
                    }
                }
                PktType::BufferedBulkPacket => {
                    return Err(Error::WrongDirection {
                        endpoint: *endpoint,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn decode_packet(
        &self,
        pkt_type: PktType,
        id: u64,
        type_header: &[u8],
        data: Bytes,
    ) -> Result<Packet> {
        macro_rules! wire_err {
            () => {
                |_| Error::WireHeaderDecode {
                    packet_type: pkt_type,
                }
            };
        }

        match pkt_type {
            PktType::Hello => {
                let hdr = wire::HelloHeader::read_from_bytes(type_header).map_err(wire_err!())?;
                let version_bytes = &hdr.version;
                let version = core::str::from_utf8(version_bytes)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string();
                let caps = Caps::from_le_bytes(&data);
                Ok(Packet::Hello { version, caps })
            }
            PktType::DeviceConnect => {
                if self.negotiated(Cap::ConnectDeviceVersion) {
                    let hdr = wire::DeviceConnectHeader::read_from_bytes(type_header)
                        .map_err(wire_err!())?;
                    Ok(Packet::DeviceConnect(crate::packet::DeviceConnectInfo {
                        speed: Speed::try_from(hdr.speed).map_err(Error::InvalidEnumValue)?,
                        device_class: hdr.device_class,
                        device_subclass: hdr.device_subclass,
                        device_protocol: hdr.device_protocol,
                        vendor_id: hdr.vendor_id.get(),
                        product_id: hdr.product_id.get(),
                        device_version_bcd: hdr.device_version_bcd.get(),
                    }))
                } else {
                    let hdr = wire::DeviceConnectHeaderNoVersion::read_from_bytes(type_header)
                        .map_err(wire_err!())?;
                    Ok(Packet::DeviceConnect(crate::packet::DeviceConnectInfo {
                        speed: Speed::try_from(hdr.speed).map_err(Error::InvalidEnumValue)?,
                        device_class: hdr.device_class,
                        device_subclass: hdr.device_subclass,
                        device_protocol: hdr.device_protocol,
                        vendor_id: hdr.vendor_id.get(),
                        product_id: hdr.product_id.get(),
                        device_version_bcd: 0,
                    }))
                }
            }
            PktType::DeviceDisconnect => Ok(Packet::DeviceDisconnect),
            PktType::Reset => Ok(Packet::Request(crate::packet::RequestPacket {
                id,
                kind: crate::packet::RequestKind::Reset,
            })),
            PktType::InterfaceInfo => {
                let hdr =
                    wire::InterfaceInfoHeader::read_from_bytes(type_header).map_err(wire_err!())?;
                Ok(Packet::InterfaceInfo(Box::new(
                    crate::packet::InterfaceInfoData {
                        interface_count: hdr.interface_count.get(),
                        interface: hdr.interface,
                        interface_class: hdr.interface_class,
                        interface_subclass: hdr.interface_subclass,
                        interface_protocol: hdr.interface_protocol,
                    },
                )))
            }
            PktType::EpInfo => {
                let mut ep_type = [TransferType::Invalid; 32];
                let mut interval = [0u8; 32];
                let mut interface = [0u8; 32];
                let mut max_packet_size = [0u16; 32];
                let mut max_streams = [0u32; 32];

                if self.negotiated(Cap::BulkStreams) {
                    let hdr =
                        wire::EpInfoHeader::read_from_bytes(type_header).map_err(wire_err!())?;
                    for i in 0..32 {
                        ep_type[i] = TransferType::try_from(hdr.ep_type[i])
                            .map_err(Error::InvalidEnumValue)?;
                        interval[i] = hdr.interval[i];
                        interface[i] = hdr.interface[i];
                        max_packet_size[i] = hdr.max_packet_size[i].get();
                        max_streams[i] = hdr.max_streams[i].get();
                    }
                } else if self.negotiated(Cap::EpInfoMaxPacketSize) {
                    let hdr = wire::EpInfoHeaderNoMaxStreams::read_from_bytes(type_header)
                        .map_err(wire_err!())?;
                    for i in 0..32 {
                        ep_type[i] = TransferType::try_from(hdr.ep_type[i])
                            .map_err(Error::InvalidEnumValue)?;
                        interval[i] = hdr.interval[i];
                        interface[i] = hdr.interface[i];
                        max_packet_size[i] = hdr.max_packet_size[i].get();
                    }
                } else {
                    let hdr = wire::EpInfoHeaderNoMaxPktsz::read_from_bytes(type_header)
                        .map_err(wire_err!())?;
                    for i in 0..32 {
                        ep_type[i] = TransferType::try_from(hdr.ep_type[i])
                            .map_err(Error::InvalidEnumValue)?;
                        interval[i] = hdr.interval[i];
                        interface[i] = hdr.interface[i];
                    }
                }

                Ok(Packet::EpInfo(Box::new(crate::packet::EpInfoData {
                    ep_type,
                    interval,
                    interface,
                    max_packet_size,
                    max_streams,
                })))
            }
            PktType::SetConfiguration => {
                let hdr = wire::SetConfigurationHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::set_configuration(id, hdr.configuration))
            }
            PktType::GetConfiguration => Ok(Packet::get_configuration(id)),
            PktType::ConfigurationStatus => {
                let hdr = wire::ConfigurationStatusHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::configuration_status(
                    id,
                    Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    hdr.configuration,
                ))
            }
            PktType::SetAltSetting => {
                let hdr =
                    wire::SetAltSettingHeader::read_from_bytes(type_header).map_err(wire_err!())?;
                Ok(Packet::set_alt_setting(id, hdr.interface, hdr.alt))
            }
            PktType::GetAltSetting => {
                let hdr =
                    wire::GetAltSettingHeader::read_from_bytes(type_header).map_err(wire_err!())?;
                Ok(Packet::get_alt_setting(id, hdr.interface))
            }
            PktType::AltSettingStatus => {
                let hdr = wire::AltSettingStatusHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::alt_setting_status(
                    id,
                    Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    hdr.interface,
                    hdr.alt,
                ))
            }
            PktType::StartIsoStream => {
                let hdr = wire::StartIsoStreamHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::start_iso_stream(
                    id,
                    Endpoint::new(hdr.endpoint),
                    hdr.pkts_per_urb,
                    hdr.no_urbs,
                ))
            }
            PktType::StopIsoStream => {
                let hdr =
                    wire::StopIsoStreamHeader::read_from_bytes(type_header).map_err(wire_err!())?;
                Ok(Packet::stop_iso_stream(id, Endpoint::new(hdr.endpoint)))
            }
            PktType::IsoStreamStatus => {
                let hdr = wire::IsoStreamStatusHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::iso_stream_status(
                    id,
                    Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    Endpoint::new(hdr.endpoint),
                ))
            }
            PktType::StartInterruptReceiving => {
                let hdr = wire::StartInterruptReceivingHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::start_interrupt_receiving(
                    id,
                    Endpoint::new(hdr.endpoint),
                ))
            }
            PktType::StopInterruptReceiving => {
                let hdr = wire::StopInterruptReceivingHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::stop_interrupt_receiving(
                    id,
                    Endpoint::new(hdr.endpoint),
                ))
            }
            PktType::InterruptReceivingStatus => {
                let hdr = wire::InterruptReceivingStatusHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::interrupt_receiving_status(
                    id,
                    Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    Endpoint::new(hdr.endpoint),
                ))
            }
            PktType::AllocBulkStreams => {
                let hdr = wire::AllocBulkStreamsHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::alloc_bulk_streams(
                    id,
                    hdr.endpoints.get(),
                    hdr.no_streams.get(),
                ))
            }
            PktType::FreeBulkStreams => {
                let hdr = wire::FreeBulkStreamsHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::free_bulk_streams(id, hdr.endpoints.get()))
            }
            PktType::BulkStreamsStatus => {
                let hdr = wire::BulkStreamsStatusHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::bulk_streams_status(
                    id,
                    hdr.endpoints.get(),
                    hdr.no_streams.get(),
                    Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                ))
            }
            PktType::CancelDataPacket => Ok(Packet::cancel_data_packet(id)),
            PktType::FilterReject => Ok(Packet::FilterReject),
            PktType::FilterFilter => {
                // Data is a null-terminated string of filter rules
                let s = if !data.is_empty() && data[data.len() - 1] == 0 {
                    core::str::from_utf8(&data[..data.len() - 1]).map_err(|_| Error::InvalidUtf8)?
                } else {
                    return Err(Error::FilterNotNullTerminated);
                };
                let rules = filter::parse_rules(s, ",", "|")?;
                Ok(Packet::FilterFilter { rules })
            }
            PktType::DeviceDisconnectAck => Ok(Packet::DeviceDisconnectAck),
            PktType::StartBulkReceiving => {
                let hdr = wire::StartBulkReceivingHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::start_bulk_receiving(
                    id,
                    hdr.stream_id.get(),
                    hdr.bytes_per_transfer.get(),
                    Endpoint::new(hdr.endpoint),
                    hdr.no_transfers,
                ))
            }
            PktType::StopBulkReceiving => {
                let hdr = wire::StopBulkReceivingHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::stop_bulk_receiving(
                    id,
                    hdr.stream_id.get(),
                    Endpoint::new(hdr.endpoint),
                ))
            }
            PktType::BulkReceivingStatus => {
                let hdr = wire::BulkReceivingStatusHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::bulk_receiving_status(
                    id,
                    hdr.stream_id.get(),
                    Endpoint::new(hdr.endpoint),
                    Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                ))
            }
            PktType::ControlPacket => {
                let hdr =
                    wire::ControlPacketHeader::read_from_bytes(type_header).map_err(wire_err!())?;
                Ok(Packet::Data(crate::packet::DataPacket {
                    id,
                    endpoint: Endpoint::new(hdr.endpoint),
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    kind: crate::packet::DataKind::Control {
                        request: hdr.request,
                        requesttype: hdr.requesttype,
                        value: hdr.value.get(),
                        index: hdr.index.get(),
                        length: hdr.length.get(),
                    },
                    data: data.clone(),
                }))
            }
            PktType::BulkPacket => {
                if self.negotiated(Cap::BulkLength32Bits) {
                    let hdr = wire::BulkPacketHeader::read_from_bytes(type_header)
                        .map_err(wire_err!())?;
                    let length = ((hdr.length_high.get() as u32) << 16) | (hdr.length.get() as u32);
                    Ok(Packet::Data(crate::packet::DataPacket {
                        id,
                        endpoint: Endpoint::new(hdr.endpoint),
                        status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                        kind: crate::packet::DataKind::Bulk {
                            length,
                            stream_id: hdr.stream_id.get(),
                        },
                        data: data.clone(),
                    }))
                } else {
                    let hdr = wire::BulkPacketHeader16BitLength::read_from_bytes(type_header)
                        .map_err(wire_err!())?;
                    Ok(Packet::Data(crate::packet::DataPacket {
                        id,
                        endpoint: Endpoint::new(hdr.endpoint),
                        status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                        kind: crate::packet::DataKind::Bulk {
                            length: hdr.length.get() as u32,
                            stream_id: hdr.stream_id.get(),
                        },
                        data: data.clone(),
                    }))
                }
            }
            PktType::IsoPacket => {
                let hdr =
                    wire::IsoPacketHeader::read_from_bytes(type_header).map_err(wire_err!())?;
                Ok(Packet::Data(crate::packet::DataPacket {
                    id,
                    endpoint: Endpoint::new(hdr.endpoint),
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    kind: crate::packet::DataKind::Iso {
                        length: hdr.length.get(),
                    },
                    data: data.clone(),
                }))
            }
            PktType::InterruptPacket => {
                let hdr = wire::InterruptPacketHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::Data(crate::packet::DataPacket {
                    id,
                    endpoint: Endpoint::new(hdr.endpoint),
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    kind: crate::packet::DataKind::Interrupt {
                        length: hdr.length.get(),
                    },
                    data: data.clone(),
                }))
            }
            PktType::BufferedBulkPacket => {
                let hdr = wire::BufferedBulkPacketHeader::read_from_bytes(type_header)
                    .map_err(wire_err!())?;
                Ok(Packet::Data(crate::packet::DataPacket {
                    id,
                    endpoint: Endpoint::new(hdr.endpoint),
                    status: Status::try_from(hdr.status).map_err(Error::InvalidEnumValue)?,
                    kind: crate::packet::DataKind::BufferedBulk {
                        stream_id: hdr.stream_id.get(),
                        length: hdr.length.get(),
                    },
                    data: data.clone(),
                }))
            }
        }
    }

    // Sans-IO output
    /// Encode and enqueue a packet for output. The wire bytes become available
    /// via [`drain()`](Self::drain) or [`drain_output()`](Self::drain_output).
    pub fn send(&mut self, packet: &Packet) -> Result<()> {
        // Hello must be sendable before negotiation; all other packets require
        // peer caps so that capability-dependent wire formats are correct.
        if !matches!(*packet, Packet::Hello { .. }) && self.peer_caps.is_none() {
            #[cfg(feature = "tracing")]
            tracing::warn!(pkt_type = ?packet.packet_type(), "send before peer hello");
            return Err(Error::NoPeerCaps);
        }

        let pkt_type = packet.packet_type();
        let id = packet.id().unwrap_or(0);
        let type_header_len = self.get_type_header_len(pkt_type, true)?;

        self.verify_packet(packet, true)?;

        let header_len = self.header_len();
        let mut buf = BytesMut::with_capacity(header_len + type_header_len + 64);

        // Reserve space for the header (we'll patch the length after encoding)
        let header_start = buf.len();
        buf.extend_from_slice(&[0u8; 16][..header_len]);

        self.encode_packet_into(packet, &mut buf)?;

        // Patch the header now that we know the body length
        let pkt_body_len = (buf.len() - header_start - header_len) as u32;
        let pkt_type_u32: u32 = pkt_type.into();
        if self.using_32bit_ids() {
            let hdr = wire::Header32 {
                type_: pkt_type_u32.into(),
                length: pkt_body_len.into(),
                id: (id as u32).into(),
            };
            buf[header_start..header_start + header_len]
                .copy_from_slice(zerocopy::IntoBytes::as_bytes(&hdr));
        } else {
            let hdr = wire::Header {
                type_: pkt_type_u32.into(),
                length: pkt_body_len.into(),
                id: id.into(),
            };
            buf[header_start..header_start + header_len]
                .copy_from_slice(zerocopy::IntoBytes::as_bytes(&hdr));
        }

        let bytes = buf.freeze();
        #[cfg(feature = "tracing")]
        tracing::debug!(
            ?pkt_type,
            id,
            wire_len = bytes.len(),
            "packet sent"
        );
        self.output_total_size = self.output_total_size.saturating_add(bytes.len() as u64);
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
            Packet::DeviceConnect(info) => {
                if self.negotiated(Cap::ConnectDeviceVersion) {
                    write_hdr!(wire::DeviceConnectHeader {
                        speed: info.speed as u8,
                        device_class: info.device_class,
                        device_subclass: info.device_subclass,
                        device_protocol: info.device_protocol,
                        vendor_id: info.vendor_id.into(),
                        product_id: info.product_id.into(),
                        device_version_bcd: info.device_version_bcd.into(),
                    });
                } else {
                    write_hdr!(wire::DeviceConnectHeaderNoVersion {
                        speed: info.speed as u8,
                        device_class: info.device_class,
                        device_subclass: info.device_subclass,
                        device_protocol: info.device_protocol,
                        vendor_id: info.vendor_id.into(),
                        product_id: info.product_id.into(),
                    });
                }
            }
            Packet::DeviceDisconnect => {}
            Packet::InterfaceInfo(info) => {
                write_hdr!(wire::InterfaceInfoHeader {
                    interface_count: info.interface_count.into(),
                    interface: info.interface,
                    interface_class: info.interface_class,
                    interface_subclass: info.interface_subclass,
                    interface_protocol: info.interface_protocol,
                });
            }
            Packet::EpInfo(info) => {
                let crate::packet::EpInfoData {
                    ep_type,
                    interval,
                    interface,
                    max_packet_size,
                    max_streams,
                } = info.as_ref();
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
                    for (i, et) in ep_type.iter().enumerate() {
                        hdr.ep_type[i] = *et as u8;
                    }
                    write_hdr!(hdr);
                }
            }
            Packet::Request(ref req) => {
                use crate::packet::RequestKind;
                match &req.kind {
                    RequestKind::SetConfiguration { configuration } => {
                        write_hdr!(wire::SetConfigurationHeader {
                            configuration: *configuration,
                        });
                    }
                    RequestKind::GetConfiguration => {}
                    RequestKind::ConfigurationStatus {
                        status,
                        configuration,
                    } => {
                        write_hdr!(wire::ConfigurationStatusHeader {
                            status: *status as u8,
                            configuration: *configuration,
                        });
                    }
                    RequestKind::SetAltSetting { interface, alt } => {
                        write_hdr!(wire::SetAltSettingHeader {
                            interface: *interface,
                            alt: *alt,
                        });
                    }
                    RequestKind::GetAltSetting { interface } => {
                        write_hdr!(wire::GetAltSettingHeader {
                            interface: *interface,
                        });
                    }
                    RequestKind::AltSettingStatus {
                        status,
                        interface,
                        alt,
                    } => {
                        write_hdr!(wire::AltSettingStatusHeader {
                            status: *status as u8,
                            interface: *interface,
                            alt: *alt,
                        });
                    }
                    RequestKind::StartIsoStream {
                        endpoint,
                        pkts_per_urb,
                        no_urbs,
                    } => {
                        write_hdr!(wire::StartIsoStreamHeader {
                            endpoint: endpoint.raw(),
                            pkts_per_urb: *pkts_per_urb,
                            no_urbs: *no_urbs,
                        });
                    }
                    RequestKind::StopIsoStream { endpoint } => {
                        write_hdr!(wire::StopIsoStreamHeader {
                            endpoint: endpoint.raw(),
                        });
                    }
                    RequestKind::IsoStreamStatus { status, endpoint } => {
                        write_hdr!(wire::IsoStreamStatusHeader {
                            status: *status as u8,
                            endpoint: endpoint.raw(),
                        });
                    }
                    RequestKind::StartInterruptReceiving { endpoint } => {
                        write_hdr!(wire::StartInterruptReceivingHeader {
                            endpoint: endpoint.raw(),
                        });
                    }
                    RequestKind::StopInterruptReceiving { endpoint } => {
                        write_hdr!(wire::StopInterruptReceivingHeader {
                            endpoint: endpoint.raw(),
                        });
                    }
                    RequestKind::InterruptReceivingStatus { status, endpoint } => {
                        write_hdr!(wire::InterruptReceivingStatusHeader {
                            status: *status as u8,
                            endpoint: endpoint.raw(),
                        });
                    }
                    RequestKind::AllocBulkStreams {
                        endpoints,
                        no_streams,
                    } => {
                        write_hdr!(wire::AllocBulkStreamsHeader {
                            endpoints: (*endpoints).into(),
                            no_streams: (*no_streams).into(),
                        });
                    }
                    RequestKind::FreeBulkStreams { endpoints } => {
                        write_hdr!(wire::FreeBulkStreamsHeader {
                            endpoints: (*endpoints).into(),
                        });
                    }
                    RequestKind::BulkStreamsStatus {
                        endpoints,
                        no_streams,
                        status,
                    } => {
                        write_hdr!(wire::BulkStreamsStatusHeader {
                            endpoints: (*endpoints).into(),
                            no_streams: (*no_streams).into(),
                            status: *status as u8,
                        });
                    }
                    RequestKind::CancelDataPacket => {}
                    RequestKind::Reset => {}
                    RequestKind::StartBulkReceiving {
                        stream_id,
                        bytes_per_transfer,
                        endpoint,
                        no_transfers,
                    } => {
                        write_hdr!(wire::StartBulkReceivingHeader {
                            stream_id: (*stream_id).into(),
                            bytes_per_transfer: (*bytes_per_transfer).into(),
                            endpoint: endpoint.raw(),
                            no_transfers: *no_transfers,
                        });
                    }
                    RequestKind::StopBulkReceiving {
                        stream_id,
                        endpoint,
                    } => {
                        write_hdr!(wire::StopBulkReceivingHeader {
                            stream_id: (*stream_id).into(),
                            endpoint: endpoint.raw(),
                        });
                    }
                    RequestKind::BulkReceivingStatus {
                        stream_id,
                        endpoint,
                        status,
                    } => {
                        write_hdr!(wire::BulkReceivingStatusHeader {
                            stream_id: (*stream_id).into(),
                            endpoint: endpoint.raw(),
                            status: *status as u8,
                        });
                    }
                }
            }
            Packet::FilterReject => {}
            Packet::FilterFilter { rules } => {
                let s = filter::rules_to_string(rules, ",", "|")?;
                buf.extend_from_slice(s.as_bytes());
                buf.extend_from_slice(&[0]); // null terminator
            }
            Packet::DeviceDisconnectAck => {}
            Packet::Data(d) => {
                use crate::packet::DataKind;
                match &d.kind {
                    DataKind::Control {
                        request,
                        requesttype,
                        value,
                        index,
                        length,
                    } => {
                        write_hdr!(wire::ControlPacketHeader {
                            endpoint: d.endpoint.raw(),
                            request: *request,
                            requesttype: *requesttype,
                            status: d.status as u8,
                            value: (*value).into(),
                            index: (*index).into(),
                            length: (*length).into(),
                        });
                    }
                    DataKind::Bulk { length, stream_id } => {
                        if self.negotiated(Cap::BulkLength32Bits) {
                            write_hdr!(wire::BulkPacketHeader {
                                endpoint: d.endpoint.raw(),
                                status: d.status as u8,
                                length: (*length as u16).into(),
                                stream_id: (*stream_id).into(),
                                length_high: ((*length >> 16) as u16).into(),
                            });
                        } else {
                            write_hdr!(wire::BulkPacketHeader16BitLength {
                                endpoint: d.endpoint.raw(),
                                status: d.status as u8,
                                length: (*length as u16).into(),
                                stream_id: (*stream_id).into(),
                            });
                        }
                    }
                    DataKind::Iso { length } => {
                        write_hdr!(wire::IsoPacketHeader {
                            endpoint: d.endpoint.raw(),
                            status: d.status as u8,
                            length: (*length).into(),
                        });
                    }
                    DataKind::Interrupt { length } => {
                        write_hdr!(wire::InterruptPacketHeader {
                            endpoint: d.endpoint.raw(),
                            status: d.status as u8,
                            length: (*length).into(),
                        });
                    }
                    DataKind::BufferedBulk { stream_id, length } => {
                        write_hdr!(wire::BufferedBulkPacketHeader {
                            stream_id: (*stream_id).into(),
                            length: (*length).into(),
                            endpoint: d.endpoint.raw(),
                            status: d.status as u8,
                        });
                    }
                }
                buf.extend_from_slice(&d.data);
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
            self.output_total_size = self.output_total_size.saturating_sub(buf.len() as u64);
            Some(buf)
        } else {
            None
        }
    }

    /// Returns an iterator that drains all pending output buffers.
    pub fn drain_output(&mut self) -> impl Iterator<Item = Bytes> + '_ {
        core::iter::from_fn(move || self.drain())
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

    pub(crate) fn parse_state(&self) -> &ParseState {
        &self.state
    }

    #[allow(dead_code)]
    pub(crate) fn input_buf(&self) -> &[u8] {
        &self.input
    }

    pub(crate) fn output_bufs(&self) -> &VecDeque<Bytes> {
        &self.output
    }

    pub(crate) fn is_using_32bit_ids(&self) -> bool {
        self.using_32bit_ids()
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
        self.output_total_size = self.output_total_size.saturating_add(buf.len() as u64);
        self.output.push_back(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::{Cap, Caps};
    use crate::packet::RequestKind;

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
            version: "test-0.1".to_string(),
            caps,
            no_hello: false,
            max_input_buffer: None,
        }
    }

    #[test]
    fn hello_roundtrip() {
        let mut host = Parser::<Host>::new(make_config());
        let mut guest = Parser::<Guest>::new(make_config());

        // Host drains its hello packet
        let host_hello = host.drain().unwrap();

        // Guest feeds it
        guest.feed(&host_hello).unwrap();

        // Guest should emit a Log (peer info) + the hello Packet
        let mut got_hello = false;
        while let Some(event) = guest.poll() {
            if let Event::Packet(packet) = event {
                if let Packet::Hello { version, caps } = *packet {
                    assert!(version.starts_with("test"));
                    assert!(caps.has(Cap::Ids64Bits));
                    got_hello = true;
                }
            }
        }
        assert!(got_hello);
    }

    #[test]
    fn partial_feed() {
        let mut host = Parser::<Host>::new(make_config());
        let mut guest = Parser::<Guest>::new(make_config());

        let host_hello = host.drain().unwrap();

        // Feed one byte at a time
        for byte in host_hello.iter() {
            guest.feed(&[*byte]).unwrap();
        }

        let mut got_hello = false;
        while let Some(event) = guest.poll() {
            if let Event::Packet(packet) = event {
                if let Packet::Hello { .. } = *packet {
                    got_hello = true;
                }
            }
        }
        assert!(got_hello);
    }

    #[test]
    fn bidirectional_hello_then_set_config() {
        let mut host = Parser::<Host>::new(make_config());
        let mut guest = Parser::<Guest>::new(make_config());

        // Exchange hellos
        let host_hello = host.drain().unwrap();
        let guest_hello = guest.drain().unwrap();

        guest.feed(&host_hello).unwrap();
        host.feed(&guest_hello).unwrap();

        // Drain events
        while guest.poll().is_some() {}
        while host.poll().is_some() {}

        // Now guest sends set_configuration (guest is NOT host, so SetConfiguration
        // is command_for_host=true when sending from guest)
        guest.send(&Packet::set_configuration(42, 1)).unwrap();

        let pkt_bytes = guest.drain().unwrap();
        host.feed(&pkt_bytes).unwrap();

        let mut found = false;
        while let Some(event) = host.poll() {
            if let Event::Packet(packet) = event {
                if let Packet::Request(ref req) = *packet {
                    if let RequestKind::SetConfiguration { configuration } = req.kind {
                        assert_eq!(req.id, 42);
                        assert_eq!(configuration, 1);
                        found = true;
                    }
                }
            }
        }
        assert!(found);
    }
}
