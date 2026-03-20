//! Tokio codec for framing usbredir over an `AsyncRead + AsyncWrite` transport.
//!
//! Enable with the `tokio` feature flag.
//!
//! # Example
//!
//! ```ignore
//! use tokio::net::TcpStream;
//! use tokio_util::codec::Framed;
//! use usbredir_proto::{Packet, ParserConfig, Host, codec::UsbredirCodec};
//!
//! let stream = TcpStream::connect("127.0.0.1:4000").await?;
//! let codec = UsbredirCodec::<Host>::new(ParserConfig::new("my-app 1.0"));
//! let mut framed = Framed::new(stream, codec);
//! ```

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::{Error, Result};
use crate::packet::Packet;
use crate::parser::{Parser, ParserConfig, Role};

/// A [`tokio_util::codec`] implementation wrapping [`Parser`].
///
/// Decodes inbound bytes into [`Packet`]s and encodes outbound [`Packet`]s.
pub struct UsbredirCodec<R: Role> {
    parser: Parser<R>,
}

impl<R: Role> UsbredirCodec<R> {
    /// Create a new codec with the given config.
    pub fn new(config: ParserConfig) -> Self {
        Self {
            parser: Parser::new(config),
        }
    }

    /// Access the underlying parser (e.g. to check capabilities).
    pub fn parser(&self) -> &Parser<R> {
        &self.parser
    }

    /// Mutable access to the underlying parser.
    pub fn parser_mut(&mut self) -> &mut Parser<R> {
        &mut self.parser
    }
}

impl<R: Role> Decoder for UsbredirCodec<R> {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if !src.is_empty() {
            let data = src.split();
            self.parser.feed(&data);
        }
        loop {
            match self.parser.poll() {
                Some(Ok(p)) => return Ok(Some(*p)),
                Some(Err(e)) => return Err(e),
                None => return Ok(None),
            }
        }
    }
}

impl<R: Role> Encoder<Packet> for UsbredirCodec<R> {
    type Error = Error;

    fn encode(&mut self, item: Packet, dst: &mut BytesMut) -> Result<()> {
        self.parser.send(&item)?;
        while let Some(chunk) = self.parser.drain() {
            dst.extend_from_slice(&chunk);
        }
        Ok(())
    }
}
