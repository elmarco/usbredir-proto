use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use crossterm::{cursor, execute, style, terminal};
use futures::{SinkExt, StreamExt};
use rustyline_async::{Readline, ReadlineEvent, SharedWriter};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use usbredir_proto::codec::UsbredirCodec;
use usbredir_proto::{
    Cap, DataKind, DataPacket, Endpoint, Guest, Packet, ParserConfig, RequestKind, Status,
    TransferType,
};

const DEFAULT_PORT: u16 = 4000;

fn history_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("usbredir")
        .join("testclient.history")
}

fn load_history(rl: &mut Readline) {
    let path = history_path();
    if let Ok(contents) = std::fs::read_to_string(&path) {
        let entries = contents.lines().map(String::from);
        rl.set_history_entries(entries);
    }
}

fn save_history(rl: &Readline) {
    let path = history_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let entries: Vec<&str> = rl.get_history_entries().iter().map(|s| s.as_str()).collect();
    let _ = std::fs::write(&path, entries.join("\n"));
}

#[derive(Clone)]
struct ByteCounters {
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
}

impl ByteCounters {
    fn new() -> Self {
        Self {
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
        }
    }
}

struct CountingStream {
    inner: TcpStream,
    counters: ByteCounters,
}

impl CountingStream {
    fn new(inner: TcpStream, counters: ByteCounters) -> Self {
        Self { inner, counters }
    }
}

impl AsyncRead for CountingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut me.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            me.counters.rx.fetch_add(n as u64, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        let result = Pin::new(&mut me.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            me.counters.tx.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    WaitHello,
    WaitGetConfig,
    WaitSetConfig,
    WaitGetAlt,
    WaitSetAlt,
    Interactive,
}

struct Client {
    phase: Phase,
    next_id: u64,
    get_config_id: u64,
    set_config_id: u64,
    get_alt_id: u64,
    set_alt_id: u64,
}

impl Client {
    fn new() -> Self {
        Self {
            phase: Phase::WaitHello,
            next_id: 1,
            get_config_id: 0,
            set_config_id: 0,
            get_alt_id: 0,
            set_alt_id: 0,
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

enum InputEvent {
    Line(String),
    Eof,
    Interrupted,
    Error(String),
}

enum Output {
    Shared(SharedWriter),
    Stdout(std::io::Stdout),
}

impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Output::Shared(w) => w.write(buf),
            Output::Stdout(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Output::Shared(w) => w.flush(),
            Output::Stdout(w) => w.flush(),
        }
    }
}

fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_000_000.0 {
        format!("{:.1}MB/s", bytes_per_sec / 1_000_000.0)
    } else if bytes_per_sec >= 1_000.0 {
        format!("{:.1}kB/s", bytes_per_sec / 1_000.0)
    } else {
        format!("{:.0}B/s", bytes_per_sec)
    }
}

fn print_device_connect(w: &mut impl Write, info: &usbredir_proto::DeviceConnectInfo) {
    let _ = writeln!(
        w,
        "DeviceConnect: speed={:?} class={:#04x} subclass={:#04x} protocol={:#04x} \
         vendor={:#06x} product={:#06x} version_bcd={:#06x}",
        info.speed,
        info.device_class,
        info.device_subclass,
        info.device_protocol,
        info.vendor_id,
        info.product_id,
        info.device_version_bcd,
    );
}

fn print_interface_info(
    w: &mut impl Write,
    interface_count: u32,
    interface: &[u8; 32],
    interface_class: &[u8; 32],
    interface_subclass: &[u8; 32],
    interface_protocol: &[u8; 32],
) {
    let _ = writeln!(w, "InterfaceInfo: {interface_count} interface(s)");
    for i in 0..interface_count as usize {
        let _ = writeln!(
            w,
            "  iface {}: number={} class={:#04x} subclass={:#04x} protocol={:#04x}",
            i, interface[i], interface_class[i], interface_subclass[i], interface_protocol[i],
        );
    }
}

fn print_ep_info(
    w: &mut impl Write,
    ep_type: &[TransferType; 32],
    interval: &[u8; 32],
    interface: &[u8; 32],
    max_packet_size: &[u16; 32],
) {
    let _ = writeln!(w, "EpInfo:");
    for i in 0..32 {
        if ep_type[i] == TransferType::Invalid {
            continue;
        }
        let dir = if i >= 16 { "IN" } else { "OUT" };
        let num = i % 16;
        let _ = writeln!(
            w,
            "  ep {num:2} {dir:3}: type={:?} interval={} interface={} max_packet_size={}",
            ep_type[i], interval[i], interface[i], max_packet_size[i],
        );
    }
}

fn print_control_response(w: &mut impl Write, d: &DataPacket) {
    if let DataKind::Control {
        request,
        requesttype,
        value,
        index,
        length,
    } = &d.kind
    {
        let _ = writeln!(
            w,
            "ControlPacket: id={} endpoint={} status={:?} request={} requesttype={:#04x} \
             value={} index={} length={} data_len={}",
            d.id,
            d.endpoint,
            d.status,
            request,
            requesttype,
            value,
            index,
            length,
            d.data.len(),
        );
        if !d.data.is_empty() {
            let _ = writeln!(w, "  data: {:02x?}", d.data.as_ref());
        }
    }
}

fn print_help(w: &mut impl Write) {
    let _ = writeln!(w, "Commands:");
    let _ = writeln!(
        w,
        "  ctrl <endpoint> <request> <requesttype> <value> <index> <length> [data...]"
    );
    let _ = writeln!(w, "  alt <interface> <alt>          - set alt setting");
    let _ = writeln!(
        w,
        "  int_start <endpoint>           - start interrupt receiving"
    );
    let _ = writeln!(
        w,
        "  int_stop <endpoint>            - stop interrupt receiving"
    );
    let _ = writeln!(
        w,
        "  iso_start <endpoint> <pkts> <urbs> - start iso stream"
    );
    let _ = writeln!(w, "  iso_stop <endpoint>            - stop iso stream");
    let _ = writeln!(
        w,
        "  wait <seconds>                 - wait and print incoming data"
    );
    let _ = writeln!(w, "  help");
    let _ = writeln!(w, "  quit");
}

fn parse_ctrl_command(
    w: &mut impl Write,
    client: &mut Client,
    parts: &[&str],
) -> Option<Packet> {
    if parts.len() < 7 {
        let _ = writeln!(
            w,
            "Usage: ctrl <endpoint> <request> <requesttype> <value> <index> <length> [data...]"
        );
        return None;
    }

    let parse_u8 = |s: &str| -> Option<u8> { parse_int(s) };
    let parse_u16 = |s: &str| -> Option<u16> { parse_int(s) };

    let endpoint: u8 = parse_u8(parts[1])?;
    let request: u8 = parse_u8(parts[2])?;
    let requesttype: u8 = parse_u8(parts[3])?;
    let value: u16 = parse_u16(parts[4])?;
    let index: u16 = parse_u16(parts[5])?;
    let length: u16 = parse_u16(parts[6])?;

    let mut data = Vec::new();
    for part in &parts[7..] {
        if let Some(b) = parse_u8(part) {
            data.push(b);
        } else {
            return None;
        }
    }

    let id = client.alloc_id();
    Some(Packet::control_packet(
        id,
        Endpoint::new(endpoint),
        request,
        requesttype,
        Status::Success,
        value,
        index,
        length,
        data,
    ))
}

fn parse_int<T: std::str::FromStr + TryFrom<u64>>(s: &str) -> Option<T>
where
    u64: TryFrom<T>,
{
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
            .ok()
            .and_then(|v| T::try_from(v).ok())
    } else {
        s.parse().ok()
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <server> [port]", args[0]);
        process::exit(1);
    }

    let server = &args[1];
    let port: u16 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let addr = format!("{server}:{port}");
    println!("Connecting to {addr}...");

    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to connect to {addr}: {e}");
            process::exit(1);
        }
    };
    println!("Connected.");

    let counters = ByteCounters::new();
    let stream = CountingStream::new(stream, counters.clone());

    let config = ParserConfig::new("usbredir-testclient-rs 0.1")
        .cap(Cap::EpInfoMaxPacketSize)
        .cap(Cap::Ids64Bits);

    let codec = UsbredirCodec::<Guest>::new(config);
    let mut framed = Framed::new(stream, codec);

    let interactive = std::io::stdin().is_terminal();

    let mut rl;
    let mut lines;
    let mut w;

    if interactive {
        let (readline, writer) = match Readline::new("usbredir> ".to_owned()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to initialize readline: {e}");
                process::exit(1);
            }
        };
        let mut readline = readline;
        load_history(&mut readline);
        rl = Some(readline);
        lines = None;
        w = Output::Shared(writer);
    } else {
        rl = None;
        lines = Some(BufReader::new(tokio::io::stdin()).lines());
        w = Output::Stdout(std::io::stdout());
    }

    let mut client = Client::new();
    let mut pending_commands: std::collections::VecDeque<String> =
        std::collections::VecDeque::new();
    let mut stdin_eof = false;

    let mut stats_interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    stats_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prev_rx: u64 = 0;
    let mut prev_tx: u64 = 0;

    loop {
        let input_event = tokio::select! {
            result = framed.next() => {
                match result {
                    Some(Ok(packet)) => {
                        let (responses, disconnect) = handle_packet(&mut client, &packet, &mut w);
                        if let Some(responses) = responses {
                            for pkt in responses {
                                if let Err(e) = framed.send(pkt).await {
                                    let _ = writeln!(w, "Send error: {e}");
                                    break;
                                }
                            }
                        }
                        if disconnect {
                            break;
                        }
                        if client.phase == Phase::Interactive
                            && !drain_pending(&mut client, &mut framed, &mut pending_commands, stdin_eof, &mut w).await {
                            break;
                        }
                        continue;
                    }
                    Some(Err(e)) => {
                        let _ = writeln!(w, "Protocol error: {e}");
                        continue;
                    }
                    None => {
                        let _ = writeln!(w, "Connection closed.");
                        break;
                    }
                }
            }
            result = async { rl.as_mut().unwrap().readline().await }, if !stdin_eof && rl.is_some() => {
                match result {
                    Ok(ReadlineEvent::Line(line)) => {
                        rl.as_mut().unwrap().add_history_entry(line.clone());
                        InputEvent::Line(line)
                    }
                    Ok(ReadlineEvent::Eof) => InputEvent::Eof,
                    Ok(ReadlineEvent::Interrupted) => InputEvent::Interrupted,
                    Err(e) => InputEvent::Error(e.to_string()),
                }
            }
            result = async { lines.as_mut().unwrap().next_line().await }, if !stdin_eof && lines.is_some() => {
                match result {
                    Ok(Some(line)) => InputEvent::Line(line),
                    Ok(None) => InputEvent::Eof,
                    Err(e) => InputEvent::Error(e.to_string()),
                }
            }
            _ = stats_interval.tick(), if interactive => {
                let rx = counters.rx.load(Ordering::Relaxed);
                let tx = counters.tx.load(Ordering::Relaxed);
                let rx_rate = rx.saturating_sub(prev_rx) as f64;
                let tx_rate = tx.saturating_sub(prev_tx) as f64;
                prev_rx = rx;
                prev_tx = tx;
                let stats = format!("↓{} ↑{}", format_rate(rx_rate), format_rate(tx_rate));
                if let Ok((term_w, _)) = terminal::size() {
                    let col = (term_w as usize).saturating_sub(stats.len());
                    let mut stdout = std::io::stdout();
                    let _ = execute!(
                        stdout,
                        cursor::SavePosition,
                        cursor::MoveToColumn(col as u16),
                        style::SetForegroundColor(style::Color::DarkGrey),
                        style::Print(&stats),
                        style::ResetColor,
                        cursor::RestorePosition,
                    );
                }
                continue;
            }
        };

        match input_event {
            InputEvent::Line(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if client.phase == Phase::Interactive {
                    if !process_command(&mut client, &mut framed, &line, &mut w).await {
                        break;
                    }
                } else {
                    pending_commands.push_back(line);
                }
            }
            InputEvent::Eof => {
                if client.phase == Phase::Interactive || pending_commands.is_empty() {
                    let _ = writeln!(w, "EOF on stdin.");
                    break;
                }
                stdin_eof = true;
            }
            InputEvent::Interrupted => {
                let _ = writeln!(w, "Interrupted.");
                break;
            }
            InputEvent::Error(e) => {
                let _ = writeln!(w, "Input error: {e}");
                break;
            }
        }
    }

    if let Some(ref rl) = rl {
        save_history(rl);
    }
}

async fn drain_pending(
    client: &mut Client,
    framed: &mut Framed<CountingStream, UsbredirCodec<Guest>>,
    pending: &mut std::collections::VecDeque<String>,
    stdin_eof: bool,
    w: &mut impl Write,
) -> bool {
    while let Some(line) = pending.pop_front() {
        if !process_command(client, framed, &line, w).await {
            return false;
        }
    }
    if stdin_eof {
        let _ = writeln!(w, "EOF on stdin.");
        return false;
    }
    true
}

async fn process_command(
    client: &mut Client,
    framed: &mut Framed<CountingStream, UsbredirCodec<Guest>>,
    line: &str,
    w: &mut impl Write,
) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts[0] {
        "quit" | "exit" => {
            let _ = writeln!(w, "Bye.");
            return false;
        }
        "help" => print_help(w),
        "ctrl" => {
            if let Some(pkt) = parse_ctrl_command(w, client, &parts) {
                if let Err(e) = framed.send(pkt).await {
                    let _ = writeln!(w, "Send error: {e}");
                    return false;
                }
            }
        }
        "alt" => {
            if parts.len() < 3 {
                let _ = writeln!(w, "Usage: alt <interface> <alt>");
            } else if let (Some(iface), Some(alt)) =
                (parse_int::<u8>(parts[1]), parse_int::<u8>(parts[2]))
            {
                let id = client.alloc_id();
                let _ = writeln!(w, "Sending SetAltSetting(interface={iface}, alt={alt})");
                if let Err(e) = framed.send(Packet::set_alt_setting(id, iface, alt)).await {
                    let _ = writeln!(w, "Send error: {e}");
                    return false;
                }
            }
        }
        "int_start" => {
            if parts.len() < 2 {
                let _ = writeln!(w, "Usage: int_start <endpoint>");
            } else if let Some(ep) = parse_int::<u8>(parts[1]) {
                let id = client.alloc_id();
                let _ = writeln!(w, "Sending StartInterruptReceiving(endpoint={ep:#04x})");
                if let Err(e) = framed
                    .send(Packet::start_interrupt_receiving(id, Endpoint::new(ep)))
                    .await
                {
                    let _ = writeln!(w, "Send error: {e}");
                    return false;
                }
            }
        }
        "int_stop" => {
            if parts.len() < 2 {
                let _ = writeln!(w, "Usage: int_stop <endpoint>");
            } else if let Some(ep) = parse_int::<u8>(parts[1]) {
                let id = client.alloc_id();
                let _ = writeln!(w, "Sending StopInterruptReceiving(endpoint={ep:#04x})");
                if let Err(e) = framed
                    .send(Packet::stop_interrupt_receiving(id, Endpoint::new(ep)))
                    .await
                {
                    let _ = writeln!(w, "Send error: {e}");
                    return false;
                }
            }
        }
        "iso_start" => {
            if parts.len() < 4 {
                let _ = writeln!(w, "Usage: iso_start <endpoint> <pkts_per_urb> <no_urbs>");
            } else if let (Some(ep), Some(pkts), Some(urbs)) = (
                parse_int::<u8>(parts[1]),
                parse_int::<u8>(parts[2]),
                parse_int::<u8>(parts[3]),
            ) {
                let id = client.alloc_id();
                let _ = writeln!(
                    w,
                    "Sending StartIsoStream(endpoint={ep:#04x}, pkts={pkts}, urbs={urbs})"
                );
                if let Err(e) = framed
                    .send(Packet::start_iso_stream(id, Endpoint::new(ep), pkts, urbs))
                    .await
                {
                    let _ = writeln!(w, "Send error: {e}");
                    return false;
                }
            }
        }
        "iso_stop" => {
            if parts.len() < 2 {
                let _ = writeln!(w, "Usage: iso_stop <endpoint>");
            } else if let Some(ep) = parse_int::<u8>(parts[1]) {
                let id = client.alloc_id();
                let _ = writeln!(w, "Sending StopIsoStream(endpoint={ep:#04x})");
                if let Err(e) = framed
                    .send(Packet::stop_iso_stream(id, Endpoint::new(ep)))
                    .await
                {
                    let _ = writeln!(w, "Send error: {e}");
                    return false;
                }
            }
        }
        "wait" => {
            let secs: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);
            let _ = writeln!(w, "Waiting {secs}s for incoming data...");
            let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(secs);
            let mut count = 0usize;
            let mut bytes = 0usize;
            loop {
                tokio::select! {
                    result = framed.next() => {
                        match result {
                            Some(Ok(ref packet)) => {
                                if let Packet::Data(d) = packet {
                                    bytes += d.data.len();
                                }
                                count += 1;
                                handle_packet(client, packet, w);
                            }
                            Some(Err(e)) => {
                                let _ = writeln!(w, "Protocol error: {e}");
                            }
                            None => {
                                let _ = writeln!(w, "Connection closed.");
                                return false;
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        break;
                    }
                }
            }
            let _ = writeln!(w, "Received {count} packets ({bytes} data bytes) in {secs}s");
        }
        other => {
            let _ = writeln!(w, "Unknown command: {other}. Type 'help' for help.");
        }
    }
    true
}

fn handle_packet(
    client: &mut Client,
    packet: &Packet,
    w: &mut impl Write,
) -> (Option<Vec<Packet>>, bool) {
    match packet {
        Packet::Hello { version, caps } => {
            let _ = writeln!(w, "Hello from server: version={version:?}, caps=[{caps}]");
            if client.phase != Phase::WaitHello {
                let _ = writeln!(w, "Unexpected Hello");
                return (None, false);
            }

            let reset_id = client.alloc_id();
            client.get_config_id = client.alloc_id();
            client.phase = Phase::WaitGetConfig;

            let _ = writeln!(w, "Sending Reset + GetConfiguration");
            (
                Some(vec![
                    Packet::reset(reset_id),
                    Packet::get_configuration(client.get_config_id),
                ]),
                false,
            )
        }

        Packet::Request(req) => match &req.kind {
            RequestKind::ConfigurationStatus {
                status,
                configuration,
            } => {
                let _ = writeln!(
                    w,
                    "ConfigurationStatus: id={} status={status:?} configuration={configuration}",
                    req.id
                );

                match client.phase {
                    Phase::WaitGetConfig if req.id == client.get_config_id => {
                        client.set_config_id = client.alloc_id();
                        client.phase = Phase::WaitSetConfig;
                        let _ = writeln!(
                            w,
                            "Sending SetConfiguration(config={configuration})"
                        );
                        (
                            Some(vec![Packet::set_configuration(
                                client.set_config_id,
                                *configuration,
                            )]),
                            false,
                        )
                    }
                    Phase::WaitSetConfig if req.id == client.set_config_id => {
                        client.get_alt_id = client.alloc_id();
                        client.phase = Phase::WaitGetAlt;
                        let _ = writeln!(w, "Sending GetAltSetting(interface=0)");
                        (
                            Some(vec![Packet::get_alt_setting(client.get_alt_id, 0)]),
                            false,
                        )
                    }
                    _ => (None, false),
                }
            }

            RequestKind::AltSettingStatus {
                status,
                interface,
                alt,
            } => {
                let _ = writeln!(
                    w,
                    "AltSettingStatus: id={} status={status:?} interface={interface} alt={alt}",
                    req.id
                );

                match client.phase {
                    Phase::WaitGetAlt if req.id == client.get_alt_id => {
                        client.set_alt_id = client.alloc_id();
                        client.phase = Phase::WaitSetAlt;
                        let _ = writeln!(
                            w,
                            "Sending SetAltSetting(interface={interface}, alt={alt})"
                        );
                        (
                            Some(vec![Packet::set_alt_setting(
                                client.set_alt_id,
                                *interface,
                                *alt,
                            )]),
                            false,
                        )
                    }
                    Phase::WaitSetAlt if req.id == client.set_alt_id => {
                        client.phase = Phase::Interactive;
                        let _ = writeln!(w, "Handshake complete. Entering interactive mode.");
                        print_help(w);
                        (None, false)
                    }
                    _ => (None, false),
                }
            }

            other => {
                let _ = writeln!(w, "Request: {other}");
                (None, false)
            }
        },

        Packet::DeviceConnect(info) => {
            print_device_connect(w, info);
            (None, false)
        }

        Packet::DeviceDisconnect => {
            let _ = writeln!(w, "DeviceDisconnect");
            (None, true)
        }

        Packet::InterfaceInfo(info) => {
            print_interface_info(
                w,
                info.interface_count,
                &info.interface,
                &info.interface_class,
                &info.interface_subclass,
                &info.interface_protocol,
            );
            (None, false)
        }

        Packet::EpInfo(info) => {
            print_ep_info(
                w,
                &info.ep_type,
                &info.interval,
                &info.interface,
                &info.max_packet_size,
            );
            (None, false)
        }

        Packet::Data(d) => {
            if matches!(d.kind, DataKind::Control { .. }) {
                print_control_response(w, d);
            } else {
                let _ = writeln!(w, "Data: {d}");
            }
            (None, false)
        }

        other => {
            let _ = writeln!(w, "Received: {other}");
            (None, false)
        }
    }
}
