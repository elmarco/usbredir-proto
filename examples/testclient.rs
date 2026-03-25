use std::collections::HashMap;
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

// === UVC Constants ===

const UVC_REQ_SET_CUR: u8 = 0x01;
const UVC_REQ_GET_CUR: u8 = 0x81;
const UVC_REQ_GET_MIN: u8 = 0x82;
const UVC_REQ_GET_MAX: u8 = 0x83;
const UVC_REQ_GET_RES: u8 = 0x84;
const UVC_REQ_GET_INFO: u8 = 0x86;
const UVC_REQ_GET_DEF: u8 = 0x87;

const UVC_GET_REQUEST_TYPE: u8 = 0xA1; // device-to-host, class, interface
const UVC_SET_REQUEST_TYPE: u8 = 0x21; // host-to-device, class, interface

const UVC_VS_PROBE_CONTROL: u8 = 0x01;
const UVC_VS_COMMIT_CONTROL: u8 = 0x02;

const UVC_PROBE_COMMIT_LEN: u16 = 26;

const UVC_CLASS: u8 = 0x0E;
const UVC_SC_VIDEOCONTROL: u8 = 0x01;
const UVC_SC_VIDEOSTREAMING: u8 = 0x02;

#[derive(Debug, Clone, Copy)]
enum UvcEntity {
    CameraTerm,
    ProcUnit,
}

struct UvcControl {
    name: &'static str,
    selector: u8,
    entity: UvcEntity,
    data_len: u16,
}

const UVC_CONTROLS: &[UvcControl] = &[
    UvcControl { name: "brightness", selector: 0x02, entity: UvcEntity::ProcUnit, data_len: 2 },
    UvcControl { name: "contrast", selector: 0x03, entity: UvcEntity::ProcUnit, data_len: 2 },
    UvcControl { name: "exposure-time", selector: 0x04, entity: UvcEntity::CameraTerm, data_len: 4 },
    UvcControl { name: "focus-abs", selector: 0x06, entity: UvcEntity::CameraTerm, data_len: 2 },
    UvcControl { name: "focus-auto", selector: 0x08, entity: UvcEntity::CameraTerm, data_len: 1 },
    UvcControl { name: "ae-mode", selector: 0x02, entity: UvcEntity::CameraTerm, data_len: 1 },
];

fn find_uvc_control(name: &str) -> Option<&'static UvcControl> {
    UVC_CONTROLS.iter().find(|c| c.name.eq_ignore_ascii_case(name))
}

fn uvc_request_name(req: u8) -> &'static str {
    match req {
        UVC_REQ_SET_CUR => "SET_CUR",
        UVC_REQ_GET_CUR => "GET_CUR",
        UVC_REQ_GET_MIN => "GET_MIN",
        UVC_REQ_GET_MAX => "GET_MAX",
        UVC_REQ_GET_RES => "GET_RES",
        UVC_REQ_GET_INFO => "GET_INFO",
        UVC_REQ_GET_DEF => "GET_DEF",
        _ => "UNKNOWN",
    }
}

// === UVC State ===

struct UvcPendingRequest {
    control_name: String,
    request: u8,
    is_probe_commit: bool,
}

struct UvcFunction {
    vc_iface: u8,
    vs_iface: Option<u8>,
}

struct UvcState {
    functions: Vec<UvcFunction>,
    active: usize,
    ct_id: u8,
    pu_id: u8,
    pending: HashMap<u64, UvcPendingRequest>,
    last_probe: Option<Vec<u8>>,
}

impl UvcState {
    fn new() -> Self {
        Self {
            functions: Vec::new(),
            active: 0,
            ct_id: 1,
            pu_id: 2,
            pending: HashMap::new(),
            last_probe: None,
        }
    }

    fn vc_iface(&self) -> Option<u8> {
        self.functions.get(self.active).map(|f| f.vc_iface)
    }

    fn vs_iface(&self) -> Option<u8> {
        self.functions.get(self.active).and_then(|f| f.vs_iface)
    }

    fn entity_id(&self, entity: UvcEntity) -> u8 {
        match entity {
            UvcEntity::CameraTerm => self.ct_id,
            UvcEntity::ProcUnit => self.pu_id,
        }
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
    uvc: UvcState,
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
            uvc: UvcState::new(),
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
    let _ = writeln!(w);
    let _ = writeln!(w, "UVC commands:");
    let _ = writeln!(w, "  uvc-info                       - show detected UVC state");
    let _ = writeln!(w, "  uvc-func <index>               - switch active UVC function");
    let _ = writeln!(w, "  uvc-set-ids [ct=N] [pu=N]      - override entity IDs");
    let _ = writeln!(
        w,
        "  uvc-get <ctrl> [cur|min|max|def|res|info|all]"
    );
    let _ = writeln!(w, "  uvc-set <ctrl> <value>         - set control value");
    let _ = writeln!(
        w,
        "  uvc-probe [format=N] [frame=N] [interval=N]"
    );
    let _ = writeln!(w, "  uvc-commit                     - commit last probe");
    let _ = writeln!(
        w,
        "  uvc-stream <endpoint> [pkts] [urbs] - set alt + start iso"
    );
    let _ = writeln!(
        w,
        "  uvc-raw <get|set> <entity> <sel> <iface> <len> [data...]"
    );
}

// === UVC Interface Detection ===

fn uvc_detect_interfaces(
    w: &mut impl Write,
    uvc: &mut UvcState,
    interface_count: u32,
    interface: &[u8; 32],
    interface_class: &[u8; 32],
    interface_subclass: &[u8; 32],
) {
    uvc.functions.clear();
    uvc.active = 0;
    for i in 0..interface_count as usize {
        if interface_class[i] == UVC_CLASS && interface_subclass[i] == UVC_SC_VIDEOCONTROL {
            uvc.functions.push(UvcFunction {
                vc_iface: interface[i],
                vs_iface: None,
            });
        }
    }
    for i in 0..interface_count as usize {
        if interface_class[i] == UVC_CLASS && interface_subclass[i] == UVC_SC_VIDEOSTREAMING {
            // Associate VS with the nearest preceding VC
            if let Some(func) = uvc.functions.iter_mut().rev().find(|f| {
                f.vs_iface.is_none() && f.vc_iface < interface[i]
            }) {
                func.vs_iface = Some(interface[i]);
            }
        }
    }
    for (idx, func) in uvc.functions.iter().enumerate() {
        let _ = write!(w, "UVC function {idx}: VC interface={}", func.vc_iface);
        if let Some(vs) = func.vs_iface {
            let _ = write!(w, " VS interface={vs}");
        }
        let _ = writeln!(w);
    }
    if uvc.functions.len() > 1 {
        let _ = writeln!(w, "UVC active function: 0 (use uvc-func to switch)");
    }
}

// === UVC Commands ===

fn print_uvc_info(w: &mut impl Write, uvc: &UvcState) {
    let _ = writeln!(w, "UVC state:");
    if uvc.functions.is_empty() {
        let _ = writeln!(w, "  No UVC functions detected");
    } else {
        for (idx, func) in uvc.functions.iter().enumerate() {
            let marker = if idx == uvc.active { "*" } else { " " };
            let vs = func.vs_iface.map_or("none".to_string(), |n| n.to_string());
            let _ = writeln!(w, " {marker} function {idx}: VC={} VS={vs}", func.vc_iface);
        }
    }
    let _ = writeln!(w, "  Camera Terminal ID: {}", uvc.ct_id);
    let _ = writeln!(w, "  Processing Unit ID: {}", uvc.pu_id);
    let _ = write!(w, "  Controls:");
    for ctrl in UVC_CONTROLS {
        let _ = write!(w, " {}", ctrl.name);
    }
    let _ = writeln!(w);
}

fn parse_uvc_set_ids(w: &mut impl Write, uvc: &mut UvcState, parts: &[&str]) {
    if parts.len() < 2 {
        let _ = writeln!(w, "Usage: uvc-set-ids [ct=N] [pu=N]");
        return;
    }
    for part in &parts[1..] {
        if let Some(val) = part.strip_prefix("ct=") {
            if let Some(id) = parse_int::<u8>(val) {
                uvc.ct_id = id;
                let _ = writeln!(w, "Camera Terminal ID set to {id}");
            }
        } else if let Some(val) = part.strip_prefix("pu=") {
            if let Some(id) = parse_int::<u8>(val) {
                uvc.pu_id = id;
                let _ = writeln!(w, "Processing Unit ID set to {id}");
            }
        } else {
            let _ = writeln!(w, "Unknown parameter: {part}. Use ct=N or pu=N");
        }
    }
}

fn build_uvc_get_packets(
    client: &mut Client,
    ctrl: &UvcControl,
    requests: &[u8],
) -> Vec<Packet> {
    let vc_iface = client.uvc.vc_iface().unwrap_or(0);
    let entity_id = client.uvc.entity_id(ctrl.entity);
    let value = (ctrl.selector as u16) << 8;
    let index = ((entity_id as u16) << 8) | vc_iface as u16;

    requests
        .iter()
        .map(|&req| {
            let id = client.alloc_id();
            client.uvc.pending.insert(
                id,
                UvcPendingRequest {
                    control_name: ctrl.name.to_string(),
                    request: req,
                    is_probe_commit: false,
                },
            );
            // Endpoint 0x80 (IN) so the parser accepts empty data with length > 0
            Packet::control_packet(
                id,
                Endpoint::new(0x80),
                req,
                UVC_GET_REQUEST_TYPE,
                Status::Success,
                value,
                index,
                ctrl.data_len,
                Vec::new(),
            )
        })
        .collect()
}

fn build_uvc_set_packet(
    client: &mut Client,
    ctrl: &UvcControl,
    value_int: u64,
) -> Packet {
    let vc_iface = client.uvc.vc_iface().unwrap_or(0);
    let entity_id = client.uvc.entity_id(ctrl.entity);
    let wvalue = (ctrl.selector as u16) << 8;
    let index = ((entity_id as u16) << 8) | vc_iface as u16;

    let data: Vec<u8> = match ctrl.data_len {
        1 => vec![value_int as u8],
        2 => (value_int as u16).to_le_bytes().to_vec(),
        4 => (value_int as u32).to_le_bytes().to_vec(),
        n => value_int.to_le_bytes()[..n as usize].to_vec(),
    };

    let id = client.alloc_id();
    client.uvc.pending.insert(
        id,
        UvcPendingRequest {
            control_name: ctrl.name.to_string(),
            request: UVC_REQ_SET_CUR,
            is_probe_commit: false,
        },
    );
    Packet::control_packet(
        id,
        Endpoint::new(0),
        UVC_REQ_SET_CUR,
        UVC_SET_REQUEST_TYPE,
        Status::Success,
        wvalue,
        index,
        ctrl.data_len,
        data,
    )
}

fn build_probe_payload(format: u8, frame: u8, interval: u32) -> Vec<u8> {
    let mut buf = vec![0u8; UVC_PROBE_COMMIT_LEN as usize];
    // bmHint = 0x0000 (bytes 0-1)
    buf[2] = format; // bFormatIndex
    buf[3] = frame; // bFrameIndex
    // dwFrameInterval (bytes 4-7, little-endian)
    buf[4..8].copy_from_slice(&interval.to_le_bytes());
    buf
}

fn build_probe_packets(client: &mut Client, format: u8, frame: u8, interval: u32) -> Option<Vec<Packet>> {
    let vs_iface = client.uvc.vs_iface()?;
    let wvalue = (UVC_VS_PROBE_CONTROL as u16) << 8;
    let index = vs_iface as u16;
    let payload = build_probe_payload(format, frame, interval);

    let set_id = client.alloc_id();
    client.uvc.pending.insert(
        set_id,
        UvcPendingRequest {
            control_name: "PROBE".to_string(),
            request: UVC_REQ_SET_CUR,
            is_probe_commit: true,
        },
    );
    let set_pkt = Packet::control_packet(
        set_id,
        Endpoint::new(0),
        UVC_REQ_SET_CUR,
        UVC_SET_REQUEST_TYPE,
        Status::Success,
        wvalue,
        index,
        UVC_PROBE_COMMIT_LEN,
        payload,
    );

    let get_id = client.alloc_id();
    client.uvc.pending.insert(
        get_id,
        UvcPendingRequest {
            control_name: "PROBE".to_string(),
            request: UVC_REQ_GET_CUR,
            is_probe_commit: true,
        },
    );
    let get_pkt = Packet::control_packet(
        get_id,
        Endpoint::new(0x80),
        UVC_REQ_GET_CUR,
        UVC_GET_REQUEST_TYPE,
        Status::Success,
        wvalue,
        index,
        UVC_PROBE_COMMIT_LEN,
        Vec::new(),
    );

    Some(vec![set_pkt, get_pkt])
}

fn build_commit_packet(client: &mut Client) -> Option<Packet> {
    let vs_iface = client.uvc.vs_iface()?;
    let probe_data = client.uvc.last_probe.clone()?;
    let wvalue = (UVC_VS_COMMIT_CONTROL as u16) << 8;
    let index = vs_iface as u16;
    let len = probe_data.len() as u16;

    let id = client.alloc_id();
    client.uvc.pending.insert(
        id,
        UvcPendingRequest {
            control_name: "COMMIT".to_string(),
            request: UVC_REQ_SET_CUR,
            is_probe_commit: true,
        },
    );
    Some(Packet::control_packet(
        id,
        Endpoint::new(0),
        UVC_REQ_SET_CUR,
        UVC_SET_REQUEST_TYPE,
        Status::Success,
        wvalue,
        index,
        len,
        probe_data,
    ))
}

fn build_uvc_raw_packets(
    w: &mut impl Write,
    client: &mut Client,
    parts: &[&str],
) -> Option<Vec<Packet>> {
    if parts.len() < 6 {
        let _ = writeln!(w, "Usage: uvc-raw <get|set> <entity-id> <selector> <iface> <length> [data...]");
        return None;
    }
    let is_get = match parts[1] {
        "get" => true,
        "set" => false,
        other => {
            let _ = writeln!(w, "Expected 'get' or 'set', got '{other}'");
            return None;
        }
    };
    let entity_id: u8 = parse_int(parts[2])?;
    let selector: u8 = parse_int(parts[3])?;
    let iface: u8 = parse_int(parts[4])?;
    let length: u16 = parse_int(parts[5])?;

    let mut data = Vec::new();
    if !is_get {
        for part in &parts[6..] {
            data.push(parse_int::<u8>(part)?);
        }
    }

    let (request, requesttype) = if is_get {
        (UVC_REQ_GET_CUR, UVC_GET_REQUEST_TYPE)
    } else {
        (UVC_REQ_SET_CUR, UVC_SET_REQUEST_TYPE)
    };

    let wvalue = (selector as u16) << 8;
    let index = ((entity_id as u16) << 8) | iface as u16;
    let id = client.alloc_id();
    client.uvc.pending.insert(
        id,
        UvcPendingRequest {
            control_name: format!("raw(entity={entity_id},sel={selector:#04x})"),
            request,
            is_probe_commit: false,
        },
    );
    let ep = if is_get { 0x80 } else { 0 };
    Some(vec![Packet::control_packet(
        id,
        Endpoint::new(ep),
        request,
        requesttype,
        Status::Success,
        wvalue,
        index,
        length,
        data,
    )])
}

// === UVC Response Pretty-Printing ===

fn try_print_uvc_response(w: &mut impl Write, d: &DataPacket, uvc: &mut UvcState) -> bool {
    let pending = match uvc.pending.remove(&d.id) {
        Some(p) => p,
        None => return false,
    };

    let req_name = uvc_request_name(pending.request);

    if d.status != Status::Success {
        let _ = writeln!(
            w,
            "UVC {} {}: {:?}",
            pending.control_name, req_name, d.status
        );
        return true;
    }

    if pending.is_probe_commit {
        if pending.request == UVC_REQ_SET_CUR {
            let _ = writeln!(w, "UVC {} {}: ok", pending.control_name, req_name);
        } else {
            if pending.request == UVC_REQ_GET_CUR {
                uvc.last_probe = Some(d.data.to_vec());
            }
            print_probe_commit_struct(w, &d.data, &pending.control_name, req_name);
        }
    } else if pending.request == UVC_REQ_GET_INFO {
        print_uvc_info_bits(w, &pending.control_name, &d.data);
    } else if pending.request == UVC_REQ_SET_CUR {
        let _ = writeln!(w, "UVC {} {}: ok", pending.control_name, req_name);
    } else {
        print_uvc_control_value(w, &pending.control_name, req_name, &d.data);
    }
    true
}

fn print_uvc_control_value(w: &mut impl Write, name: &str, req_name: &str, data: &[u8]) {
    let val: i64 = match data.len() {
        1 => data[0] as i8 as i64,
        2 => i16::from_le_bytes([data[0], data[1]]) as i64,
        4 => i32::from_le_bytes([data[0], data[1], data[2], data[3]]) as i64,
        _ => {
            let _ = writeln!(w, "UVC {name} {req_name}: {:02x?}", data);
            return;
        }
    };

    // Special formatting for known controls
    let extra = match name {
        "ae-mode" => {
            let v = data[0];
            let mut modes = Vec::new();
            if v & 0x01 != 0 { modes.push("Manual"); }
            if v & 0x02 != 0 { modes.push("Auto"); }
            if v & 0x04 != 0 { modes.push("ShutterPriority"); }
            if v & 0x08 != 0 { modes.push("AperturePriority"); }
            format!(" ({})", modes.join("|"))
        }
        "focus-auto" => {
            format!(" ({})", if data[0] != 0 { "On" } else { "Off" })
        }
        _ => String::new(),
    };

    let _ = writeln!(
        w,
        "UVC {name} {req_name}: {val} ({:#0width$x}){extra}",
        val,
        width = data.len() * 2 + 2,
    );
}

fn print_probe_commit_struct(w: &mut impl Write, data: &[u8], label: &str, req_name: &str) {
    if data.len() < 26 {
        let _ = writeln!(w, "UVC {label} {req_name}: short response ({} bytes): {:02x?}", data.len(), data);
        return;
    }

    let hint = u16::from_le_bytes([data[0], data[1]]);
    let format_index = data[2];
    let frame_index = data[3];
    let frame_interval = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let key_frame_rate = u16::from_le_bytes([data[8], data[9]]);
    let p_frame_rate = u16::from_le_bytes([data[10], data[11]]);
    let comp_quality = u16::from_le_bytes([data[12], data[13]]);
    let comp_window_size = u16::from_le_bytes([data[14], data[15]]);
    let delay = u16::from_le_bytes([data[16], data[17]]);
    let max_video_frame_size = u32::from_le_bytes([data[18], data[19], data[20], data[21]]);
    let max_payload_transfer_size = u32::from_le_bytes([data[22], data[23], data[24], data[25]]);

    let fps = if frame_interval > 0 {
        10_000_000.0 / frame_interval as f64
    } else {
        0.0
    };

    let _ = writeln!(w, "UVC {label} {req_name}:");
    let _ = writeln!(w, "  bmHint:                       {hint:#06x}");
    let _ = writeln!(w, "  bFormatIndex:                 {format_index}");
    let _ = writeln!(w, "  bFrameIndex:                  {frame_index}");
    let _ = writeln!(w, "  dwFrameInterval:              {frame_interval} ({fps:.1} fps)");
    let _ = writeln!(w, "  wKeyFrameRate:                {key_frame_rate}");
    let _ = writeln!(w, "  wPFrameRate:                  {p_frame_rate}");
    let _ = writeln!(w, "  wCompQuality:                 {comp_quality}");
    let _ = writeln!(w, "  wCompWindowSize:              {comp_window_size}");
    let _ = writeln!(w, "  wDelay:                       {delay}");
    let _ = writeln!(w, "  dwMaxVideoFrameSize:          {max_video_frame_size}");
    let _ = writeln!(w, "  dwMaxPayloadTransferSize:     {max_payload_transfer_size}");
}

fn print_uvc_info_bits(w: &mut impl Write, name: &str, data: &[u8]) {
    if data.is_empty() {
        let _ = writeln!(w, "UVC {name} GET_INFO: (empty)");
        return;
    }
    let bits = data[0];
    let _ = writeln!(
        w,
        "UVC {name} GET_INFO: {bits:#04x} ({}{}{}{}{})",
        if bits & 0x01 != 0 { "supports_get " } else { "" },
        if bits & 0x02 != 0 { "supports_set " } else { "" },
        if bits & 0x04 != 0 { "disabled " } else { "" },
        if bits & 0x08 != 0 { "auto_update " } else { "" },
        if bits & 0x10 != 0 { "async" } else { "" },
    );
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
        "uvc-info" => print_uvc_info(w, &client.uvc),
        "uvc-set-ids" => parse_uvc_set_ids(w, &mut client.uvc, &parts),
        "uvc-func" => {
            if parts.len() < 2 {
                let _ = writeln!(w, "Usage: uvc-func <index>");
            } else if let Some(idx) = parse_int::<usize>(parts[1]) {
                if idx < client.uvc.functions.len() {
                    client.uvc.active = idx;
                    let func = &client.uvc.functions[idx];
                    let vs = func.vs_iface.map_or("none".to_string(), |n| n.to_string());
                    let _ = writeln!(w, "Active UVC function: {idx} (VC={} VS={vs})", func.vc_iface);
                } else {
                    let _ = writeln!(w, "Invalid index. {} function(s) available.", client.uvc.functions.len());
                }
            }
        }
        "uvc-get" => {
            if parts.len() < 2 {
                let _ = writeln!(w, "Usage: uvc-get <control> [cur|min|max|def|res|info|all]");
            } else if let Some(ctrl) = find_uvc_control(parts[1]) {
                let query = parts.get(2).copied().unwrap_or("cur");
                let requests: Vec<u8> = match query {
                    "cur" => vec![UVC_REQ_GET_CUR],
                    "min" => vec![UVC_REQ_GET_MIN],
                    "max" => vec![UVC_REQ_GET_MAX],
                    "def" => vec![UVC_REQ_GET_DEF],
                    "res" => vec![UVC_REQ_GET_RES],
                    "info" => vec![UVC_REQ_GET_INFO],
                    "all" => vec![UVC_REQ_GET_CUR, UVC_REQ_GET_MIN, UVC_REQ_GET_MAX, UVC_REQ_GET_DEF],
                    other => {
                        let _ = writeln!(w, "Unknown query '{other}'. Use cur|min|max|def|res|info|all");
                        vec![]
                    }
                };
                if !requests.is_empty() {
                    let packets = build_uvc_get_packets(client, ctrl, &requests);
                    for pkt in packets {
                        if let Err(e) = framed.send(pkt).await {
                            let _ = writeln!(w, "Send error: {e}");
                            return false;
                        }
                    }
                }
            } else {
                let _ = writeln!(w, "Unknown control '{}'. See uvc-info for available controls.", parts[1]);
            }
        }
        "uvc-set" => {
            if parts.len() < 3 {
                let _ = writeln!(w, "Usage: uvc-set <control> <value>");
            } else if let Some(ctrl) = find_uvc_control(parts[1]) {
                if let Some(val) = parse_int::<u64>(parts[2]) {
                    let pkt = build_uvc_set_packet(client, ctrl, val);
                    if let Err(e) = framed.send(pkt).await {
                        let _ = writeln!(w, "Send error: {e}");
                        return false;
                    }
                } else {
                    let _ = writeln!(w, "Invalid value: {}", parts[2]);
                }
            } else {
                let _ = writeln!(w, "Unknown control '{}'. See uvc-info for available controls.", parts[1]);
            }
        }
        "uvc-probe" => {
            let mut format: u8 = 1;
            let mut frame: u8 = 1;
            let mut interval: u32 = 333333;
            for part in &parts[1..] {
                if let Some(v) = part.strip_prefix("format=") {
                    format = parse_int(v).unwrap_or(format);
                } else if let Some(v) = part.strip_prefix("frame=") {
                    frame = parse_int(v).unwrap_or(frame);
                } else if let Some(v) = part.strip_prefix("interval=") {
                    interval = parse_int(v).unwrap_or(interval);
                }
            }
            match build_probe_packets(client, format, frame, interval) {
                Some(packets) => {
                    let fps = 10_000_000.0 / interval as f64;
                    let _ = writeln!(w, "Probing: format={format} frame={frame} interval={interval} ({fps:.1} fps)");
                    for pkt in packets {
                        if let Err(e) = framed.send(pkt).await {
                            let _ = writeln!(w, "Send error: {e}");
                            return false;
                        }
                    }
                }
                None => {
                    let _ = writeln!(w, "No VS interface detected. Use uvc-info to check.");
                }
            }
        }
        "uvc-commit" => {
            match build_commit_packet(client) {
                Some(pkt) => {
                    let _ = writeln!(w, "Committing last probe result...");
                    if let Err(e) = framed.send(pkt).await {
                        let _ = writeln!(w, "Send error: {e}");
                        return false;
                    }
                }
                None => {
                    if client.uvc.vs_iface().is_none() {
                        let _ = writeln!(w, "No VS interface detected.");
                    } else {
                        let _ = writeln!(w, "No probe result to commit. Run uvc-probe first.");
                    }
                }
            }
        }
        "uvc-stream" => {
            if parts.len() < 2 {
                let _ = writeln!(w, "Usage: uvc-stream <endpoint> [pkts] [urbs]");
            } else if let Some(ep) = parse_int::<u8>(parts[1]) {
                let pkts: u8 = parts.get(2).and_then(|s| parse_int(s)).unwrap_or(8);
                let urbs: u8 = parts.get(3).and_then(|s| parse_int(s)).unwrap_or(4);
                if let Some(vs_iface) = client.uvc.vs_iface() {
                    let alt_id = client.alloc_id();
                    let _ = writeln!(w, "Setting alt=1 on VS interface {vs_iface}");
                    if let Err(e) = framed.send(Packet::set_alt_setting(alt_id, vs_iface, 1)).await {
                        let _ = writeln!(w, "Send error: {e}");
                        return false;
                    }
                    let iso_id = client.alloc_id();
                    let _ = writeln!(w, "Starting iso stream on endpoint {ep:#04x} (pkts={pkts}, urbs={urbs})");
                    if let Err(e) = framed
                        .send(Packet::start_iso_stream(iso_id, Endpoint::new(ep), pkts, urbs))
                        .await
                    {
                        let _ = writeln!(w, "Send error: {e}");
                        return false;
                    }
                } else {
                    let _ = writeln!(w, "No VS interface detected.");
                }
            }
        }
        "uvc-raw" => {
            if let Some(packets) = build_uvc_raw_packets(w, client, &parts) {
                for pkt in packets {
                    if let Err(e) = framed.send(pkt).await {
                        let _ = writeln!(w, "Send error: {e}");
                        return false;
                    }
                }
            }
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
            uvc_detect_interfaces(
                w,
                &mut client.uvc,
                info.interface_count,
                &info.interface,
                &info.interface_class,
                &info.interface_subclass,
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
            if try_print_uvc_response(w, d, &mut client.uvc) {
                // handled by UVC pretty-printer
            } else if matches!(d.kind, DataKind::Control { .. }) {
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
