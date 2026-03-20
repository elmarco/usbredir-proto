use std::process;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use usbredir_proto::codec::UsbredirCodec;
use usbredir_proto::{
    Cap, DataKind, DataPacket, Endpoint, Guest, Packet, ParserConfig, RequestKind, Status,
    TransferType,
};

const DEFAULT_PORT: u16 = 4000;

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

fn print_device_connect(info: &usbredir_proto::DeviceConnectInfo) {
    println!(
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
    interface_count: u32,
    interface: &[u8; 32],
    interface_class: &[u8; 32],
    interface_subclass: &[u8; 32],
    interface_protocol: &[u8; 32],
) {
    println!("InterfaceInfo: {interface_count} interface(s)");
    for i in 0..interface_count as usize {
        println!(
            "  iface {}: number={} class={:#04x} subclass={:#04x} protocol={:#04x}",
            i, interface[i], interface_class[i], interface_subclass[i], interface_protocol[i],
        );
    }
}

fn print_ep_info(
    ep_type: &[TransferType; 32],
    interval: &[u8; 32],
    interface: &[u8; 32],
    max_packet_size: &[u16; 32],
) {
    println!("EpInfo:");
    for i in 0..32 {
        if ep_type[i] == TransferType::Invalid {
            continue;
        }
        let dir = if i >= 16 { "IN" } else { "OUT" };
        let num = i % 16;
        println!(
            "  ep {num:2} {dir:3}: type={:?} interval={} interface={} max_packet_size={}",
            ep_type[i], interval[i], interface[i], max_packet_size[i],
        );
    }
}

fn print_control_response(d: &DataPacket) {
    if let DataKind::Control {
        request,
        requesttype,
        value,
        index,
        length,
    } = &d.kind
    {
        println!(
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
            println!("  data: {:02x?}", d.data.as_ref());
        }
    }
}

fn print_help() {
    println!("Commands:");
    println!("  ctrl <endpoint> <request> <requesttype> <value> <index> <length> [data...]");
    println!("  alt <interface> <alt>          - set alt setting");
    println!("  int_start <endpoint>           - start interrupt receiving");
    println!("  int_stop <endpoint>            - stop interrupt receiving");
    println!("  iso_start <endpoint> <pkts> <urbs> - start iso stream");
    println!("  iso_stop <endpoint>            - stop iso stream");
    println!("  wait <seconds>                 - wait and print incoming data");
    println!("  help");
    println!("  quit");
}

fn parse_ctrl_command(client: &mut Client, parts: &[&str]) -> Option<Packet> {
    if parts.len() < 7 {
        eprintln!("Usage: ctrl <endpoint> <request> <requesttype> <value> <index> <length> [data...]");
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

    let config = ParserConfig::new("usbredir-testclient-rs 0.1")
        .cap(Cap::EpInfoMaxPacketSize)
        .cap(Cap::Ids64Bits);

    let codec = UsbredirCodec::<Guest>::new(config);
    let mut framed = Framed::new(stream, codec);

    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    let mut client = Client::new();
    let mut pending_commands: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut stdin_eof = false;

    loop {
        tokio::select! {
            result = framed.next() => {
                match result {
                    Some(Ok(packet)) => {
                        if let Some(responses) = handle_packet(&mut client, &packet) {
                            for pkt in responses {
                                if let Err(e) = framed.send(pkt).await {
                                    eprintln!("Send error: {e}");
                                    return;
                                }
                            }
                        }
                        if client.phase == Phase::Interactive {
                            if !drain_pending(&mut client, &mut framed, &mut pending_commands, stdin_eof).await {
                                return;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("Protocol error: {e}");
                    }
                    None => {
                        println!("Connection closed.");
                        return;
                    }
                }
            }
            result = lines.next_line(), if !stdin_eof => {
                match result {
                    Ok(Some(line)) => {
                        let line = line.trim().to_string();
                        if line.is_empty() {
                            continue;
                        }
                        if client.phase == Phase::Interactive {
                            if !process_command(&mut client, &mut framed, &line).await {
                                return;
                            }
                        } else {
                            pending_commands.push_back(line);
                        }
                    }
                    Ok(None) => {
                        if client.phase == Phase::Interactive || pending_commands.is_empty() {
                            println!("EOF on stdin.");
                            return;
                        }
                        stdin_eof = true;
                    }
                    Err(e) => {
                        eprintln!("stdin error: {e}");
                        return;
                    }
                }
            }
        }
    }
}

async fn drain_pending(
    client: &mut Client,
    framed: &mut Framed<TcpStream, UsbredirCodec<Guest>>,
    pending: &mut std::collections::VecDeque<String>,
    stdin_eof: bool,
) -> bool {
    while let Some(line) = pending.pop_front() {
        if !process_command(client, framed, &line).await {
            return false;
        }
    }
    if stdin_eof {
        println!("EOF on stdin.");
        return false;
    }
    true
}

async fn process_command(
    client: &mut Client,
    framed: &mut Framed<TcpStream, UsbredirCodec<Guest>>,
    line: &str,
) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts[0] {
        "quit" | "exit" => {
            println!("Bye.");
            return false;
        }
        "help" => print_help(),
        "ctrl" => {
            if let Some(pkt) = parse_ctrl_command(client, &parts) {
                if let Err(e) = framed.send(pkt).await {
                    eprintln!("Send error: {e}");
                    return false;
                }
            }
        }
        "alt" => {
            if parts.len() < 3 {
                eprintln!("Usage: alt <interface> <alt>");
            } else if let (Some(iface), Some(alt)) =
                (parse_int::<u8>(parts[1]), parse_int::<u8>(parts[2]))
            {
                let id = client.alloc_id();
                println!("Sending SetAltSetting(interface={iface}, alt={alt})");
                if let Err(e) = framed.send(Packet::set_alt_setting(id, iface, alt)).await {
                    eprintln!("Send error: {e}");
                    return false;
                }
            }
        }
        "int_start" => {
            if parts.len() < 2 {
                eprintln!("Usage: int_start <endpoint>");
            } else if let Some(ep) = parse_int::<u8>(parts[1]) {
                let id = client.alloc_id();
                println!("Sending StartInterruptReceiving(endpoint={ep:#04x})");
                if let Err(e) = framed
                    .send(Packet::start_interrupt_receiving(id, Endpoint::new(ep)))
                    .await
                {
                    eprintln!("Send error: {e}");
                    return false;
                }
            }
        }
        "int_stop" => {
            if parts.len() < 2 {
                eprintln!("Usage: int_stop <endpoint>");
            } else if let Some(ep) = parse_int::<u8>(parts[1]) {
                let id = client.alloc_id();
                println!("Sending StopInterruptReceiving(endpoint={ep:#04x})");
                if let Err(e) = framed
                    .send(Packet::stop_interrupt_receiving(id, Endpoint::new(ep)))
                    .await
                {
                    eprintln!("Send error: {e}");
                    return false;
                }
            }
        }
        "iso_start" => {
            if parts.len() < 4 {
                eprintln!("Usage: iso_start <endpoint> <pkts_per_urb> <no_urbs>");
            } else if let (Some(ep), Some(pkts), Some(urbs)) = (
                parse_int::<u8>(parts[1]),
                parse_int::<u8>(parts[2]),
                parse_int::<u8>(parts[3]),
            ) {
                let id = client.alloc_id();
                println!(
                    "Sending StartIsoStream(endpoint={ep:#04x}, pkts={pkts}, urbs={urbs})"
                );
                if let Err(e) = framed
                    .send(Packet::start_iso_stream(id, Endpoint::new(ep), pkts, urbs))
                    .await
                {
                    eprintln!("Send error: {e}");
                    return false;
                }
            }
        }
        "iso_stop" => {
            if parts.len() < 2 {
                eprintln!("Usage: iso_stop <endpoint>");
            } else if let Some(ep) = parse_int::<u8>(parts[1]) {
                let id = client.alloc_id();
                println!("Sending StopIsoStream(endpoint={ep:#04x})");
                if let Err(e) = framed
                    .send(Packet::stop_iso_stream(id, Endpoint::new(ep)))
                    .await
                {
                    eprintln!("Send error: {e}");
                    return false;
                }
            }
        }
        "wait" => {
            let secs: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);
            println!("Waiting {secs}s for incoming data...");
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
                                handle_packet(client, packet);
                            }
                            Some(Err(e)) => {
                                eprintln!("Protocol error: {e}");
                            }
                            None => {
                                println!("Connection closed.");
                                return false;
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        break;
                    }
                }
            }
            println!("Received {count} packets ({bytes} data bytes) in {secs}s");
        }
        other => {
            eprintln!("Unknown command: {other}. Type 'help' for help.");
        }
    }
    true
}

fn handle_packet(client: &mut Client, packet: &Packet) -> Option<Vec<Packet>> {
    match packet {
        Packet::Hello { version, caps } => {
            println!("Hello from server: version={version:?}, caps={caps:?}");
            if client.phase != Phase::WaitHello {
                eprintln!("Unexpected Hello");
                return None;
            }

            let reset_id = client.alloc_id();
            client.get_config_id = client.alloc_id();
            client.phase = Phase::WaitGetConfig;

            println!("Sending Reset + GetConfiguration");
            Some(vec![
                Packet::reset(reset_id),
                Packet::get_configuration(client.get_config_id),
            ])
        }

        Packet::Request(req) => match &req.kind {
            RequestKind::ConfigurationStatus {
                status,
                configuration,
            } => {
                println!(
                    "ConfigurationStatus: id={} status={status:?} configuration={configuration}",
                    req.id
                );

                match client.phase {
                    Phase::WaitGetConfig if req.id == client.get_config_id => {
                        client.set_config_id = client.alloc_id();
                        client.phase = Phase::WaitSetConfig;
                        println!(
                            "Sending SetConfiguration(config={configuration})"
                        );
                        Some(vec![Packet::set_configuration(
                            client.set_config_id,
                            *configuration,
                        )])
                    }
                    Phase::WaitSetConfig if req.id == client.set_config_id => {
                        client.get_alt_id = client.alloc_id();
                        client.phase = Phase::WaitGetAlt;
                        println!("Sending GetAltSetting(interface=0)");
                        Some(vec![Packet::get_alt_setting(client.get_alt_id, 0)])
                    }
                    _ => None,
                }
            }

            RequestKind::AltSettingStatus {
                status,
                interface,
                alt,
            } => {
                println!(
                    "AltSettingStatus: id={} status={status:?} interface={interface} alt={alt}",
                    req.id
                );

                match client.phase {
                    Phase::WaitGetAlt if req.id == client.get_alt_id => {
                        client.set_alt_id = client.alloc_id();
                        client.phase = Phase::WaitSetAlt;
                        println!(
                            "Sending SetAltSetting(interface={interface}, alt={alt})"
                        );
                        Some(vec![Packet::set_alt_setting(
                            client.set_alt_id,
                            *interface,
                            *alt,
                        )])
                    }
                    Phase::WaitSetAlt if req.id == client.set_alt_id => {
                        client.phase = Phase::Interactive;
                        println!("Handshake complete. Entering interactive mode.");
                        print_help();
                        None
                    }
                    _ => None,
                }
            }

            other => {
                println!("Request: {other}");
                None
            }
        },

        Packet::DeviceConnect(info) => {
            print_device_connect(info);
            None
        }

        Packet::DeviceDisconnect => {
            println!("DeviceDisconnect");
            process::exit(0);
        }

        Packet::InterfaceInfo(info) => {
            print_interface_info(
                info.interface_count,
                &info.interface,
                &info.interface_class,
                &info.interface_subclass,
                &info.interface_protocol,
            );
            None
        }

        Packet::EpInfo(info) => {
            print_ep_info(&info.ep_type, &info.interval, &info.interface, &info.max_packet_size);
            None
        }

        Packet::Data(d) => {
            if matches!(d.kind, DataKind::Control { .. }) {
                print_control_response(d);
            } else {
                println!("Data: {d}");
            }
            None
        }

        other => {
            println!("Received: {other}");
            None
        }
    }
}
