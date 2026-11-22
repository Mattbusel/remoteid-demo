//! The `decode` subcommand: pretty-print the Remote ID in a capture.
//!
//! Handles the standard ASTM F3411 Remote ID that [`remoteid`] decodes from
//! pcap, pcapng and RIDF, and additionally scans Wi-Fi frames in a pcap or
//! pcapng for DJI DroneID vendor elements.

use remoteid::capture::{self, CapturedFrame, Packet};
use remoteid::dji::{self, WifiDroneId};
use remoteid::{wifi, Frame, Message, Transmitter};

/// Runs the decode subcommand.
pub fn run(path: &str, limit: usize) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("could not read {path}: {e}"))?;

    println!("Remote ID decode of {path}");
    println!("====================={}", "=".repeat(path.len()));

    let mut printed = 0usize;
    let keep_going = |printed: usize| limit == 0 || printed < limit;

    if bytes.starts_with(b"RIDF") {
        // RIDF carries only standard Remote ID frames.
        let frames =
            capture::frames(&bytes).map_err(|e| format!("could not parse {path}: {e:?}"))?;
        for f in &frames {
            if !keep_going(printed) {
                break;
            }
            print_astm(f);
            printed += 1;
        }
    } else {
        let packets = if bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
            capture::pcapng_packets(&bytes)
        } else {
            capture::pcap_packets(&bytes)
        }
        .map_err(|e| format!("could not parse {path}: {e:?}"))?;

        for p in &packets {
            if !keep_going(printed) {
                break;
            }
            if let Some(f) = capture::frame_of(p) {
                print_astm(&f);
                printed += 1;
            } else if let Some(dji) = dji_of(p) {
                print_dji(&dji);
                printed += 1;
            }
        }
    }

    if printed == 0 {
        println!("(no Remote ID frames found)");
    } else {
        println!();
        println!("{printed} frame(s) decoded.");
    }
    Ok(())
}

/// Formats a transmitter address.
fn fmt_tx(tx: &Transmitter) -> String {
    match tx {
        Transmitter::Ble(a) | Transmitter::Wifi(a) => a
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        Transmitter::Other(n) => format!("other:{n}"),
    }
}

/// Pretty-prints a standard Remote ID frame and each message in it.
fn print_astm(f: &CapturedFrame) {
    println!();
    println!(
        "[{:>10.3}s] {} via {}",
        f.time_us as f64 / 1_000_000.0,
        fmt_tx(&f.transmitter),
        f.transport.name()
    );
    let frame = match Frame::decode(&f.payload) {
        Ok(fr) => fr,
        Err(e) => {
            println!("    (undecodable payload: {e})");
            return;
        }
    };
    frame.for_each_message(|m| print_message(&m));
}

/// Pretty-prints one Remote ID message.
fn print_message(m: &Message) {
    match m {
        Message::BasicId(b) => {
            let id = b.uas_id_str().unwrap_or("(binary id)");
            println!(
                "    BasicId     id={id}  id_type={:?}  ua_type={:?}",
                b.id_type, b.ua_type
            );
        }
        Message::Location(l) => {
            print!(
                "    Location    lat={:.6} lon={:.6}",
                l.latitude, l.longitude
            );
            if let Some(a) = l.altitude_geo {
                print!(" alt={a:.0}m");
            }
            if let Some(s) = l.speed_horizontal {
                print!(" speed={s:.1}m/s");
            }
            if let Some(d) = l.direction {
                print!(" track={d:.0}deg");
            }
            println!(" status={:?}", l.status);
        }
        Message::System(s) => {
            print!(
                "    System      operator_lat={:.6} operator_lon={:.6} area_count={}",
                s.operator_latitude, s.operator_longitude, s.area_count
            );
            if let Some(a) = s.operator_altitude_geo {
                print!(" operator_alt={a:.0}m");
            }
            println!();
        }
        Message::OperatorId(o) => {
            println!(
                "    OperatorId  {}",
                o.operator_id_str().unwrap_or("(binary)")
            );
        }
        Message::SelfId(s) => {
            println!(
                "    SelfId      {}",
                s.description_str().unwrap_or("(binary)")
            );
        }
        Message::Auth(a) => {
            println!("    Auth        page {} of auth data", a.page);
        }
    }
}

/// Extracts a DJI DroneID report from a Wi-Fi packet, if present.
fn dji_of<'a>(p: &'a Packet<'a>) -> Option<DjiFrame<'a>> {
    // Raw 802.11 (105) or radiotap-prefixed 802.11 (127).
    let frame = match p.linktype {
        105 => p.data,
        127 => wifi::strip_radiotap(p.data).ok()?,
        _ => return None,
    };
    // Beacon or probe response: 24 byte management header, 12 fixed bytes,
    // then the information elements that may carry a DroneID vendor element.
    let info = wifi::beacon_info(frame)?;
    let ies = frame.get(36..)?;
    let dji = dji::find_in_elements(ies)?;
    Some(DjiFrame {
        time_us: p.time_us,
        source: info.source,
        dji,
    })
}

/// A decoded DJI DroneID report tied to its packet.
struct DjiFrame<'a> {
    time_us: u64,
    source: [u8; 6],
    dji: WifiDroneId<'a>,
}

/// Pretty-prints a DJI DroneID report.
fn print_dji(d: &DjiFrame) {
    let addr = d
        .source
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    println!();
    println!(
        "[{:>10.3}s] {addr} via wifi (DJI DroneID)",
        d.time_us as f64 / 1_000_000.0
    );
    match &d.dji {
        WifiDroneId::FlightInfo(fi) => {
            let serial = fi.serial_str().unwrap_or("(unset)");
            let product = fi.product_name().unwrap_or("unknown product");
            println!("    DJI FlightInfo  serial={serial}  product={product}");
            if let Some((lat, lon)) = fi.position() {
                print!(
                    "    aircraft        lat={lat:.6} lon={lon:.6} alt={:.0}m",
                    fi.altitude_m()
                );
                println!(" height={:.0}m yaw={:.0}deg", fi.height_m(), fi.yaw_deg());
            }
            if let Some((lat, lon)) = fi.pilot_position() {
                println!("    pilot           lat={lat:.6} lon={lon:.6}");
            }
            if let Some((lat, lon)) = fi.home_position() {
                println!("    home            lat={lat:.6} lon={lon:.6}");
            }
        }
        WifiDroneId::FlightPurpose(fp) => {
            println!(
                "    DJI FlightPurpose  serial={}  purpose={}",
                fp.serial_str().unwrap_or("(unset)"),
                fp.purpose_str().unwrap_or("(unset)")
            );
        }
        WifiDroneId::Other { subcommand, .. } => {
            println!("    DJI record      type 0x{subcommand:02x} (not decoded)");
        }
    }
}
