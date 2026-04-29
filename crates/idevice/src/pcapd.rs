//! `com.apple.pcapd` — stream the iOS Remote Virtual Interface to a libpcap file.
//!
//! Mirrors `pymobiledevice3/services/pcapd.py`. iOS publishes the **RVI** (remote virtual
//! interface) as a TLS-protected lockdown service; each frame on the wire is a standard
//! `property_list_service` message — `u32 BE length + binary plist` — whose payload is a single
//! **CFData** carrying the packed `device_packet_struct` documented in
//! [`idevice_usb_core::pcapd_proto`].
//!
//! Connection topology mirrors the syslog relay (secondary mux pseudo-TCP + service TLS) so any
//! environment that already runs `syslog` / `crash-reports` / `screenshot` will run `pcap` too.
//!
//! ```text
//! HOST                                      DEVICE
//!  →  StartService("com.apple.pcapd")  →    (TLS upgrade)
//!  ←  framed CFData(device_packet_struct, IP / Eth bytes)
//!  ←  framed CFData(device_packet_struct, IP / Eth bytes)
//!  …
//! ```
//!
//! Output is a classic libpcap (`.pcap`) file with `LINKTYPE_ETHERNET` so any tool that reads
//! `tcpdump -w` files (Wireshark, tshark, scapy, …) can open it. For raw IP packets coming from
//! cellular interfaces (`pdp_ip*`) we synthesise an Ethernet II header so the dissector chain
//! stays happy — same trick pymobiledevice3 uses.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::ClientConnection;

use crate::crypto::HostKeys;
use crate::lockdown::LockdownClient;
use crate::lockdown_rustls::{
    handshake_service_tls, tls_read_plain_service, LockdownTlsClientAuth, LockdownTlsSni,
};
use crate::mux_link::MuxHub;
use idevice_usb_core::pcapd_proto::{
    build_pcap_global_header, build_pcap_record_header, build_pcap_record_payload,
    interface_type_label, parse_pcapd_message, protocol_family_label, PcapdRecord,
    LINKTYPE_ETHERNET, MAX_PCAPD_FRAME, PCAPD_SERVICE, PCAP_DEFAULT_SNAPLEN,
};
use idevice_usb_core::TcpConn;

type MuxHubRc = Rc<RefCell<MuxHub>>;

/// Stop the relay loop after observing this many decoded packets. `None` means run until the
/// device closes the stream (or the caller hits Ctrl-C).
#[derive(Clone, Debug, Default)]
pub struct PcapRelayLimits {
    pub max_packets: Option<u64>,
    pub max_bytes_in_pcap: Option<u64>,
    /// Drop packets whose `pid` doesn't match (also matched against `comm`/`ecomm` as a string).
    pub filter_process: Option<String>,
    /// Drop packets whose `interface_name` doesn't match (`"en0"`, `"pdp_ip0"`, …).
    pub filter_interface: Option<String>,
}

/// Why [`relay_pcap`] returned. Useful for the CLI summary at the end of the run.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PcapStopReason {
    StreamClosed,
    MaxPackets,
    MaxBytes,
}

/// One decoded packet in user-friendly form (callers don't have to depend on `idevice-usb-core`
/// directly to format CLI status lines).
#[derive(Debug, Clone)]
pub struct PcapEvent<'a> {
    pub interface: &'a str,
    pub interface_type: &'a str,
    pub direction: &'static str,
    pub protocol_family: &'static str,
    pub pid: u32,
    pub comm: &'a str,
    pub byte_len: usize,
    pub packet_index: u64,
}

/// Entry point — assumes `client` already finished `StartSession` + lockdown TLS upgrade
/// (the same recipe as `syslog_relay::relay_syslog`).
///
/// `out` is anything `Write`-able; we write a 24-byte libpcap global header up front, then one
/// `[16-byte rec hdr | <ethernet+ip>]` per accepted packet. After every accepted packet we call
/// `on_packet` with the [`PcapEvent`] so callers can print live stats. `on_packet` returns
/// `false` to stop early (used by Ctrl-C handling and `--max-packets`).
#[allow(clippy::too_many_arguments)]
pub fn relay_pcap<W, F>(
    client: &mut LockdownClient,
    keys: &HostKeys,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
    tls_debug: bool,
    out: &mut W,
    limits: PcapRelayLimits,
    mut on_packet: F,
) -> Result<PcapStopReason, String>
where
    W: Write,
    F: FnMut(&PcapEvent<'_>) -> bool,
{
    let mux = client.mux_link().ok_or(
        "pcap relay needs direct USB mux (a second pseudo-TCP to the relay port). \
         When usbmuxd holds the device, use `pymobiledevice3 pcap` instead, \
         or stop usbmuxd briefly so this process owns the USB interface.",
    )?;

    let (port, ssl) = client.start_service(PCAPD_SERVICE)?;
    crate::console_log!(
        "[pcap] StartService {} → port {} EnableServiceSSL={}",
        PCAPD_SERVICE,
        port,
        ssl
    );

    let hub = client
        .mux_hub()
        .ok_or_else(|| "pcap: internal error (no mux hub)".to_string())?;

    let tcp = Rc::new(RefCell::new(mux.borrow().connect_service_tcp(port)?));

    out.write_all(&build_pcap_global_header(
        PCAP_DEFAULT_SNAPLEN,
        LINKTYPE_ETHERNET,
    ))
    .map_err(|e| format!("pcap output: {}", e))?;
    out.flush().ok();

    if ssl {
        let mut tls = handshake_service_tls(
            hub.clone(),
            tcp.clone(),
            keys,
            client_auth,
            tls_sni,
            tls_debug,
        )?;
        relay_pcap_loop_tls(&mut tls, &hub, &tcp, tls_debug, out, &limits, &mut on_packet)
    } else {
        relay_pcap_loop_cleartext(&hub, &tcp, out, &limits, &mut on_packet)
    }
}

fn relay_pcap_loop_tls<W: Write, F: FnMut(&PcapEvent<'_>) -> bool>(
    tls: &mut ClientConnection,
    hub: &MuxHubRc,
    tcp: &Rc<RefCell<TcpConn>>,
    tls_debug: bool,
    out: &mut W,
    limits: &PcapRelayLimits,
    on_packet: &mut F,
) -> Result<PcapStopReason, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut scratch = vec![0u8; 64 * 1024];
    let mut packets_written: u64 = 0;
    let mut bytes_written: u64 = 0;
    loop {
        let n = tls_read_plain_service(tls, hub, tcp, &mut scratch, tls_debug)?;
        if n == 0 {
            return Ok(PcapStopReason::StreamClosed);
        }
        buf.extend_from_slice(&scratch[..n]);
        if let Some(reason) = drain_frames(
            &mut buf,
            out,
            limits,
            &mut packets_written,
            &mut bytes_written,
            on_packet,
        )? {
            return Ok(reason);
        }
    }
}

fn relay_pcap_loop_cleartext<W: Write, F: FnMut(&PcapEvent<'_>) -> bool>(
    hub: &MuxHubRc,
    tcp: &Rc<RefCell<TcpConn>>,
    out: &mut W,
    limits: &PcapRelayLimits,
    on_packet: &mut F,
) -> Result<PcapStopReason, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut packets_written: u64 = 0;
    let mut bytes_written: u64 = 0;
    loop {
        let chunk = {
            let mut h = hub.borrow_mut();
            let mut t = tcp.borrow_mut();
            h.recv_tcp_payload_for(&mut *t)?
        };
        if chunk.is_empty() {
            return Ok(PcapStopReason::StreamClosed);
        }
        buf.extend_from_slice(&chunk);
        if let Some(reason) = drain_frames(
            &mut buf,
            out,
            limits,
            &mut packets_written,
            &mut bytes_written,
            on_packet,
        )? {
            return Ok(reason);
        }
    }
}

/// Pull every complete `<u32 BE length><bplist>` frame out of `buf` and write the matching
/// libpcap record. Returns `Some(reason)` if a stop condition was reached (max-packets,
/// max-bytes, or `on_packet` returned `false`).
fn drain_frames<W: Write, F: FnMut(&PcapEvent<'_>) -> bool>(
    buf: &mut Vec<u8>,
    out: &mut W,
    limits: &PcapRelayLimits,
    packets_written: &mut u64,
    bytes_written: &mut u64,
    on_packet: &mut F,
) -> Result<Option<PcapStopReason>, String> {
    loop {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
        if len == 0 {
            buf.drain(..4);
            continue;
        }
        if len > MAX_PCAPD_FRAME {
            return Err(format!(
                "pcap frame length {} exceeds max {} bytes",
                len, MAX_PCAPD_FRAME
            ));
        }
        if buf.len() < 4 + len {
            return Ok(None);
        }
        let plist_bytes: Vec<u8> = buf.drain(..4 + len).collect();
        let payload = &plist_bytes[4..4 + len];
        let rec = match parse_pcapd_message(payload) {
            Ok(r) => r,
            Err(e) => {
                crate::console_log!("[pcap] dropping malformed frame: {}", e);
                continue;
            }
        };
        if !record_matches_filters(&rec, limits) {
            continue;
        }
        let frame = build_pcap_record_payload(&rec);
        let (sec, usec) = record_timestamp(&rec);
        let header = build_pcap_record_header(sec, usec, frame.len() as u32);
        out.write_all(&header)
            .map_err(|e| format!("pcap output: {}", e))?;
        out.write_all(&frame)
            .map_err(|e| format!("pcap output: {}", e))?;
        out.flush().ok();
        *packets_written = packets_written.saturating_add(1);
        *bytes_written =
            bytes_written.saturating_add(header.len() as u64 + frame.len() as u64);

        let iface_label = interface_type_label(rec.interface_type);
        let event = PcapEvent {
            interface: &rec.interface_name,
            interface_type: &iface_label,
            direction: if rec.io == 0 { "in" } else { "out" },
            protocol_family: protocol_family_label(rec.protocol_family),
            pid: rec.pid,
            comm: &rec.comm,
            byte_len: frame.len(),
            packet_index: *packets_written,
        };
        if !on_packet(&event) {
            return Ok(Some(PcapStopReason::StreamClosed));
        }
        if let Some(max) = limits.max_packets {
            if *packets_written >= max {
                return Ok(Some(PcapStopReason::MaxPackets));
            }
        }
        if let Some(max) = limits.max_bytes_in_pcap {
            if *bytes_written >= max {
                return Ok(Some(PcapStopReason::MaxBytes));
            }
        }
    }
}

fn record_matches_filters(rec: &PcapdRecord, limits: &PcapRelayLimits) -> bool {
    if let Some(proc_filter) = limits.filter_process.as_deref() {
        let pid_str = rec.pid.to_string();
        if proc_filter != pid_str
            && proc_filter != rec.comm
            && proc_filter != rec.ecomm
        {
            return false;
        }
    }
    if let Some(iface) = limits.filter_interface.as_deref() {
        if iface != rec.interface_name {
            return false;
        }
    }
    true
}

/// Use the device timestamps when populated; fall back to the host clock so older firmware
/// (which sometimes emits `seconds = 0`) still yields a usable Wireshark timeline.
fn record_timestamp(rec: &PcapdRecord) -> (u32, u32) {
    if rec.seconds != 0 {
        return (rec.seconds, rec.microseconds);
    }
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as u32, d.subsec_micros()),
        Err(_) => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use idevice_usb_core::pcapd_proto::{AF_INET, ETHERTYPE_IPV4, FAKE_MAC};

    fn fake_record(iface: &str, pid: u32, comm: &str, secs: u32) -> PcapdRecord {
        PcapdRecord {
            header_length: 95,
            header_version: 1,
            packet_length: 4,
            interface_type: 6,
            unit: 0,
            io: 0,
            protocol_family: AF_INET,
            frame_pre_length: 0,
            frame_post_length: 0,
            interface_name: iface.into(),
            pid,
            comm: comm.into(),
            svc: 0,
            epid: 0,
            ecomm: String::new(),
            seconds: secs,
            microseconds: 100,
            data: b"abcd".to_vec(),
        }
    }

    #[test]
    fn record_timestamp_falls_back_to_host_clock_when_device_seconds_zero() {
        let rec = fake_record("en0", 1, "kernel", 0);
        let (sec, _us) = record_timestamp(&rec);
        assert!(sec > 1_700_000_000, "expected host clock fallback, got {}", sec);
    }

    #[test]
    fn record_timestamp_passes_device_clock_through_when_set() {
        let rec = fake_record("en0", 1, "kernel", 0xabcd_ef01);
        assert_eq!(record_timestamp(&rec), (0xabcd_ef01, 100));
    }

    #[test]
    fn filters_skip_records_with_mismatched_process_or_interface() {
        let rec = fake_record("en0", 73, "trustd", 1);
        for (filter, expect) in [("nope", false), ("trustd", true), ("73", true)] {
            let lim = PcapRelayLimits {
                filter_process: Some(filter.into()),
                ..Default::default()
            };
            assert_eq!(record_matches_filters(&rec, &lim), expect, "filter={filter}");
        }
        for (iface, expect) in [("pdp_ip0", false), ("en0", true)] {
            let lim = PcapRelayLimits {
                filter_interface: Some(iface.into()),
                ..Default::default()
            };
            assert_eq!(record_matches_filters(&rec, &lim), expect, "iface={iface}");
        }
    }

    /// Exercise the full drain path: feed two complete plist frames into a buffer, make sure both
    /// land in the libpcap stream as `[record_header][ethernet+ip]` blobs and that `on_packet`
    /// observes them in order.
    #[test]
    fn drain_frames_writes_pcap_records_for_complete_plist_frames() {
        // Build one packed record then wrap it in a tiny binary plist we control.
        let body = b"hello-pcap";
        let packed = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&95u32.to_be_bytes());
            buf.push(1);
            buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
            buf.push(6); // interface_type
            buf.extend_from_slice(&0u16.to_be_bytes()); // unit
            buf.push(0); // io
            buf.extend_from_slice(&AF_INET.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes()); // frame_pre_length
            buf.extend_from_slice(&0u32.to_be_bytes()); // frame_post_length
            let mut iface = [0u8; 16];
            iface[..3].copy_from_slice(b"en0");
            buf.extend_from_slice(&iface);
            buf.extend_from_slice(&42u32.to_le_bytes()); // pid
            let mut comm = [0u8; 17];
            comm[..6].copy_from_slice(b"trustd");
            buf.extend_from_slice(&comm);
            buf.extend_from_slice(&0u32.to_be_bytes()); // svc
            buf.extend_from_slice(&0u32.to_le_bytes()); // epid
            let ecomm = [0u8; 17];
            buf.extend_from_slice(&ecomm);
            buf.extend_from_slice(&123u32.to_be_bytes()); // seconds
            buf.extend_from_slice(&456u32.to_be_bytes()); // microseconds
            buf.extend_from_slice(body);
            buf
        };
        let plist_payload = {
            let mut p = Vec::new();
            plist::Value::Data(packed.clone())
                .to_writer_xml(&mut p)
                .unwrap();
            p
        };
        let frame = {
            let mut f = (plist_payload.len() as u32).to_be_bytes().to_vec();
            f.extend_from_slice(&plist_payload);
            f
        };
        let mut buf = frame.clone();
        buf.extend_from_slice(&frame);

        let mut sink: Vec<u8> = Vec::new();
        let mut events: Vec<(String, u32, String, &'static str)> = Vec::new();
        let mut packets_written = 0u64;
        let mut bytes_written = 0u64;

        let stop = drain_frames(
            &mut buf,
            &mut sink,
            &PcapRelayLimits::default(),
            &mut packets_written,
            &mut bytes_written,
            &mut |evt: &PcapEvent<'_>| {
                events.push((
                    evt.interface.to_string(),
                    evt.pid,
                    evt.comm.to_string(),
                    evt.direction,
                ));
                true
            },
        )
        .unwrap();
        assert!(stop.is_none(), "no early stop expected");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, "en0");
        assert_eq!(events[0].1, 42);
        assert_eq!(events[0].2, "trustd");
        assert_eq!(events[0].3, "in");
        assert_eq!(packets_written, 2);

        // Each emitted record is `[16-byte header][14-byte fake eth + body]`.
        let record_size = 16 + 14 + body.len();
        assert_eq!(sink.len(), 2 * record_size);
        let first_record = &sink[..record_size];
        assert_eq!(&first_record[0..4], &123u32.to_le_bytes()); // ts_sec
        assert_eq!(&first_record[4..8], &456u32.to_le_bytes()); // ts_usec
        assert_eq!(&first_record[8..12], &(14u32 + body.len() as u32).to_le_bytes()); // incl_len
        assert_eq!(&first_record[16..22], &FAKE_MAC);
        assert_eq!(&first_record[28..30], &ETHERTYPE_IPV4.to_be_bytes());
        assert_eq!(&first_record[30..], body);
    }

    #[test]
    fn drain_frames_stops_when_callback_returns_false() {
        let body = b"x";
        let packed = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&95u32.to_be_bytes());
            buf.push(1);
            buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
            buf.push(6);
            buf.extend_from_slice(&0u16.to_be_bytes());
            buf.push(0);
            buf.extend_from_slice(&AF_INET.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
            let mut iface = [0u8; 16];
            iface[..3].copy_from_slice(b"en0");
            buf.extend_from_slice(&iface);
            buf.extend_from_slice(&1u32.to_le_bytes());
            buf.extend_from_slice(&[0u8; 17]);
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&[0u8; 17]);
            buf.extend_from_slice(&1u32.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(body);
            buf
        };
        let mut p = Vec::new();
        plist::Value::Data(packed.clone()).to_writer_xml(&mut p).unwrap();
        let mut frame = (p.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&p);

        let mut sink = Vec::new();
        let mut packets_written = 0u64;
        let mut bytes_written = 0u64;
        let stop = drain_frames(
            &mut frame.clone(),
            &mut sink,
            &PcapRelayLimits::default(),
            &mut packets_written,
            &mut bytes_written,
            &mut |_| false, // user immediately requests stop
        )
        .unwrap();
        assert_eq!(stop, Some(PcapStopReason::StreamClosed));
    }
}
