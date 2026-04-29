//! `com.apple.pcapd` protocol helpers — pure parsing / framing, no I/O.
//!
//! Mirrors `pymobiledevice3/services/pcapd.py`. iOS exposes a **remote virtual interface (RVI)** that
//! mirrors network traffic to lockdownd. Each message on the (TLS-wrapped) service socket is a
//! standard `property_list_service` frame — `u32 BE length + binary plist` — and the plist payload
//! is a single **CFData** carrying the **`device_packet_struct`** below:
//!
//! ```text
//! struct device_packet {
//!     u32 BE  header_length;        // offset to packet bytes (so this header may grow)
//!     u8       header_version;
//!     u32 BE  packet_length;        // bytes of payload after the header
//!     u8       interface_type;      // IANA-style ifType (1..=259, see pymobiledevice3 INTERFACE_NAMES)
//!     u16 BE  unit;                 // interface unit (e.g. en0 → 0)
//!     u8       io;                  // 0 = in, 1 = out
//!     u32 BE  protocol_family;      // BSD AF_*: 2=AF_INET, 30=AF_INET6
//!     u32 BE  frame_pre_length;     // bytes of link-layer header at start of payload
//!     u32 BE  frame_post_length;
//!     char     interface_name[16];  // null-padded UTF-8 (e.g. "en0\0…", "pdp_ip0\0…")
//!     u32 LE  pid;                  // <-- LE, not BE
//!     char     comm[17];            // null-padded process name
//!     u32 BE  svc;                  // socket service class (libnetcore SO_NET_SERVICE_TYPE)
//!     u32 LE  epid;                 // effective pid (or 0)
//!     char     ecomm[17];           // effective process name
//!     u32 BE  seconds;              // capture time (Unix seconds)
//!     u32 BE  microseconds;
//!     /* …header_length bytes total… */
//!     u8       data[packet_length];
//! }
//! ```
//!
//! The host then writes a standard **libpcap** capture file (`tcpdump`-compatible / Wireshark) with
//! `LINKTYPE_ETHERNET = 1`. When `frame_pre_length == 0` (typical for `pdp_ip*` cellular) the device
//! payload is a bare IPv4/IPv6 datagram, so we prepend a synthetic Ethernet II header with EtherType
//! deduced from `protocol_family` to keep Wireshark dissectors happy. This matches the trick
//! pymobiledevice3 uses (with a hardcoded `0x0800` IPv4 frame; we do `0x86dd` for `AF_INET6` so v6
//! traffic decodes too).

use plist::Value;

/// Lockdown service name (current iOS / pymobiledevice3).
pub const PCAPD_SERVICE: &str = "com.apple.pcapd";

/// Reject unreasonable u32 BE plist frames. iOS RVI frames cap well below this.
pub const MAX_PCAPD_FRAME: usize = 16 * 1024 * 1024;

/// libpcap global header magic — microsecond resolution, **little-endian** layout (the variant
/// Wireshark / `tcpdump -r` accept on every platform).
pub const PCAP_MAGIC_USEC_LE: u32 = 0xa1b2_c3d4;

/// libpcap data link type — Ethernet II frames (with the synthetic header we prepend for raw IP
/// payloads). Same value pymobiledevice3 picks (`LINKTYPE_ETHERNET`).
pub const LINKTYPE_ETHERNET: u32 = 1;

/// Snapshot length we advertise in the pcap header. iOS device packets are MTU-sized.
pub const PCAP_DEFAULT_SNAPLEN: u32 = 65_535;

/// IANA `ifType` values we surface as friendly strings (subset of pymobiledevice3 `INTERFACE_NAMES`,
/// covering everything iOS actually emits on RVI).
pub const PCAPD_IFACE_ETHERNET: u8 = 6; // ethernetCsmacd
pub const PCAPD_IFACE_PPP: u8 = 23;
pub const PCAPD_IFACE_LOOPBACK: u8 = 24; // softwareLoopback
pub const PCAPD_IFACE_SLIP: u8 = 28;
pub const PCAPD_IFACE_CELLULAR: u8 = 243; // wwanPP (cellular pdp_ip*)
pub const PCAPD_IFACE_WWAN_PP2: u8 = 244;

/// EtherType for IPv4 / IPv6 — used in the synthetic Ethernet header for `pdp_ip*` packets.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// BSD `AF_*` values that travel inside the device header.
pub const AF_UNSPEC: u32 = 0;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 30;

/// Synthetic source/destination MAC for cellular packets (matches pymobiledevice3 `\xbe\xef`*6).
pub const FAKE_MAC: [u8; 6] = [0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef];

/// Decoded **`device_packet_struct`** payload. All cstring fields are already trimmed at the first
/// `\0` and decoded with lossy UTF-8 (control bytes never make it into the cstrings on iOS).
#[derive(Debug, Clone)]
pub struct PcapdRecord {
    pub header_length: u32,
    pub header_version: u8,
    pub packet_length: u32,
    pub interface_type: u8,
    pub unit: u16,
    /// `0 = inbound`, `1 = outbound` (matches pymobiledevice3).
    pub io: u8,
    pub protocol_family: u32,
    pub frame_pre_length: u32,
    pub frame_post_length: u32,
    pub interface_name: String,
    pub pid: u32,
    pub comm: String,
    pub svc: u32,
    pub epid: u32,
    pub ecomm: String,
    /// Unix seconds for the packet (device clock). `0` is rare but possible on early boot — fall
    /// back to host time at write site if you care about Wireshark's "Time of day".
    pub seconds: u32,
    pub microseconds: u32,
    /// Raw payload exactly as emitted by the device — `frame_pre_length` link-layer prefix plus
    /// IP / TCP / etc. Use [`build_pcap_record_payload`] to get a Wireshark-friendly Ethernet
    /// frame.
    pub data: Vec<u8>,
}

/// Length of the libpcap **global** header (RFC 1761). Matches `tcpdump`'s `pcap_file_header`.
pub const PCAP_GLOBAL_HEADER_LEN: usize = 24;
/// Length of each libpcap **record** header.
pub const PCAP_RECORD_HEADER_LEN: usize = 16;

/// Build the 24-byte libpcap global header (microsecond resolution, native LE magic).
pub fn build_pcap_global_header(snaplen: u32, link_type: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(PCAP_GLOBAL_HEADER_LEN);
    h.extend_from_slice(&PCAP_MAGIC_USEC_LE.to_le_bytes()); // magic
    h.extend_from_slice(&2u16.to_le_bytes()); // version_major
    h.extend_from_slice(&4u16.to_le_bytes()); // version_minor
    h.extend_from_slice(&0i32.to_le_bytes()); // thiszone (UTC)
    h.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    h.extend_from_slice(&snaplen.to_le_bytes());
    h.extend_from_slice(&link_type.to_le_bytes());
    h
}

/// Build the 16-byte libpcap **record** header. Caller writes `payload_bytes` immediately after.
pub fn build_pcap_record_header(seconds: u32, microseconds: u32, payload_len: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(PCAP_RECORD_HEADER_LEN);
    h.extend_from_slice(&seconds.to_le_bytes());
    h.extend_from_slice(&microseconds.to_le_bytes());
    h.extend_from_slice(&payload_len.to_le_bytes()); // incl_len
    h.extend_from_slice(&payload_len.to_le_bytes()); // orig_len
    h
}

/// Pick the EtherType byte pair to staple onto a raw IP packet, based on the device's
/// `protocol_family`. Falls back to IPv4 for unknown families (matches pymobiledevice3 default
/// `\x08\x00`).
pub fn ethertype_for_protocol_family(pf: u32) -> u16 {
    match pf {
        AF_INET6 => ETHERTYPE_IPV6,
        _ => ETHERTYPE_IPV4,
    }
}

/// Convert a [`PcapdRecord`] into the **frame bytes** we should write to the libpcap file:
///
/// - When the device included its own link-layer header (`frame_pre_length > 0`) we emit
///   `data` verbatim — Wireshark dissects it as Ethernet/PPP based on the link type.
/// - When `frame_pre_length == 0` (cellular `pdp_ip*` typically) we prepend a synthetic Ethernet
///   II header (`be:ef:be:ef:be:ef` → `be:ef:be:ef:be:ef`, EtherType from `protocol_family`).
/// - Special case: `interface_name == "pdp_ip"` *with* a non-zero `frame_pre_length` — pymobiledevice3
///   strips the first 4 bytes (a BSD-style `AF_INET` family header) and prepends the synthetic
///   Ethernet header. We do the same so the resulting capture stays Ethernet-typed.
pub fn build_pcap_record_payload(rec: &PcapdRecord) -> Vec<u8> {
    let ethertype = ethertype_for_protocol_family(rec.protocol_family);
    let needs_eth = rec.frame_pre_length == 0;
    let strip_pdp_prefix = rec.frame_pre_length > 0 && rec.interface_name == "pdp_ip";
    if needs_eth || strip_pdp_prefix {
        let body = if strip_pdp_prefix && rec.data.len() >= 4 {
            &rec.data[4..]
        } else {
            &rec.data[..]
        };
        let mut out = Vec::with_capacity(14 + body.len());
        out.extend_from_slice(&FAKE_MAC); // dst
        out.extend_from_slice(&FAKE_MAC); // src
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(body);
        out
    } else {
        rec.data.clone()
    }
}

fn cstring_from_padded(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn read_u32_be(buf: &[u8], off: usize, what: &str) -> Result<u32, String> {
    let slice = buf
        .get(off..off + 4)
        .ok_or_else(|| format!("pcapd: short header reading {} at offset {}", what, off))?;
    Ok(u32::from_be_bytes(slice.try_into().unwrap()))
}

fn read_u32_le(buf: &[u8], off: usize, what: &str) -> Result<u32, String> {
    let slice = buf
        .get(off..off + 4)
        .ok_or_else(|| format!("pcapd: short header reading {} at offset {}", what, off))?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn read_u16_be(buf: &[u8], off: usize, what: &str) -> Result<u16, String> {
    let slice = buf
        .get(off..off + 2)
        .ok_or_else(|| format!("pcapd: short header reading {} at offset {}", what, off))?;
    Ok(u16::from_be_bytes(slice.try_into().unwrap()))
}

fn read_u8(buf: &[u8], off: usize, what: &str) -> Result<u8, String> {
    buf.get(off)
        .copied()
        .ok_or_else(|| format!("pcapd: short header reading {} at offset {}", what, off))
}

fn read_padded<'a>(buf: &'a [u8], off: usize, len: usize, what: &str) -> Result<&'a [u8], String> {
    buf.get(off..off + len)
        .ok_or_else(|| format!("pcapd: short header reading {} at offset {}", what, off))
}

/// Parse the **packed device header** (no surrounding plist) into a [`PcapdRecord`]. Public so
/// callers in tests / other tools can supply pre-extracted bytes.
pub fn parse_pcapd_record_bytes(bytes: &[u8]) -> Result<PcapdRecord, String> {
    let header_length = read_u32_be(bytes, 0, "header_length")?;
    let header_version = read_u8(bytes, 4, "header_version")?;
    let packet_length = read_u32_be(bytes, 5, "packet_length")?;
    let interface_type = read_u8(bytes, 9, "interface_type")?;
    let unit = read_u16_be(bytes, 10, "unit")?;
    let io = read_u8(bytes, 12, "io")?;
    let protocol_family = read_u32_be(bytes, 13, "protocol_family")?;
    let frame_pre_length = read_u32_be(bytes, 17, "frame_pre_length")?;
    let frame_post_length = read_u32_be(bytes, 21, "frame_post_length")?;
    let iface_raw = read_padded(bytes, 25, 16, "interface_name")?;
    let pid = read_u32_le(bytes, 41, "pid")?;
    let comm_raw = read_padded(bytes, 45, 17, "comm")?;
    let svc = read_u32_be(bytes, 62, "svc")?;
    let epid = read_u32_le(bytes, 66, "epid")?;
    let ecomm_raw = read_padded(bytes, 70, 17, "ecomm")?;
    let seconds = read_u32_be(bytes, 87, "seconds")?;
    let microseconds = read_u32_be(bytes, 91, "microseconds")?;

    let header_len_us = header_length as usize;
    if header_len_us < 95 {
        return Err(format!(
            "pcapd: header_length {} smaller than fixed prefix (95)",
            header_length
        ));
    }
    let pkt_len = packet_length as usize;
    let total_needed = header_len_us
        .checked_add(pkt_len)
        .ok_or_else(|| "pcapd: header_length + packet_length overflow".to_string())?;
    if bytes.len() < total_needed {
        return Err(format!(
            "pcapd: payload short — need {} bytes, got {}",
            total_needed,
            bytes.len()
        ));
    }
    let data = bytes[header_len_us..total_needed].to_vec();

    Ok(PcapdRecord {
        header_length,
        header_version,
        packet_length,
        interface_type,
        unit,
        io,
        protocol_family,
        frame_pre_length,
        frame_post_length,
        interface_name: cstring_from_padded(iface_raw),
        pid,
        comm: cstring_from_padded(comm_raw),
        svc,
        epid,
        ecomm: cstring_from_padded(ecomm_raw),
        seconds,
        microseconds,
        data,
    })
}

/// Parse one **lockdown plist payload** (the `bplist00` blob inside a `u32 BE length + plist`
/// frame) into a [`PcapdRecord`]. The plist itself is a top-level CFData blob.
pub fn parse_pcapd_message(plist_bytes: &[u8]) -> Result<PcapdRecord, String> {
    let v: Value = plist::from_bytes(plist_bytes)
        .map_err(|e| format!("pcapd: plist decode failed: {}", e))?;
    let inner = match v {
        Value::Data(d) => d,
        Value::String(s) => s.into_bytes(),
        other => {
            return Err(format!(
                "pcapd: unexpected plist payload kind {:?} (expected CFData)",
                kind_name(&other)
            ))
        }
    };
    parse_pcapd_record_bytes(&inner)
}

fn kind_name(v: &Value) -> &'static str {
    match v {
        Value::Array(_) => "Array",
        Value::Dictionary(_) => "Dictionary",
        Value::Boolean(_) => "Boolean",
        Value::Data(_) => "Data",
        Value::Date(_) => "Date",
        Value::Real(_) => "Real",
        Value::Integer(_) => "Integer",
        Value::String(_) => "String",
        Value::Uid(_) => "Uid",
        _ => "Unknown",
    }
}

/// Friendly interface-type label for human-readable status lines (`6 → ethernetCsmacd`,
/// `243 → wwanPP`, …). Unknown values become `"ifType=<n>"`.
pub fn interface_type_label(t: u8) -> String {
    match t {
        PCAPD_IFACE_ETHERNET => "ethernetCsmacd".into(),
        PCAPD_IFACE_PPP => "ppp".into(),
        PCAPD_IFACE_LOOPBACK => "softwareLoopback".into(),
        PCAPD_IFACE_SLIP => "slip".into(),
        PCAPD_IFACE_CELLULAR => "wwanPP".into(),
        PCAPD_IFACE_WWAN_PP2 => "wwanPP2".into(),
        71 => "ieee80211".into(),
        117 => "gigabitEthernet".into(),
        144 => "ieee1394".into(),
        n => format!("ifType={}", n),
    }
}

/// Human label for the BSD `protocol_family` field on the wire.
pub fn protocol_family_label(pf: u32) -> &'static str {
    match pf {
        AF_UNSPEC => "AF_UNSPEC",
        AF_INET => "AF_INET",
        AF_INET6 => "AF_INET6",
        _ => "AF_other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduce one packed `device_packet_struct` from the docstring layout. Useful as a
    /// fixture for the parser tests below — keeps every offset honest.
    fn build_packed_record(
        header_extra: usize,
        iface_name: &str,
        pid: u32,
        comm: &str,
        protocol_family: u32,
        frame_pre_length: u32,
        seconds: u32,
        microseconds: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let header_length: u32 = (95 + header_extra) as u32;
        let mut buf = Vec::with_capacity(header_length as usize + data.len());
        buf.extend_from_slice(&header_length.to_be_bytes());
        buf.push(1); // header_version
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.push(PCAPD_IFACE_CELLULAR); // interface_type — wwanPP
        buf.extend_from_slice(&0u16.to_be_bytes()); // unit
        buf.push(0); // io = inbound
        buf.extend_from_slice(&protocol_family.to_be_bytes());
        buf.extend_from_slice(&frame_pre_length.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // frame_post_length

        let mut iface = [0u8; 16];
        let bytes = iface_name.as_bytes();
        iface[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
        buf.extend_from_slice(&iface);

        buf.extend_from_slice(&pid.to_le_bytes());

        let mut comm_buf = [0u8; 17];
        let cb = comm.as_bytes();
        comm_buf[..cb.len().min(17)].copy_from_slice(&cb[..cb.len().min(17)]);
        buf.extend_from_slice(&comm_buf);

        buf.extend_from_slice(&0u32.to_be_bytes()); // svc
        buf.extend_from_slice(&0u32.to_le_bytes()); // epid

        let ecomm_buf = [0u8; 17];
        buf.extend_from_slice(&ecomm_buf);

        buf.extend_from_slice(&seconds.to_be_bytes());
        buf.extend_from_slice(&microseconds.to_be_bytes());

        // Optional extra header bytes — the device sometimes inserts vendor-specific fields after
        // the fixed prefix; we just zero them so `header_length > 95` paths get exercised.
        if header_extra > 0 {
            buf.extend(std::iter::repeat_n(0u8, header_extra));
        }
        buf.extend_from_slice(data);
        buf
    }

    #[test]
    fn parses_minimal_pdp_ip_record_and_synthesises_ethernet_header() {
        // 8-byte IPv4 stub payload. `frame_pre_length=0` → we'll prepend a fake Ethernet header.
        let body = b"\x45\x00\x00\x08\x00\x00\x40\x00";
        let packed = build_packed_record(0, "pdp_ip0", 73, "trustd", AF_INET, 0, 0x6000_0000, 0, body);
        let rec = parse_pcapd_record_bytes(&packed).expect("parse");
        assert_eq!(rec.interface_name, "pdp_ip0");
        assert_eq!(rec.pid, 73);
        assert_eq!(rec.comm, "trustd");
        assert_eq!(rec.protocol_family, AF_INET);
        assert_eq!(rec.frame_pre_length, 0);
        assert_eq!(rec.data, body);
        assert_eq!(rec.header_length, 95);

        let frame = build_pcap_record_payload(&rec);
        assert_eq!(frame.len(), 14 + body.len(), "Ethernet header prepended");
        assert_eq!(&frame[..6], &FAKE_MAC, "dst MAC");
        assert_eq!(&frame[6..12], &FAKE_MAC, "src MAC");
        assert_eq!(&frame[12..14], &ETHERTYPE_IPV4.to_be_bytes());
        assert_eq!(&frame[14..], body);
    }

    #[test]
    fn passes_through_packets_that_already_carry_a_link_layer_header() {
        // 14-byte Ethernet header + 4-byte body. `frame_pre_length` is non-zero and the iface
        // is **not** "pdp_ip", so we should emit the bytes verbatim.
        let mut full = Vec::new();
        full.extend_from_slice(&FAKE_MAC);
        full.extend_from_slice(&FAKE_MAC);
        full.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        full.extend_from_slice(b"DEAD");
        let packed = build_packed_record(0, "en0", 1, "kernel", AF_INET, 14, 0, 0, &full);
        let rec = parse_pcapd_record_bytes(&packed).unwrap();
        let frame = build_pcap_record_payload(&rec);
        assert_eq!(frame, full);
    }

    #[test]
    fn pdp_ip_with_frame_prefix_strips_first_4_bytes_then_prepends_eth() {
        // A `pdp_ip` packet *with* a 4-byte BSD AF header — pymobiledevice3 strips it.
        let mut bsd = vec![0u8, 0, 0, 2]; // 4-byte AF_INET prefix
        bsd.extend_from_slice(b"PAYLOAD!");
        let packed = build_packed_record(0, "pdp_ip", 4, "comd", AF_INET, 4, 0, 0, &bsd);
        let rec = parse_pcapd_record_bytes(&packed).unwrap();
        let frame = build_pcap_record_payload(&rec);
        assert_eq!(frame.len(), 14 + 8, "stripped BSD prefix, kept body");
        assert_eq!(&frame[14..], b"PAYLOAD!");
    }

    #[test]
    fn ipv6_protocol_family_yields_ipv6_ethertype() {
        let body = b"v6stub";
        let packed = build_packed_record(0, "pdp_ip0", 1, "p", AF_INET6, 0, 0, 0, body);
        let rec = parse_pcapd_record_bytes(&packed).unwrap();
        let frame = build_pcap_record_payload(&rec);
        assert_eq!(&frame[12..14], &ETHERTYPE_IPV6.to_be_bytes());
    }

    #[test]
    fn parse_handles_extended_header_versions() {
        // Some firmwares set `header_length > 95` to reserve room for future fields. The parser
        // must skip those bytes and only return `data` from the offset the device declared.
        let body = b"abcd";
        let packed = build_packed_record(8, "en0", 9, "wifid", AF_INET, 14, 0, 0, body);
        let rec = parse_pcapd_record_bytes(&packed).unwrap();
        assert_eq!(rec.header_length, 95 + 8);
        assert_eq!(rec.data, body);
    }

    #[test]
    fn parse_rejects_truncated_payload_and_too_small_header() {
        // header_length < 95 must fail without panicking.
        let mut tiny = vec![0u8; 95];
        tiny[..4].copy_from_slice(&50u32.to_be_bytes());
        assert!(parse_pcapd_record_bytes(&tiny).is_err());

        // Promised packet_length larger than what we provided.
        let body = b"only-2";
        let mut packed = build_packed_record(0, "en0", 1, "x", AF_INET, 14, 0, 0, body);
        // Bump packet_length by 100 to make `total_needed` exceed buffer size.
        let lying = (body.len() as u32 + 100).to_be_bytes();
        packed[5..9].copy_from_slice(&lying);
        assert!(parse_pcapd_record_bytes(&packed).is_err());
    }

    #[test]
    fn parse_pcapd_message_unwraps_cfdata_blob() {
        let body = b"hello";
        let packed = build_packed_record(0, "en0", 1, "x", AF_INET, 14, 0, 0, body);
        let plist_bytes = {
            let mut buf = Vec::new();
            Value::Data(packed.clone())
                .to_writer_xml(&mut buf)
                .unwrap();
            buf
        };
        let rec = parse_pcapd_message(&plist_bytes).unwrap();
        assert_eq!(rec.data, body);
    }

    #[test]
    fn parse_pcapd_message_rejects_non_data_root() {
        let mut buf = Vec::new();
        Value::String("nope".into()).to_writer_xml(&mut buf).unwrap();
        // String is allowed (some firmwares emit binary as String); make sure we treat it as bytes
        // and then fail at the inner parse rather than the kind check.
        let err = parse_pcapd_message(&buf).unwrap_err();
        assert!(
            err.contains("short") || err.contains("header"),
            "unexpected error: {}",
            err
        );

        let mut dict_buf = Vec::new();
        Value::Dictionary(plist::Dictionary::new())
            .to_writer_xml(&mut dict_buf)
            .unwrap();
        let err = parse_pcapd_message(&dict_buf).unwrap_err();
        assert!(err.contains("Dictionary"), "unexpected error: {}", err);
    }

    #[test]
    fn pcap_global_header_layout_matches_libpcap_spec() {
        let h = build_pcap_global_header(PCAP_DEFAULT_SNAPLEN, LINKTYPE_ETHERNET);
        assert_eq!(h.len(), PCAP_GLOBAL_HEADER_LEN);
        assert_eq!(&h[..4], &PCAP_MAGIC_USEC_LE.to_le_bytes());
        assert_eq!(&h[4..6], &2u16.to_le_bytes());
        assert_eq!(&h[6..8], &4u16.to_le_bytes());
        assert_eq!(&h[8..12], &0i32.to_le_bytes());
        assert_eq!(&h[12..16], &0u32.to_le_bytes());
        assert_eq!(&h[16..20], &PCAP_DEFAULT_SNAPLEN.to_le_bytes());
        assert_eq!(&h[20..24], &LINKTYPE_ETHERNET.to_le_bytes());
    }

    #[test]
    fn pcap_record_header_uses_microsecond_resolution() {
        let h = build_pcap_record_header(0xdead_beef, 123_456, 999);
        assert_eq!(h.len(), PCAP_RECORD_HEADER_LEN);
        assert_eq!(&h[0..4], &0xdead_beef_u32.to_le_bytes());
        assert_eq!(&h[4..8], &123_456u32.to_le_bytes());
        assert_eq!(&h[8..12], &999u32.to_le_bytes());
        assert_eq!(&h[12..16], &999u32.to_le_bytes());
    }

    #[test]
    fn ethertype_for_protocol_family_defaults_to_ipv4() {
        assert_eq!(ethertype_for_protocol_family(AF_INET), ETHERTYPE_IPV4);
        assert_eq!(ethertype_for_protocol_family(AF_INET6), ETHERTYPE_IPV6);
        assert_eq!(ethertype_for_protocol_family(0xff), ETHERTYPE_IPV4);
    }

    #[test]
    fn interface_type_label_recognises_known_apple_values() {
        assert_eq!(interface_type_label(PCAPD_IFACE_CELLULAR), "wwanPP");
        assert_eq!(interface_type_label(PCAPD_IFACE_ETHERNET), "ethernetCsmacd");
        assert_eq!(interface_type_label(PCAPD_IFACE_LOOPBACK), "softwareLoopback");
        assert_eq!(interface_type_label(0), "ifType=0");
    }

    #[test]
    fn protocol_family_label_covers_known_families() {
        assert_eq!(protocol_family_label(AF_UNSPEC), "AF_UNSPEC");
        assert_eq!(protocol_family_label(AF_INET), "AF_INET");
        assert_eq!(protocol_family_label(AF_INET6), "AF_INET6");
        assert_eq!(protocol_family_label(99), "AF_other");
    }
}
