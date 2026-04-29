//! Talk to **usbmuxd** over a Unix socket (Linux/macOS) — same path as libimobiledevice when the daemon owns the USB device.
//!
//! Direct libusb fails with `Resource busy` / `set_active_configuration` when **usbmuxd** is running; this module connects through **`/var/run/usbmuxd`** instead.

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use plist::{Dictionary, Integer, Value};
use std::os::unix::net::UnixStream;

const MESSAGE_RESULT: u32 = 1;
const MESSAGE_PLIST: u32 = 8;
const PLIST_LIBUSBMUX_VERSION: u64 = 3;

fn next_tag() -> u32 {
    static TAG: AtomicU32 = AtomicU32::new(1);
    TAG.fetch_add(1, Ordering::Relaxed)
}

/// Default usbmuxd socket; override with env **`USBMUXD_SOCKET_PATH`**.
pub fn default_socket_path() -> PathBuf {
    std::env::var_os("USBMUXD_SOCKET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run/usbmuxd"))
}

#[derive(Clone, Debug)]
pub struct UsbMuxDevice {
    pub device_id: u32,
    pub udid: String,
}

fn base_plist_dict(message_type: &str) -> Dictionary {
    let mut d = Dictionary::new();
    d.insert(
        "BundleID".into(),
        Value::String("org.idevice-rs.idevice".into()),
    );
    d.insert(
        "ClientVersionString".into(),
        Value::String("idevice-rs 0.1".into()),
    );
    d.insert(
        "MessageType".into(),
        Value::String(message_type.into()),
    );
    d.insert("ProgName".into(), Value::String("idevice".into()));
    d.insert(
        "kLibUSBMuxVersion".into(),
        Value::Integer(Integer::from(PLIST_LIBUSBMUX_VERSION)),
    );
    d
}

fn write_frame(stream: &mut UnixStream, version: u32, message: u32, tag: u32, payload: &[u8]) -> Result<(), String> {
    let length = (16 + payload.len()) as u32;
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&length.to_le_bytes());
    hdr[4..8].copy_from_slice(&version.to_le_bytes());
    hdr[8..12].copy_from_slice(&message.to_le_bytes());
    hdr[12..16].copy_from_slice(&tag.to_le_bytes());
    stream.write_all(&hdr).map_err(|e| e.to_string())?;
    stream.write_all(payload).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn send_plist_xml(stream: &mut UnixStream, tag: u32, dict: &Dictionary) -> Result<(), String> {
    let root = Value::Dictionary(dict.clone());
    let mut xml = Vec::new();
    root.to_writer_xml(&mut xml)
        .map_err(|e| format!("plist to xml: {}", e))?;
    write_frame(stream, 1, MESSAGE_PLIST, tag, &xml)
}

fn read_frame(stream: &mut UnixStream) -> Result<(u32, u32, u32, Vec<u8>), String> {
    let mut h = [0u8; 16];
    stream.read_exact(&mut h).map_err(|e| e.to_string())?;
    let length = u32::from_le_bytes(h[0..4].try_into().unwrap()) as usize;
    let version = u32::from_le_bytes(h[4..8].try_into().unwrap());
    let message = u32::from_le_bytes(h[8..12].try_into().unwrap());
    let tag = u32::from_le_bytes(h[12..16].try_into().unwrap());
    if length < 16 {
        return Err(format!("usbmuxd: invalid length {}", length));
    }
    let plen = length - 16;
    let mut payload = vec![0u8; plen];
    stream.read_exact(&mut payload).map_err(|e| e.to_string())?;
    Ok((version, message, tag, payload))
}

/// Read one reply whose **tag** matches `expect_tag`. Handles **MESSAGE_RESULT** (binary) or **MESSAGE_PLIST** (XML).
fn read_reply_for_tag(
    stream: &mut UnixStream,
    expect_tag: u32,
) -> Result<(u32, Option<Value>), String> {
    for _ in 0..64 {
        let (_ver, message, tag, payload) = read_frame(stream)?;
        if tag != expect_tag {
            continue;
        }
        if message == MESSAGE_RESULT {
            if payload.len() < 4 {
                return Err("usbmuxd: short RESULT".into());
            }
            let code = u32::from_le_bytes(payload[0..4].try_into().unwrap());
            return Ok((code, None));
        }
        if message == MESSAGE_PLIST {
            let v = Value::from_reader_xml(Cursor::new(&payload))
                .map_err(|e| format!("usbmuxd plist parse: {}", e))?;
            return Ok((0, Some(v)));
        }
        return Err(format!("usbmuxd: unexpected message type {}", message));
    }
    Err("usbmuxd: no matching reply (tag)".into())
}

/// Normalizes **SerialNumber** from usbmuxd (24 hex chars without hyphen → UDID shape).
pub fn normalize_udid_str(s: &str) -> String {
    let mut t = s.trim().to_string();
    if t.len() == 24 && !t.contains('-') {
        t.insert(8, '-');
    }
    t
}

fn udid_from_props(props: &Dictionary) -> Option<String> {
    let n = props.get("SerialNumber")?;
    if let Value::String(s) = n {
        let t = s.trim().to_string();
        if !t.is_empty() {
            return Some(normalize_udid_str(&t));
        }
    }
    None
}

fn device_id_from_props(props: &Dictionary) -> Option<u32> {
    let n = props.get("DeviceID")?;
    match n {
        Value::Integer(i) => (*i).as_unsigned().map(|u| u as u32),
        Value::Uid(u) => Some(u.get() as u32),
        _ => None,
    }
}

fn connection_type_usb(props: &Dictionary) -> bool {
    match props.get("ConnectionType") {
        Some(Value::String(s)) => s == "USB",
        _ => false,
    }
}

/// List devices known to usbmuxd (USB and network; callers often filter to USB).
pub fn list_devices(socket_path: &Path) -> Result<Vec<UsbMuxDevice>, String> {
    let mut s = UnixStream::connect(socket_path)
        .map_err(|e| format!("usbmuxd connect {}: {}", socket_path.display(), e))?;
    let tag = next_tag();
    let dict = base_plist_dict("ListDevices");
    send_plist_xml(&mut s, tag, &dict)?;

    let (_code, val) = read_reply_for_tag(&mut s, tag)?;
    let root = val.ok_or_else(|| "usbmuxd: empty ListDevices reply".to_string())?;
    let devlist = match root {
        Value::Dictionary(mut d) => d
            .remove("DeviceList")
            .ok_or_else(|| "usbmuxd: no DeviceList".to_string())?,
        _ => return Err("usbmuxd: ListDevices root not dict".into()),
    };
    let arr = match devlist {
        Value::Array(a) => a,
        _ => return Err("usbmuxd: DeviceList not array".into()),
    };

    let mut out = Vec::new();
    for item in arr {
        let ent = match item {
            Value::Dictionary(d) => d,
            _ => continue,
        };
        let props = match ent.get("Properties") {
            Some(Value::Dictionary(p)) => p,
            _ => continue,
        };
        if !connection_type_usb(props) {
            continue;
        }
        let Some(udid) = udid_from_props(props) else {
            continue;
        };
        let Some(device_id) = device_id_from_props(props) else {
            continue;
        };
        out.push(UsbMuxDevice { device_id, udid });
    }
    Ok(out)
}

/// `port` in **host** byte order (e.g. 62078 for lockdownd). Encoded like libusbmuxd: **`htons(port)`** as plist integer.
pub fn connect_device_port(socket_path: &Path, device_id: u32, port: u16) -> Result<UnixStream, String> {
    let mut s = UnixStream::connect(socket_path)
        .map_err(|e| format!("usbmuxd connect {}: {}", socket_path.display(), e))?;
    let tag = next_tag();
    let mut dict = base_plist_dict("Connect");
    dict.insert(
        "DeviceID".into(),
        Value::Integer(Integer::from(device_id as u64)),
    );
    let port_net = (port as u16).to_be() as u32;
    dict.insert(
        "PortNumber".into(),
        Value::Integer(Integer::from(port_net as u64)),
    );
    send_plist_xml(&mut s, tag, &dict)?;

    let (code, _) = read_reply_for_tag(&mut s, tag)?;
    if code != 0 {
        return Err(format!(
            "usbmuxd Connect failed (code {}); is the device unlocked and trusted?",
            code
        ));
    }
    Ok(s)
}

/// Resolve **device_id** for a UDID string (USB devices only).
pub fn device_id_for_udid(socket_path: &Path, udid: &str) -> Result<u32, String> {
    let udid_norm = udid.trim();
    for d in list_devices(socket_path)? {
        if d.udid == udid_norm {
            return Ok(d.device_id);
        }
    }
    Err(format!(
        "usbmuxd: no USB device with UDID/serial matching `{}`",
        udid_norm
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_udid_inserts_dash_after_8_hex_when_missing() {
        // 24 hex chars without a hyphen → libusbmuxd `SerialNumber` shape →
        // canonical UDID `<8>-<16>` like Apple's idevicepair output.
        assert_eq!(
            normalize_udid_str("00008150000A62342613401C"),
            "00008150-000A62342613401C"
        );
    }

    #[test]
    fn normalize_udid_keeps_already_dashed_strings() {
        let input = "00008150-000A62342613401C";
        assert_eq!(normalize_udid_str(input), input);
    }

    #[test]
    fn normalize_udid_trims_surrounding_whitespace() {
        assert_eq!(
            normalize_udid_str("  00008150000A62342613401C  "),
            "00008150-000A62342613401C"
        );
    }

    #[test]
    fn normalize_udid_does_not_reformat_short_strings() {
        assert_eq!(normalize_udid_str("short"), "short");
        assert_eq!(
            normalize_udid_str("not-quite-twenty-four-chars"),
            "not-quite-twenty-four-chars"
        );
    }

    /// Both branches of `default_socket_path()` are exercised here in a single test so the
    /// `USBMUXD_SOCKET_PATH` env mutation can't race against another in-process test.
    #[test]
    fn default_socket_path_honours_env_override_or_falls_back() {
        let key = "USBMUXD_SOCKET_PATH";
        let prev = std::env::var_os(key);
        std::env::set_var(key, "/tmp/idevice-rs-test-usbmuxd.sock");
        assert_eq!(
            default_socket_path(),
            PathBuf::from("/tmp/idevice-rs-test-usbmuxd.sock")
        );
        std::env::remove_var(key);
        assert_eq!(default_socket_path(), PathBuf::from("/var/run/usbmuxd"));
        if let Some(v) = prev {
            std::env::set_var(key, v);
        }
    }

    #[test]
    fn next_tag_returns_monotonic_increasing_values() {
        let a = next_tag();
        let b = next_tag();
        let c = next_tag();
        assert!(b > a && c > b, "next_tag() must be strictly increasing");
    }

    #[test]
    fn base_plist_dict_emits_well_known_libusbmux_fields() {
        let d = base_plist_dict("ListDevices");
        let mt = d
            .get("MessageType")
            .and_then(|v| v.as_string())
            .unwrap_or("");
        assert_eq!(mt, "ListDevices");
        let v = d
            .get("kLibUSBMuxVersion")
            .and_then(|v| v.as_unsigned_integer())
            .unwrap_or(0);
        assert_eq!(v, PLIST_LIBUSBMUX_VERSION);
        assert!(d.get("BundleID").is_some());
        assert!(d.get("ClientVersionString").is_some());
        assert!(d.get("ProgName").is_some());
    }
}
