//! Big-endian mux constants and static packets (matches usbmuxd `device.c`).

pub const APPLE_VENDOR_CLASS: u8 = 255;
pub const APPLE_VENDOR_SUBCLASS: u8 = 254;

pub const MUX_PROTO_VERSION: u32 = 0;
/// Device → host control / status (see `usbmuxd` `MUX_PROTO_CONTROL` / `device_control_input`).
pub const MUX_PROTO_CONTROL: u32 = 1;
pub const MUX_PROTO_SETUP: u32 = 2;
pub const MUX_PROTO_TCP: u32 = 6;

pub const MUX_MAGIC: u32 = 0xfeedface;

/// usbmuxd uses `tx_win = 131072` and `th_win = htons(tx_win >> 8)` in `send_tcp`.
pub const MUX_TCP_WINDOW: u32 = 131_072;

/// Appended to WebUSB `selectConfiguration` errors on Linux (browser + native CLI).
pub const SELECT_CONFIGURATION_FAILED_LINUX_HINT: &str = "\n\n\
On Linux, another stack often holds the device. In a terminal (then unplug/replug the cable and retry):\n\
  sudo systemctl stop usbmuxd\n\
  sudo systemctl stop usbmuxd.socket   # if usbmuxd is socket-activated and still respawns\n\
  sudo modprobe -r ipheth              # iPhone USB Ethernet; stop any network using that NIC first\n\
  systemctl --user stop gvfs-afc-volume-monitor.service";

/// Appended for **WebUSB** (browser) only: native tools can still work via usbmuxd while Chromium cannot.
pub const WEBUSB_CHROMIUM_USB_BUSY_EXPLAINER: &str = "\n\n\
A native stack may still reach the device over **usbmuxd** (`/var/run/usbmuxd`) while **Chromium WebUSB** cannot use that path — it must claim the USB interface directly. \
Either free the device for WebUSB using the hints above, or keep using a native client with usbmuxd.";

#[inline]
pub fn build_mux_version_request() -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0..4].copy_from_slice(&MUX_PROTO_VERSION.to_be_bytes());
    b[4..8].copy_from_slice(&20u32.to_be_bytes());
    b[8..12].copy_from_slice(&2u32.to_be_bytes());
    b[12..16].copy_from_slice(&0u32.to_be_bytes());
    b[16..20].copy_from_slice(&0u32.to_be_bytes());
    b
}

pub fn parse_mux_version_response(buf: &[u8]) -> Result<(u8, u8), String> {
    if buf.len() < 20 {
        return Err(format!("mux version reply too short: {} bytes", buf.len()));
    }
    let proto = u32::from_be_bytes(buf[0..4].try_into().map_err(|_| "proto")?);
    if proto != MUX_PROTO_VERSION {
        return Err(format!("expected mux VERSION (0), got protocol {}", proto));
    }
    let declared = u32::from_be_bytes(buf[4..8].try_into().map_err(|_| "len")?);
    if declared as usize > buf.len() {
        return Err(format!(
            "mux version length {} exceeds buffer {}",
            declared,
            buf.len()
        ));
    }
    let major = u32::from_be_bytes(buf[8..12].try_into().map_err(|_| "major")?);
    let minor = u32::from_be_bytes(buf[12..16].try_into().map_err(|_| "minor")?);
    if major != 1 && major != 2 {
        return Err(format!("unsupported mux version {}.{}", major, minor));
    }
    Ok((major as u8, minor as u8))
}

/// `MUX_PROTO_SETUP` with 1-byte payload `0x07` after mux v2 header (`device_version_input` in usbmuxd).
#[inline]
pub fn build_mux_setup_packet_v2() -> [u8; 17] {
    let mut b = [0u8; 17];
    b[0..4].copy_from_slice(&MUX_PROTO_SETUP.to_be_bytes());
    b[4..8].copy_from_slice(&17u32.to_be_bytes());
    b[8..12].copy_from_slice(&MUX_MAGIC.to_be_bytes());
    b[12..14].copy_from_slice(&0u16.to_be_bytes());
    b[14..16].copy_from_slice(&0xFFFFu16.to_be_bytes());
    b[16] = 0x07;
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_request_matches_usbmuxd_layout() {
        let v = build_mux_version_request();
        assert_eq!(v.len(), 20);
        // protocol = MUX_PROTO_VERSION (0)
        assert_eq!(u32::from_be_bytes(v[0..4].try_into().unwrap()), 0);
        // declared length = 20
        assert_eq!(u32::from_be_bytes(v[4..8].try_into().unwrap()), 20);
        // major = 2
        assert_eq!(u32::from_be_bytes(v[8..12].try_into().unwrap()), 2);
        // minor = 0
        assert_eq!(u32::from_be_bytes(v[12..16].try_into().unwrap()), 0);
        // tail = 0
        assert_eq!(u32::from_be_bytes(v[16..20].try_into().unwrap()), 0);
    }

    #[test]
    fn parse_version_response_accepts_v1_and_v2() {
        // Build a fake VERSION reply: protocol=0 length=20 major=2 minor=0 …
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&MUX_PROTO_VERSION.to_be_bytes());
        buf[4..8].copy_from_slice(&20u32.to_be_bytes());
        buf[8..12].copy_from_slice(&2u32.to_be_bytes());
        buf[12..16].copy_from_slice(&0u32.to_be_bytes());
        let (maj, min) = parse_mux_version_response(&buf).unwrap();
        assert_eq!((maj, min), (2, 0));

        buf[8..12].copy_from_slice(&1u32.to_be_bytes());
        let (maj, _) = parse_mux_version_response(&buf).unwrap();
        assert_eq!(maj, 1);
    }

    #[test]
    fn parse_version_response_rejects_short_or_wrong_proto() {
        assert!(parse_mux_version_response(&[0u8; 4]).is_err());

        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&7u32.to_be_bytes());
        buf[4..8].copy_from_slice(&20u32.to_be_bytes());
        assert!(parse_mux_version_response(&buf).is_err());

        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&MUX_PROTO_VERSION.to_be_bytes());
        buf[4..8].copy_from_slice(&20u32.to_be_bytes());
        buf[8..12].copy_from_slice(&7u32.to_be_bytes()); // unsupported major
        assert!(parse_mux_version_response(&buf).is_err());
    }

    #[test]
    fn parse_version_response_rejects_bad_declared_length() {
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&MUX_PROTO_VERSION.to_be_bytes());
        // declared > buffer
        buf[4..8].copy_from_slice(&999u32.to_be_bytes());
        buf[8..12].copy_from_slice(&2u32.to_be_bytes());
        assert!(parse_mux_version_response(&buf).is_err());
    }

    #[test]
    fn setup_packet_v2_has_magic_and_payload_byte() {
        let s = build_mux_setup_packet_v2();
        assert_eq!(s.len(), 17);
        // protocol = MUX_PROTO_SETUP (2)
        assert_eq!(u32::from_be_bytes(s[0..4].try_into().unwrap()), MUX_PROTO_SETUP);
        // length = 17
        assert_eq!(u32::from_be_bytes(s[4..8].try_into().unwrap()), 17);
        // mux magic
        assert_eq!(u32::from_be_bytes(s[8..12].try_into().unwrap()), MUX_MAGIC);
        // tx seq = 0, rx seq = 0xFFFF (so first device frame can have tx seq 1)
        assert_eq!(u16::from_be_bytes([s[12], s[13]]), 0);
        assert_eq!(u16::from_be_bytes([s[14], s[15]]), 0xFFFF);
        // payload byte = 0x07 (SETUP "v2 capable" indicator)
        assert_eq!(s[16], 0x07);
    }

    #[test]
    fn proto_constants_match_usbmuxd_values() {
        assert_eq!(MUX_PROTO_VERSION, 0);
        assert_eq!(MUX_PROTO_CONTROL, 1);
        assert_eq!(MUX_PROTO_SETUP, 2);
        assert_eq!(MUX_PROTO_TCP, 6);
        assert_eq!(MUX_MAGIC, 0xfeedface);
        assert_eq!(MUX_TCP_WINDOW, 131_072);
    }
}
