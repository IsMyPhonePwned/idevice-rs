//! Open a [`crate::lockdown::LockdownClient`]: try **direct USB** first, then **usbmuxd** (Unix) when the device is busy (`Resource busy` / `set_active_configuration`).
//!
//! Use [`open_lockdown_for_cli`] when you need the **USB serial string** (or usbmuxd UDID) for pair-record path resolution.

use std::path::Path;

use crate::lockdown::LockdownClient;

/// Arguments needed to pick a device and resolve pairing metadata.
#[derive(Debug, Clone, Copy)]
pub struct LockdownConnectArgs<'a> {
    pub bus: Option<u8>,
    pub addr: Option<u8>,
    pub serial: Option<&'a str>,
    pub pair_record: Option<&'a Path>,
}

fn usb_open_busy(err: &str) -> bool {
    err.contains("set_active_configuration")
        || err.contains("Resource busy")
        || err.contains("claim_interface")
        || err.contains("Could not claim")
        || err.contains("LIBUSB_ERROR_BUSY")
}

#[cfg(unix)]
fn try_usbmuxd(args: LockdownConnectArgs<'_>) -> Result<LockdownClient, String> {
    let path = crate::usbmuxd::default_socket_path();
    if !path.exists() {
        return Err(format!(
            "usbmuxd socket not found at {} (set USBMUXD_SOCKET_PATH if non-standard)",
            path.display()
        ));
    }
    let udid = resolve_udid_usbmux(args)?;
    let device_id = crate::usbmuxd::device_id_for_udid(&path, &udid)?;
    crate::console_log!(
        "[connect] Using usbmuxd {} — device_id={} udid={}",
        path.display(),
        device_id,
        udid
    );
    let stream = crate::usbmuxd::connect_device_port(
        &path,
        device_id,
        idevice_usb_core::lockdown_proto::LOCKDOWND_PORT,
    )?;
    LockdownClient::new_usbmuxd(stream, path, device_id)
}

#[cfg(unix)]
fn resolve_udid_usbmux(args: LockdownConnectArgs<'_>) -> Result<String, String> {
    if let Some(s) = args.serial {
        let t = s.trim();
        if !t.is_empty() {
            return Ok(crate::usbmuxd::normalize_udid_str(t));
        }
    }
    if let Some(p) = args.pair_record {
        if let Some(stem) = p.file_stem().and_then(|x| x.to_str()) {
            let stem = stem.trim();
            if stem.contains('-') || stem.len() >= 8 {
                return Ok(crate::usbmuxd::normalize_udid_str(stem));
            }
        }
    }
    let list = crate::usbmuxd::list_devices(&crate::usbmuxd::default_socket_path())?;
    list
        .into_iter()
        .next()
        .map(|d| d.udid)
        .ok_or_else(|| {
            "usbmuxd: no USB devices (plug in iPhone, unlock, trust this computer)".to_string()
        })
}

/// USB serial string (or UDID when using usbmuxd) plus an open [`LockdownClient`].
pub fn open_lockdown_for_cli(
    args: LockdownConnectArgs<'_>,
) -> Result<(String, LockdownClient), String> {
    match crate::usb::open_apple(args.bus, args.addr, args.serial) {
        Ok(mut usb) => {
            let ser = crate::usb::usb_serial_for_pair_record(&mut usb)?;
            let client = LockdownClient::new(usb)?;
            Ok((ser, client))
        }
        #[cfg(unix)]
        Err(e) if usb_open_busy(&e) => {
            crate::console_log!("[connect] Direct USB: {} — using usbmuxd tunnel…", e);
            let client = try_usbmuxd(args)?;
            let ser = resolve_udid_usbmux(args)?;
            Ok((ser, client))
        }
        Err(e) => Err(e),
    }
}

/// Same as [`open_lockdown_for_cli`] but discards the serial string.
pub fn open_lockdown(args: LockdownConnectArgs<'_>) -> Result<LockdownClient, String> {
    open_lockdown_for_cli(args).map(|(_, c)| c)
}
