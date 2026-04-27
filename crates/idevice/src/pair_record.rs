//! Load **and save** **libimobiledevice**-style pairing plists (e.g.
//! **`/var/lib/lockdown/<UDID>.plist`** on Linux when **usbmuxd** is running, or our default
//! cache **`$XDG_CONFIG_HOME/idevice-rs/pair-records/<UDID>.plist`** when running direct-USB).

use std::path::{Path, PathBuf};

use idevice_usb_core::PairingIds;

use crate::crypto::HostKeys;

/// Read a `.plist` and build [`HostKeys`] + [`PairingIds`] for `StartSession` / TLS.
pub fn load_pair_record(path: &Path) -> Result<(HostKeys, PairingIds), String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    crate::pair_record_parse::load_pair_record_plist_bytes(&data)
}

/// Resolve plist path: explicit `--pair-record`, or `<dir>/<usb_serial>.plist`.
pub fn resolve_pair_record_path(
    explicit: &Option<PathBuf>,
    dir: &Option<PathBuf>,
    usb_serial: &str,
) -> Result<Option<PathBuf>, String> {
    if let Some(p) = explicit {
        if !p.exists() {
            return Err(format!("--pair-record: no file at {}", p.display()));
        }
        return Ok(Some(p.clone()));
    }
    if let Some(d) = dir {
        let path = d.join(format!("{}.plist", usb_serial.trim()));
        if path.exists() {
            return Ok(Some(path));
        }
        return Err(format!(
            "No pair record at {} (copy from the system that paired this device, or pass `--pair-record PATH`)",
            path.display()
        ));
    }
    Ok(None)
}

/// **`$XDG_CONFIG_HOME/idevice-rs/pair-records/<usb_serial>.plist`** (or
/// **`$HOME/.config/idevice-rs/pair-records/<usb_serial>.plist`**) — the cache where
/// **`idevice pair`** persists the libimobiledevice-shape pair record after a successful
/// **`Pair`** so subsequent **`battery`** / **`diagnostics`** / **`syslog`** /
/// **`crash-reports`** runs can skip **`Pair`** entirely (no Trust prompt, fast TLS resume).
///
/// This intentionally **does not** use **`/var/lib/lockdown/`** — that directory is owned by
/// **usbmuxd** and writing into it would conflict with it. We keep our own cache.
pub fn default_pair_record_save_dir() -> Result<PathBuf, String> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.join(".config"))
        })
        .ok_or_else(|| {
            "Cannot determine $XDG_CONFIG_HOME or $HOME for the pair-record cache".to_string()
        })?;
    Ok(base.join("idevice-rs").join("pair-records"))
}

/// **`<save-dir>/<usb_serial>.plist`** under [`default_pair_record_save_dir`].
pub fn default_pair_record_save_path(usb_serial: &str) -> Result<PathBuf, String> {
    let serial = usb_serial.trim();
    if serial.is_empty() {
        return Err("Empty USB serial — cannot derive a default pair-record path".into());
    }
    Ok(default_pair_record_save_dir()?.join(format!("{}.plist", serial)))
}

/// Persist a libimobiledevice-shape pair-record plist (XML) to disk after a **successful**
/// **`Pair`**. Layout matches what **`idevicepair pair`** writes to
/// **`/var/lib/lockdown/<UDID>.plist`** so the same plist works with our loader, with
/// **`pymobiledevice3 --pair-record`**, and with **idevicepair**:
///
/// **`DeviceCertificate`**, **`HostCertificate`**, **`HostPrivateKey`**, **`RootCertificate`**,
/// **`RootPrivateKey`** — all CFData (PEM bytes); **`HostID`**, **`SystemBUID`**,
/// **`WiFiMACAddress`** — strings (last one optional); **`EscrowBag`** — CFData (raw bytes
/// from the success reply, optional on iOS releases that don't send one).
///
/// Parent directories are created on demand. Permissions are kept default — host private
/// keys land here, so users running shared accounts may want to **`chmod 600`** the result.
pub fn save_pair_record_plist(
    path: &Path,
    keys: &HostKeys,
    ids: &PairingIds,
    device_cert_pem: &str,
    wifi_mac: Option<&str>,
    escrow_bag: Option<&[u8]>,
) -> Result<(), String> {
    let mut dict = plist::Dictionary::new();
    let push_pem = |d: &mut plist::Dictionary, key: &str, pem: &str| {
        d.insert(key.into(), plist::Value::Data(pem.as_bytes().to_vec()));
    };
    push_pem(&mut dict, "DeviceCertificate", device_cert_pem);
    push_pem(&mut dict, "HostCertificate", &keys.host_cert_pem);
    push_pem(&mut dict, "HostPrivateKey", &keys.private_key_pem);
    push_pem(&mut dict, "RootCertificate", &keys.root_cert_pem);
    push_pem(&mut dict, "RootPrivateKey", &keys.root_private_pem);
    dict.insert("HostID".into(), plist::Value::String(ids.host_id.clone()));
    dict.insert(
        "SystemBUID".into(),
        plist::Value::String(ids.system_buid.clone()),
    );
    if let Some(mac) = wifi_mac {
        if !mac.is_empty() {
            dict.insert("WiFiMACAddress".into(), plist::Value::String(mac.into()));
        }
    }
    if let Some(bag) = escrow_bag {
        if !bag.is_empty() {
            dict.insert("EscrowBag".into(), plist::Value::Data(bag.to_vec()));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create {}: {}", parent.display(), e))?;
    }
    let value = plist::Value::Dictionary(dict);
    let mut buf: Vec<u8> = Vec::new();
    value
        .to_writer_xml(&mut buf)
        .map_err(|e| format!("plist xml encode: {}", e))?;
    std::fs::write(path, &buf).map_err(|e| format!("write {}: {}", path.display(), e))?;
    Ok(())
}
