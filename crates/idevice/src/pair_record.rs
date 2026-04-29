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

/// **`<save-dir>/<usb_serial>.plist`** under [`default_pair_record_save_dir`]. Strips
/// control bytes, slashes, and whitespace from the serial so a noisy USB string descriptor
/// (some Apple devices pad with NUL — see `usb::sanitize_usb_descriptor_string`) never
/// produces a path that `std::fs::write` rejects with `file name contained an unexpected
/// NUL byte`.
pub fn default_pair_record_save_path(usb_serial: &str) -> Result<PathBuf, String> {
    let serial: String = usb_serial
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .collect::<String>()
        .trim()
        .to_string();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Several tests in this module mutate `XDG_CONFIG_HOME` / `HOME` — Cargo runs tests in
    /// parallel by default, so we serialize all env-touching tests behind one mutex to keep
    /// observations deterministic.
    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// rusb has been observed returning a USB serial with a trailing NUL byte on some
    /// Apple devices; without sanitization this becomes a path that `std::fs::write`
    /// rejects with "file name contained an unexpected NUL byte". Make sure
    /// [`default_pair_record_save_path`] strips controls so the resulting filename is
    /// safe for `CString`-based syscalls.
    #[test]
    fn save_path_strips_nul_and_control_bytes_from_serial() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/idevice-rs-test-config");
        let p = default_pair_record_save_path("00008150000A62342613401C\0").unwrap();
        let s = p.to_str().unwrap();
        assert!(
            !s.as_bytes().contains(&0),
            "save path still contains a NUL byte: {:?}",
            s
        );
        assert!(s.ends_with("00008150000A62342613401C.plist"), "got {}", s);
    }

    #[test]
    fn save_path_rejects_empty_or_only_control_serial() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/idevice-rs-test-config");
        assert!(default_pair_record_save_path("").is_err());
        assert!(default_pair_record_save_path("\0\0\0").is_err());
    }

    /// Both branches of `default_pair_record_save_dir()` are exercised together so we don't
    /// race with the other tests that also mutate `XDG_CONFIG_HOME` / `HOME`.
    #[test]
    fn default_pair_record_save_dir_xdg_then_home_fallback() {
        let _g = env_lock().lock().unwrap();
        let prev_x = std::env::var_os("XDG_CONFIG_HOME");
        let prev_h = std::env::var_os("HOME");

        std::env::set_var("XDG_CONFIG_HOME", "/tmp/idevice-rs-test-cfg-x");
        let p = default_pair_record_save_dir().unwrap();
        assert!(p.starts_with("/tmp/idevice-rs-test-cfg-x"));
        assert!(p.ends_with("idevice-rs/pair-records"));

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_var("HOME", "/tmp/idevice-rs-fake-home");
        let p = default_pair_record_save_dir().unwrap();
        assert!(p.starts_with("/tmp/idevice-rs-fake-home/.config"));
        assert!(p.ends_with("idevice-rs/pair-records"));

        match prev_x {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match prev_h {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn resolve_pair_record_path_with_explicit_existing_file() {
        let tmp = std::env::temp_dir().join("idevice-rs-pr-explicit.plist");
        std::fs::write(&tmp, b"x").unwrap();
        let r = resolve_pair_record_path(
            &Some(tmp.clone()),
            &None,
            "ignored-serial",
        )
        .unwrap();
        assert_eq!(r, Some(tmp.clone()));
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn resolve_pair_record_path_errors_when_explicit_missing() {
        let tmp = std::path::PathBuf::from("/tmp/idevice-rs-does-not-exist.plist");
        let _ = std::fs::remove_file(&tmp);
        let err = resolve_pair_record_path(&Some(tmp.clone()), &None, "abc")
            .unwrap_err();
        assert!(err.contains("--pair-record"));
    }

    #[test]
    fn resolve_pair_record_path_uses_dir_when_serial_file_present() {
        let dir = std::env::temp_dir().join("idevice-rs-pr-dir");
        std::fs::create_dir_all(&dir).unwrap();
        let serial = "TESTSERIAL12345";
        let p = dir.join(format!("{}.plist", serial));
        std::fs::write(&p, b"x").unwrap();
        let r = resolve_pair_record_path(&None, &Some(dir.clone()), serial).unwrap();
        assert_eq!(r, Some(p.clone()));
        std::fs::remove_file(&p).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn resolve_pair_record_path_returns_none_when_no_dir_and_no_explicit() {
        let r = resolve_pair_record_path(&None, &None, "abc").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn resolve_pair_record_path_errors_when_dir_set_but_serial_file_missing() {
        let dir = std::env::temp_dir().join("idevice-rs-pr-dir-empty");
        std::fs::create_dir_all(&dir).unwrap();
        let err = resolve_pair_record_path(&None, &Some(dir.clone()), "MISSING").unwrap_err();
        assert!(err.contains("MISSING.plist"));
        std::fs::remove_dir(&dir).ok();
    }

    /// Round-trip the on-disk pair record format. We craft a fake [`HostKeys`] with PEM strings
    /// (no real RSA — `save_pair_record_plist` only treats them as bytes) and verify the
    /// resulting plist re-reads as the same dict.
    #[test]
    fn save_pair_record_plist_round_trips_through_xml() {
        let keys = HostKeys {
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nHOST\n-----END PRIVATE KEY-----\n".into(),
            host_cert_pem: "-----BEGIN CERTIFICATE-----\nHOST_CERT\n-----END CERTIFICATE-----\n"
                .into(),
            root_cert_pem: "-----BEGIN CERTIFICATE-----\nROOT_CERT\n-----END CERTIFICATE-----\n"
                .into(),
            root_private_pem: "-----BEGIN PRIVATE KEY-----\nROOT\n-----END PRIVATE KEY-----\n"
                .into(),
            host_cert_der: vec![1, 2, 3],
            root_cert_der: vec![4, 5, 6],
            private_key_der: vec![7, 8, 9],
            root_private_der: vec![10, 11, 12],
            root_ca: None,
        };
        let ids = idevice_usb_core::PairingIds {
            host_id: "HOST-ID-XYZ".into(),
            system_buid: "BUID-ZZZ".into(),
        };
        let path = std::env::temp_dir().join("idevice-rs-roundtrip.plist");
        let _ = std::fs::remove_file(&path);

        save_pair_record_plist(
            &path,
            &keys,
            &ids,
            "-----BEGIN CERTIFICATE-----\nDEVICE\n-----END CERTIFICATE-----\n",
            Some("aa:bb:cc:dd:ee:ff"),
            Some(b"escrow-bytes"),
        )
        .unwrap();

        let raw = std::fs::read(&path).unwrap();
        let v: plist::Value = plist::from_bytes(&raw).unwrap();
        let dict = v.as_dictionary().unwrap();
        assert_eq!(dict.get("HostID").unwrap().as_string().unwrap(), "HOST-ID-XYZ");
        assert_eq!(dict.get("SystemBUID").unwrap().as_string().unwrap(), "BUID-ZZZ");
        assert_eq!(
            dict.get("WiFiMACAddress").unwrap().as_string().unwrap(),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            dict.get("EscrowBag").unwrap().as_data().unwrap(),
            b"escrow-bytes"
        );
        // Cert / key fields are CFData (PEM bytes) — same shape libimobiledevice writes.
        for k in [
            "DeviceCertificate",
            "HostCertificate",
            "HostPrivateKey",
            "RootCertificate",
            "RootPrivateKey",
        ] {
            let bytes = dict.get(k).unwrap().as_data().unwrap();
            assert!(
                std::str::from_utf8(bytes)
                    .unwrap()
                    .contains("-----BEGIN"),
                "{} should be PEM bytes",
                k
            );
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_pair_record_plist_skips_empty_wifi_and_escrow() {
        let keys = HostKeys {
            private_key_pem: "P".into(),
            host_cert_pem: "H".into(),
            root_cert_pem: "R".into(),
            root_private_pem: "RP".into(),
            host_cert_der: vec![],
            root_cert_der: vec![],
            private_key_der: vec![],
            root_private_der: vec![],
            root_ca: None,
        };
        let ids = idevice_usb_core::PairingIds {
            host_id: "H".into(),
            system_buid: "B".into(),
        };
        let path = std::env::temp_dir().join("idevice-rs-skip-optional.plist");
        let _ = std::fs::remove_file(&path);

        save_pair_record_plist(&path, &keys, &ids, "D", Some(""), Some(b"")).unwrap();
        let v: plist::Value = plist::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        let d = v.as_dictionary().unwrap();
        assert!(d.get("WiFiMACAddress").is_none());
        assert!(d.get("EscrowBag").is_none());
        std::fs::remove_file(&path).ok();
    }
}
