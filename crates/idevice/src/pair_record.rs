//! Load **libimobiledevice**-style pairing plists (e.g. `/var/lib/lockdown/<UDID>.plist`).

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
