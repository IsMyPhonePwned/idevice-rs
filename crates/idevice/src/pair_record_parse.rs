//! Shared **libimobiledevice** pair-record plist parsing (used by **`iphone-cli`**).

use idevice_usb_core::PairingIds;

use crate::crypto::{host_keys_from_pair_record_pems, HostKeys};

fn plist_value_to_string(v: &plist::Value) -> Option<String> {
    match v {
        plist::Value::String(s) => Some(s.trim().to_string()),
        plist::Value::Data(d) => String::from_utf8(d.clone())
            .ok()
            .map(|s| s.trim().to_string()),
        _ => None,
    }
}

fn require_field(dict: &plist::Dictionary, key: &str) -> Result<String, String> {
    dict.get(key)
        .and_then(plist_value_to_string)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("pair record: missing or empty `{}`", key))
}

/// Parse a **binary or XML** plist (e.g. `/var/lib/lockdown/<UDID>.plist`).
pub fn load_pair_record_plist_bytes(data: &[u8]) -> Result<(HostKeys, PairingIds), String> {
    let v = plist::from_bytes(data).map_err(|e| format!("plist: {}", e))?;
    let dict = match v {
        plist::Value::Dictionary(d) => d,
        _ => return Err("pair record root must be a dictionary".into()),
    };

    let host_id = require_field(&dict, "HostID")?;
    let system_buid = require_field(&dict, "SystemBUID")?;
    let host_private = require_field(&dict, "HostPrivateKey")?;
    let host_cert = require_field(&dict, "HostCertificate")?;
    let root_cert = require_field(&dict, "RootCertificate")?;
    let root_private = require_field(&dict, "RootPrivateKey")?;

    let keys = host_keys_from_pair_record_pems(host_private, host_cert, root_cert, root_private)?;
    let ids = PairingIds {
        host_id,
        system_buid,
    };
    Ok((keys, ids))
}
