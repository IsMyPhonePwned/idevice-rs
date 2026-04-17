//! Parse **XML** pair-record plists (same keys as `idevice::pair_record_parse`).

use std::io::Cursor;

use idevice_usb_core::PairingIds;
use plist::{Dictionary, Value};

use crate::wasm_crypto::{host_keys_from_pair_record_pems, WasmHostKeys};

fn plist_value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Data(d) => String::from_utf8(d.clone())
            .ok()
            .map(|s| s.trim().to_string()),
        _ => None,
    }
}

fn require_field(dict: &Dictionary, key: &str) -> Result<String, String> {
    dict.get(key)
        .and_then(plist_value_to_string)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("pair record: missing or empty `{}`", key))
}

/// Parse an **XML** plist string into TLS keys + pairing IDs.
pub fn pair_record_from_xml_plist(xml: &str) -> Result<(WasmHostKeys, PairingIds), String> {
    let v = Value::from_reader_xml(Cursor::new(xml.as_bytes())).map_err(|e| format!("plist XML: {}", e))?;
    let dict = match v {
        Value::Dictionary(d) => d,
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
