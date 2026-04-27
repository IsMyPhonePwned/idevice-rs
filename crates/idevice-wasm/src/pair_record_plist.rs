//! Parse / serialize **XML** pair-record plists (same keys as `idevice::pair_record_parse`).

use std::io::Cursor;

use idevice_usb_core::lockdown_proto::xml_escape_string;
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

/// Serialize a freshly generated pair record to an **XML** plist the user can save and reload
/// via [`pair_record_from_xml_plist`]. Same keys as libimobiledevice / usbmuxd records.
pub fn pair_record_to_xml_plist(keys: &WasmHostKeys, ids: &PairingIds) -> String {
    let host_priv = xml_escape_string(keys.private_key_pem.trim());
    let host_cert = xml_escape_string(keys.host_cert_pem.trim());
    let root_cert = xml_escape_string(keys.root_cert_pem.trim());
    let root_priv = xml_escape_string(keys.root_private_pem.trim());
    let host_id = xml_escape_string(&ids.host_id);
    let system_buid = xml_escape_string(&ids.system_buid);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
\t<key>HostID</key><string>{host_id}</string>\n\
\t<key>SystemBUID</key><string>{system_buid}</string>\n\
\t<key>HostPrivateKey</key><string>{host_priv}</string>\n\
\t<key>HostCertificate</key><string>{host_cert}</string>\n\
\t<key>RootCertificate</key><string>{root_cert}</string>\n\
\t<key>RootPrivateKey</key><string>{root_priv}</string>\n\
</dict>\n</plist>\n"
    )
}
