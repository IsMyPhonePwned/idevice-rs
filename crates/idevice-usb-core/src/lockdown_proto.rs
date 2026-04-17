//! Static lockdownd XML / constants shared by WASM and CLI.

pub const HOST_ID: &str = "01234567-89AB-CDEF-0123-456789ABCDEF";
pub const LOCKDOWND_PORT: u16 = 62078;

/// Milliseconds to wait after `StartSession` (with `EnableSessionSSL`) before sending TLS ClientHello.
/// libimobiledevice calls `idevice_connection_enable_ssl` **immediately** (no sleep). A non‑zero
/// delay can let lockdownd time out and send plaintext `\0sessionUpcall connection closed` before
/// `ClientHello`. Use `--lockdown-tls-settle-ms` on **`iphone-cli`** if a short settle helps a host;
/// the WASM build uses this constant only (no CLI).
pub const LOCKDOWN_TLS_SETTLE_MS: u64 = 0;

/// RFC 4122 UUID v4 (random), lowercase hex — same style as common host tools / pymobiledevice3.
pub fn new_uuid_v4() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("getrandom for UUID");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6], b[7],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Random **HostID** + **SystemBUID** for one USB lockdownd session (libimobiledevice / idevice style).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingIds {
    pub host_id: String,
    pub system_buid: String,
}

impl PairingIds {
    pub fn new_v4() -> Self {
        Self {
            host_id: new_uuid_v4(),
            system_buid: new_uuid_v4(),
        }
    }

    /// Fixed **HostID** and **SystemBUID** (same value), matching the original `iphone-wasm` plist
    /// layout. Use this for USB mux flows where random UUIDs caused lockdownd `InvalidPairRecord`
    /// on some stacks (pairing still succeeds with pymobiledevice3-shaped **certs**).
    pub fn legacy_host_and_system() -> Self {
        Self {
            host_id: HOST_ID.to_string(),
            system_buid: HOST_ID.to_string(),
        }
    }
}

/// Whether a **`StartSession`** XML reply turns on TLS (`EnableSessionSSL`). Avoids treating any unrelated `<true/>` as SSL.
pub fn start_session_enable_ssl(xml: &str) -> bool {
    let needle = "<key>EnableSessionSSL</key>";
    let Some(pos) = xml.find(needle) else {
        return false;
    };
    let rest = xml[pos + needle.len()..].trim_start();
    rest.starts_with("<true/>")
        || rest.starts_with("<true />")
        || rest.starts_with("<integer>1</integer>")
}

/// Best-effort parse of lockdownd `GetValue` XML after `<key>Value</key>`: **`string`**, or **`data`**
/// (standard base64 — e.g. **WiFiAddress** as 6 raw bytes).
pub fn parse_get_value_string(xml: &str) -> Option<String> {
    use base64::{engine::general_purpose, Engine as _};

    let key = "<key>Value</key>";
    let i = xml.find(key)? + key.len();
    let tail = xml[i..].trim_start();
    if let Some(rest) = tail.strip_prefix("<string>") {
        let end = rest.find("</string>")?;
        return Some(rest[..end].to_string());
    }
    if let Some(rest) = tail.strip_prefix("<data>") {
        let end = rest.find("</data>")?;
        let b64: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = general_purpose::STANDARD.decode(&b64).ok()?;
        if bytes.len() == 6 {
            return Some(
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":"),
            );
        }
        return String::from_utf8(bytes).ok();
    }
    None
}

/// First request on a new lockdownd TCP session — matches **libimobiledevice** `lockdownd_query_type`
/// (`lockdownd_client_new`); skipping it can leave lockdownd in a state that **RST**s the mux session
/// when TLS `ClientHello` arrives.
pub const QUERY_TYPE_XML: &str = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>Label</key><string>iphone-wasm</string>
\t<key>Request</key><string>QueryType</string>
</dict>
</plist>";

pub const GET_DEVICE_PUBLIC_KEY_XML: &str = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>Label</key><string>iphone-wasm</string>
\t<key>Request</key><string>GetValue</string>
\t<key>Key</key><string>DevicePublicKey</string>
</dict>
</plist>";

/// `StartSession` plist — **HostID** and **SystemBUID** must match the `Pair` record (libimobiledevice
/// uses a random host id and a separate system BUID from the host; pymobiledevice3 / idevice do the same).
pub fn start_session_xml(host_id: &str, system_buid: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
            <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
            <plist version=\"1.0\">\n<dict>\n\
            \t<key>HostID</key><string>{}</string>\n\
            \t<key>Label</key><string>iphone-wasm</string>\n\
            \t<key>Request</key><string>StartSession</string>\n\
            \t<key>SystemBUID</key><string>{}</string>\n\
            </dict>\n</plist>\n",
        host_id, system_buid
    )
}

/// Legacy single-session helper (fixed host + system id) — prefer [`start_session_xml`].
pub fn start_session_xml_legacy() -> String {
    start_session_xml(HOST_ID, HOST_ID)
}

pub fn get_value_xml(domain: &str, key: &str) -> String {
    let mut req = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
            <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
            <plist version=\"1.0\">\n<dict>\n\
            \t<key>Label</key><string>iphone-wasm</string>\n\
            \t<key>Request</key><string>GetValue</string>\n",
    );
    if !domain.is_empty() {
        req.push_str(&format!("\t<key>Domain</key><string>{}</string>\n", domain));
    }
    if !key.is_empty() {
        req.push_str(&format!("\t<key>Key</key><string>{}</string>\n", key));
    }
    req.push_str("</dict>\n</plist>\n");
    req
}

/// `StartService` — used after **`StartSession`** + TLS to obtain a brokered TCP **port** for a named service.
pub fn start_service_xml(service: &str) -> String {
    let esc = xml_escape_string(service);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
\t<key>Label</key><string>iphone-wasm</string>\n\
\t<key>Request</key><string>StartService</string>\n\
\t<key>Service</key><string>{}</string>\n\
</dict>\n</plist>\n",
        esc
    )
}

fn parse_plist_integer_after_key(xml: &str, key: &str) -> Option<u64> {
    let needle = format!("<key>{}</key>", key);
    let i = xml.find(&needle)? + needle.len();
    let tail = xml[i..].trim_start();
    let rest = tail.strip_prefix("<integer>")?;
    let end = rest.find("</integer>")?;
    rest[..end].trim().parse().ok()
}

fn parse_plist_bool_after_key(xml: &str, key: &str) -> bool {
    let needle = format!("<key>{}</key>", key);
    let Some(i) = xml.find(&needle) else {
        return false;
    };
    let tail = xml[i + needle.len()..].trim_start();
    tail.starts_with("<true/>")
        || tail.starts_with("<true />")
        || tail.starts_with("<integer>1</integer>")
}

fn parse_lockdown_error_string(xml: &str) -> Option<String> {
    let key = "<key>Error</key>";
    let i = xml.find(key)? + key.len();
    let tail = xml[i..].trim_start();
    let rest = tail.strip_prefix("<string>")?;
    let end = rest.find("</string>")?;
    Some(rest[..end].to_string())
}

/// Parse **`Port`** and optional **`EnableServiceSSL`** from lockdownd’s **`StartService`** reply.
pub fn parse_start_service_response(xml: &str) -> Result<(u16, bool), String> {
    if let Some(err) = parse_lockdown_error_string(xml) {
        return Err(format!("StartService: {}", err));
    }
    let port = parse_plist_integer_after_key(xml, "Port").ok_or_else(|| {
        format!(
            "StartService response has no Port. Truncated body:\n{}",
            xml.chars().take(500).collect::<String>()
        )
    })?;
    if port == 0 || port > u16::MAX as u64 {
        return Err(format!("StartService invalid Port {}", port));
    }
    let ssl = parse_plist_bool_after_key(xml, "EnableServiceSSL");
    Ok((port as u16, ssl))
}

/// **`(label, Domain, Key)`** for successive **`GetValue`** calls on an **encrypted** lockdownd session (ideviceinfo-style).
///
/// This is **not** Apple’s full **sysdiagnose** capture (that uses **`StartService`**, other ports, and system
/// daemons). Each row is one lockdownd plist round-trip. Retail / locked / MDM devices often return
/// **`GetProhibited`** for sensitive keys — callers should record per-item errors and continue.
pub const LOCKDOWN_DIAGNOSTIC_GET_VALUES: &[(&str, &str, &str)] = &[
    ("DeviceName", "", "DeviceName"),
    ("ProductVersion", "", "ProductVersion"),
    ("ProductType", "", "ProductType"),
    ("BuildVersion", "", "BuildVersion"),
    ("SerialNumber", "", "SerialNumber"),
    ("UniqueDeviceID", "", "UniqueDeviceID"),
    ("HardwareModel", "", "HardwareModel"),
    ("CPUArchitecture", "", "CPUArchitecture"),
    ("ModelNumber", "", "ModelNumber"),
    ("WiFiAddress", "", "WiFiAddress"),
    ("BluetoothAddress", "", "BluetoothAddress"),
    (
        "InternationalMobileEquipmentIdentity",
        "",
        "InternationalMobileEquipmentIdentity",
    ),
    ("PhoneNumber", "", "PhoneNumber"),
    ("TimeZone", "", "TimeZone"),
    ("DeviceClass", "", "DeviceClass"),
    ("ActivationState", "", "ActivationState"),
    (
        "TotalDiskCapacity (disk_usage)",
        "com.apple.disk_usage",
        "TotalDiskCapacity",
    ),
    (
        "TotalDiskCapacity (mobile.disk_usage)",
        "com.apple.mobile.disk_usage",
        "TotalDiskCapacity",
    ),
    (
        "TotalDataAvailable",
        "com.apple.disk_usage",
        "TotalDataAvailable",
    ),
    (
        "AmountDataAvailable",
        "com.apple.disk_usage",
        "AmountDataAvailable",
    ),
    ("Mobile.battery", "com.apple.mobile.battery", ""),
];

/// Full PEM text (with `-----BEGIN…-----` lines) for certs and root private key — encoded as plist **`<string>`** like **pymobiledevice3** / `plistlib` (not header-stripped **`<data>`** blobs).
/// **`HostName`**, optional **`WiFiMACAddress`**, and **`RootPrivateKey`** in **`PairRecord`** match pymobiledevice3’s `Pair` message.
pub fn pair_plist(
    host_name: &str,
    host_id: &str,
    system_buid: &str,
    wifi_mac: Option<&str>,
    device_pem: &str,
    host_pem: &str,
    root_pem: &str,
    root_private_pem: &str,
) -> String {
    let host_name_esc = xml_escape_string(host_name);
    let device_esc = xml_escape_string(device_pem.trim());
    let host_esc = xml_escape_string(host_pem.trim());
    let root_esc = xml_escape_string(root_pem.trim());
    let root_priv_esc = xml_escape_string(root_private_pem.trim());
    let wifi_block = match wifi_mac {
        Some(w) if !w.is_empty() => format!(
            "\t\t<key>WiFiMACAddress</key><string>{}</string>\n",
            xml_escape_string(w)
        ),
        _ => String::new(),
    };
    format!(
        "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>Label</key><string>iphone-wasm</string>
\t<key>HostName</key><string>{}</string>
\t<key>PairRecord</key>
\t<dict>
\t\t<key>DeviceCertificate</key><string>{}</string>
\t\t<key>HostCertificate</key><string>{}</string>
\t\t<key>HostID</key><string>{}</string>
\t\t<key>RootCertificate</key><string>{}</string>
\t\t<key>RootPrivateKey</key><string>{}</string>
\t\t<key>SystemBUID</key><string>{}</string>
{}
\t</dict>
\t<key>PairingOptions</key>
\t<dict>
\t\t<key>ExtendedPairingErrors</key><true/>
\t</dict>
\t<key>ProtocolVersion</key><string>2</string>
\t<key>Request</key><string>Pair</string>
</dict>
</plist>",
        host_name_esc,
        device_esc,
        host_esc,
        host_id,
        root_esc,
        root_priv_esc,
        system_buid,
        wifi_block
    )
}

/// Escape text for XML plist `<string>` values.
pub fn xml_escape_string(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Legacy pair plist (fixed HostID / SystemBUID, no Wi-Fi line).
pub fn pair_plist_legacy(
    device_pem: &str,
    host_pem: &str,
    root_pem: &str,
    root_private_pem: &str,
) -> String {
    pair_plist(
        "iphone-wasm",
        HOST_ID,
        HOST_ID,
        None,
        device_pem,
        host_pem,
        root_pem,
        root_private_pem,
    )
}

/// `ValidatePair` — same **`PairRecord`** shape as [`pair_plist`] but no `PairingOptions`; matches **libimobiledevice** `lockdownd_validate_pair`.
/// Hosts normally call this only for **legacy iOS**; unsolicited use on modern devices can cause lockdownd to **RST** the pseudo-TCP session.
pub fn validate_pair_plist(
    host_id: &str,
    system_buid: &str,
    wifi_mac: Option<&str>,
    device_pem: &str,
    host_pem: &str,
    root_pem: &str,
) -> String {
    let device_esc = xml_escape_string(device_pem.trim());
    let host_esc = xml_escape_string(host_pem.trim());
    let root_esc = xml_escape_string(root_pem.trim());
    let wifi_block = match wifi_mac {
        Some(w) if !w.is_empty() => format!(
            "\t\t<key>WiFiMACAddress</key><string>{}</string>\n",
            xml_escape_string(w)
        ),
        _ => String::new(),
    };
    format!(
        "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>Label</key><string>iphone-wasm</string>
\t<key>PairRecord</key>
\t<dict>
\t\t<key>DeviceCertificate</key><string>{}</string>
\t\t<key>HostCertificate</key><string>{}</string>
\t\t<key>HostID</key><string>{}</string>
\t\t<key>RootCertificate</key><string>{}</string>
\t\t<key>SystemBUID</key><string>{}</string>
{}
\t</dict>
\t<key>ProtocolVersion</key><string>2</string>
\t<key>Request</key><string>ValidatePair</string>
</dict>
</plist>",
        device_esc,
        host_esc,
        host_id,
        root_esc,
        system_buid,
        wifi_block
    )
}
