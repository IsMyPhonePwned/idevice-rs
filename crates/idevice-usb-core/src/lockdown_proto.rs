//! Static lockdownd XML / constants shared by WASM and CLI.

pub const HOST_ID: &str = "01234567-89AB-CDEF-0123-456789ABCDEF";
pub const LOCKDOWND_PORT: u16 = 62078;

/// Milliseconds to wait after `StartSession` (with `EnableSessionSSL`) before sending TLS ClientHello.
/// libimobiledevice calls `idevice_connection_enable_ssl` **immediately** (no sleep). A non‑zero
/// delay can let lockdownd time out and send plaintext `\0sessionUpcall connection closed` before
/// `ClientHello`. Use `--lockdown-tls-settle-ms` on **`iphone-cli`** if a short settle helps a host;
/// the WASM build uses this constant only (no CLI).
pub const LOCKDOWN_TLS_SETTLE_MS: u64 = 0;

/// RFC 4122 UUID v4 (random), **UPPERCASE** hex — matches `libimobiledevice/common/idevice.c`'s
/// `generate_uuid()` which only emits `A-F0-9`. usbmuxd-stored pair records on macOS/Linux are
/// also uppercase. Lockdownd has been observed to fail post-Trust validation with
/// `InvalidPairRecord` when fed lowercase UUIDs on some iOS releases, so match the canonical
/// uppercase form.
pub fn new_uuid_v4() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("getrandom for UUID");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
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

/// Lockdownd **`Error`** string from a plist reply, if present.
pub fn parse_lockdown_error_string(xml: &str) -> Option<String> {
    let key = "<key>Error</key>";
    let i = xml.find(key)? + key.len();
    let tail = xml[i..].trim_start();
    let rest = tail.strip_prefix("<string>")?;
    let end = rest.find("</string>")?;
    Some(rest[..end].to_string())
}

/// Decode the **`EscrowBag`** value (CFData) from a successful **`Pair`** reply. Lockdownd
/// returns this base64-encoded blob alongside `Request=Pair` after the user accepts the Trust
/// prompt; libimobiledevice and pymobiledevice3 store it inside the on-disk pair record so
/// later sessions can use the **escrow** path on legacy iOS without needing the device to be
/// unlocked again. We use it the same way: persist with the rest of the pair record.
///
/// Whitespace inside the `<data>` block (CFData base64 wraps every 76 cols) is stripped before
/// decoding, matching `plist`'s and `plistlib`'s behaviour.
pub fn parse_escrow_bag(xml: &str) -> Option<Vec<u8>> {
    let key = "<key>EscrowBag</key>";
    let i = xml.find(key)? + key.len();
    let tail = xml[i..].trim_start();
    let rest = tail.strip_prefix("<data>")?;
    let end = rest.find("</data>")?;
    let b64: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.decode(b64.as_bytes()).ok()
}

/// Human-readable summary of a lockdownd **`GetValue`** XML reply: **`Error`**, or the **`Value`**
/// payload (**`string`**, **`integer`**, **`real`**, **`true`/`false`**, **`data`**, nested **`dict`**).
/// Used by WASM and tests; falls back to a short raw snippet when the value shape is unknown.
pub fn format_lockdown_getvalue_display(xml: &str) -> String {
    if let Some(err) = parse_lockdown_error_string(xml) {
        return format!("Error: {}", err);
    }
    let key_needle = "<key>Value</key>";
    let Some(i) = xml.find(key_needle) else {
        if let Some(s) = parse_get_value_string(xml) {
            return s;
        }
        return format!(
            "(unparsed response, {} bytes)\n{}",
            xml.len(),
            trunc_display(xml, 1200)
        );
    };
    let after = xml[i + key_needle.len()..].trim_start();
    match parse_one_plist_value_for_display(after) {
        Some((s, _)) if !s.is_empty() => s,
        _ => {
            if let Some(s) = parse_get_value_string(xml) {
                return s;
            }
            format!(
                "(could not parse Value; {} bytes)\n{}",
                xml.len(),
                trunc_display(after, 1200)
            )
        }
    }
}

fn trunc_display(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars).collect::<String>() + "…"
    }
}

/// Parses one plist value element at `s` start (after optional whitespace). Returns `(display, bytes_consumed_from_s)`.
fn parse_one_plist_value_for_display(s: &str) -> Option<(String, usize)> {
    let t = s.trim_start();
    let skipped = s.len() - t.len();
    if t.starts_with("<string>") {
        let inner = &t[8..];
        let end = inner.find("</string>")?;
        let v = inner[..end].to_string();
        let consumed = skipped + 8 + end + 9;
        return Some((v, consumed));
    }
    if t.starts_with("<integer>") {
        let inner = &t[9..];
        let end = inner.find("</integer>")?;
        let v = inner[..end].trim().to_string();
        let consumed = skipped + 9 + end + 10;
        return Some((v, consumed));
    }
    if t.starts_with("<real>") {
        let inner = &t[6..];
        let end = inner.find("</real>")?;
        let v = inner[..end].trim().to_string();
        let consumed = skipped + 6 + end + 7;
        return Some((v, consumed));
    }
    if t.starts_with("<true/>") || t.starts_with("<true />") {
        let n = if t.starts_with("<true/>") { 7 } else { 8 };
        return Some(("true".into(), skipped + n));
    }
    if t.starts_with("<false/>") || t.starts_with("<false />") {
        let n = if t.starts_with("<false/>") { 8 } else { 9 };
        return Some(("false".into(), skipped + n));
    }
    if t.starts_with("<data>") {
        let inner = &t[6..];
        let end = inner.find("</data>")?;
        let b64: String = inner[..end].chars().filter(|c| !c.is_whitespace()).collect();
        use base64::{engine::general_purpose, Engine as _};
        let Ok(bytes) = general_purpose::STANDARD.decode(&b64) else {
            return Some((format!("<data> {} bytes base64", b64.len()), skipped + 6 + end + 7));
        };
        if bytes.len() == 6 {
            let mac = bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");
            return Some((mac, skipped + 6 + end + 7));
        }
        if let Ok(utf8) = String::from_utf8(bytes) {
            return Some((utf8, skipped + 6 + end + 7));
        }
        return Some((format!("<binary data, {} bytes>", b64.len()), skipped + 6 + end + 7));
    }
    if t.starts_with("<dict>") {
        let after_open = &t[6..];
        let mut depth = 1u32;
        let mut pos = 0usize;
        while pos < after_open.len() {
            if after_open[pos..].starts_with("<dict>") {
                depth += 1;
                pos += 6;
            } else if after_open[pos..].starts_with("</dict>") {
                depth -= 1;
                if depth == 0 {
                    let inner = &after_open[..pos];
                    let formatted = format_plist_dict_lines(inner);
                    let consumed = skipped + 6 + pos + 7;
                    return Some((formatted, consumed));
                }
                pos += 7;
            } else {
                pos += 1;
            }
        }
        return None;
    }
    None
}

fn format_plist_dict_lines(inner: &str) -> String {
    let mut rest = inner;
    let mut lines: Vec<String> = Vec::new();
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let Some(krest) = rest.strip_prefix("<key>") else {
            break;
        };
        let Some(kend) = krest.find("</key>") else {
            break;
        };
        let key = krest[..kend].trim();
        rest = &krest[kend + 6..];
        rest = rest.trim_start();
        let Some((val, consumed)) = parse_one_plist_value_for_display(rest) else {
            lines.push(format!("{}: (unparsed)", key));
            break;
        };
        rest = &rest[consumed..];
        if val.contains('\n') {
            lines.push(format!("{}:\n{}", key, indent_lines(&val, "  ")));
        } else {
            lines.push(format!("{}: {}", key, val));
        }
    }
    if lines.is_empty() {
        "(empty dict)".into()
    } else {
        lines.join("\n")
    }
}

fn indent_lines(s: &str, prefix: &str) -> String {
    s.lines()
        .map(|line| format!("{}{}", prefix, line))
        .collect::<Vec<_>>()
        .join("\n")
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
    // --- Identity (root domain) ---
    ("DeviceName", "", "DeviceName"),
    ("ProductName", "", "ProductName"),
    ("ProductType", "", "ProductType"),
    ("ProductVersion", "", "ProductVersion"),
    ("BuildVersion", "", "BuildVersion"),
    ("SerialNumber", "", "SerialNumber"),
    ("UniqueDeviceID", "", "UniqueDeviceID"),
    ("HardwareModel", "", "HardwareModel"),
    ("ModelNumber", "", "ModelNumber"),
    ("RegionInfo", "", "RegionInfo"),
    ("DeviceClass", "", "DeviceClass"),
    ("DeviceColor", "", "DeviceColor"),
    ("MarketingName", "", "MarketingName"),
    ("CPUArchitecture", "", "CPUArchitecture"),
    ("ChipID", "", "ChipID"),
    ("BoardId", "", "BoardId"),
    ("FirmwareVersion", "", "FirmwareVersion"),
    ("HardwarePlatform", "", "HardwarePlatform"),
    // --- Network / cellular (root domain) ---
    ("WiFiAddress", "", "WiFiAddress"),
    ("EthernetAddress", "", "EthernetAddress"),
    ("BluetoothAddress", "", "BluetoothAddress"),
    (
        "InternationalMobileEquipmentIdentity",
        "",
        "InternationalMobileEquipmentIdentity",
    ),
    ("MobileEquipmentIdentifier", "", "MobileEquipmentIdentifier"),
    (
        "InternationalMobileSubscriberIdentity",
        "",
        "InternationalMobileSubscriberIdentity",
    ),
    (
        "IntegratedCircuitCardIdentity",
        "",
        "IntegratedCircuitCardIdentity",
    ),
    ("PhoneNumber", "", "PhoneNumber"),
    ("CarrierBundleInfoArray", "", "CarrierBundleInfoArray"),
    // --- Locale / time ---
    ("TimeZone", "", "TimeZone"),
    ("TimeIntervalSince1970", "", "TimeIntervalSince1970"),
    ("Language", "com.apple.international", "Language"),
    ("Locale", "com.apple.international", "Locale"),
    // --- Activation / security state ---
    ("ActivationState", "", "ActivationState"),
    (
        "ActivationStateAcknowledged",
        "",
        "ActivationStateAcknowledged",
    ),
    ("BrickState", "", "BrickState"),
    ("DeveloperModeStatus", "", "DeveloperModeStatus"),
    ("PasswordProtected", "", "PasswordProtected"),
    ("TrustedHostAttached", "", "TrustedHostAttached"),
    ("HasSiDP", "", "HasSiDP"),
    // --- Storage (com.apple.disk_usage / mobile.disk_usage) ---
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
        "TotalSystemCapacity",
        "com.apple.disk_usage",
        "TotalSystemCapacity",
    ),
    (
        "TotalSystemAvailable",
        "com.apple.disk_usage",
        "TotalSystemAvailable",
    ),
    (
        "TotalDataCapacity",
        "com.apple.disk_usage",
        "TotalDataCapacity",
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
    (
        "AmountDataReserved",
        "com.apple.disk_usage",
        "AmountDataReserved",
    ),
    // --- iTunes / sync ---
    (
        "iTunesHasConnected",
        "com.apple.mobile.iTunes",
        "iTunesHasConnected",
    ),
    (
        "MinITunesVersion",
        "com.apple.mobile.iTunes",
        "MinITunesVersion",
    ),
    // --- Battery (returns a dict) ---
    ("Mobile.battery", "com.apple.mobile.battery", ""),
];

/// Map a `(domain, key)` pair to a stable category title for the device-report formatter.
/// Falls back to **Other** for any key that doesn't match a known category. Order returned
/// from `device_report_section_order()` controls the section order in `format_lockdown_device_report`.
pub fn device_report_section_for(domain: &str, key: &str) -> &'static str {
    if domain == "com.apple.mobile.battery" {
        return "Battery (com.apple.mobile.battery)";
    }
    if domain == "com.apple.disk_usage" || domain == "com.apple.mobile.disk_usage" {
        return "Storage (disk_usage)";
    }
    if domain == "com.apple.international" {
        return "Locale / time";
    }
    if domain == "com.apple.mobile.iTunes" {
        return "iTunes / sync";
    }
    match key {
        "DeviceName" | "ProductName" | "ProductType" | "ProductVersion" | "BuildVersion"
        | "SerialNumber" | "UniqueDeviceID" | "HardwareModel" | "ModelNumber" | "RegionInfo"
        | "DeviceClass" | "DeviceColor" | "MarketingName" | "CPUArchitecture" | "ChipID"
        | "BoardId" | "FirmwareVersion" | "HardwarePlatform" => "Identity",
        "WiFiAddress" | "EthernetAddress" | "BluetoothAddress"
        | "InternationalMobileEquipmentIdentity"
        | "MobileEquipmentIdentifier"
        | "InternationalMobileSubscriberIdentity"
        | "IntegratedCircuitCardIdentity"
        | "PhoneNumber"
        | "CarrierBundleInfoArray" => "Network / cellular",
        "TimeZone" | "TimeIntervalSince1970" => "Locale / time",
        "ActivationState" | "ActivationStateAcknowledged" | "BrickState"
        | "DeveloperModeStatus" | "PasswordProtected" | "TrustedHostAttached" | "HasSiDP" => {
            "Activation / security"
        }
        _ => "Other",
    }
}

/// Stable order in which `format_lockdown_device_report` emits sections (sections that have no
/// entries are skipped at render time, so this list is just the *priority* order).
pub fn device_report_section_order() -> &'static [&'static str] {
    &[
        "Identity",
        "Network / cellular",
        "Locale / time",
        "Activation / security",
        "Storage (disk_usage)",
        "iTunes / sync",
        "Battery (com.apple.mobile.battery)",
        "Other",
    ]
}

/// Render a sectioned, human-friendly report for a batch of `GetValue` results.
///
/// Input rows are `(label, domain, key, Result<xml, error>)` where `xml` is the **raw**
/// lockdownd `GetValue` reply (already passed through TLS/cleartext) and `error` is whatever
/// the transport returned. Each row is parsed via [`format_lockdown_getvalue_display`] (so
/// integers, booleans, MAC `<data>` blobs, and full battery `<dict>`s all render as plain
/// text), grouped by [`device_report_section_for`], and emitted in the order returned by
/// [`device_report_section_order`].
///
/// Storage byte counts (anything in `com.apple.disk_usage` / `mobile.disk_usage` whose value
/// parses as an unsigned integer) are annotated with a human-readable `(~ X.XX GiB)` suffix.
/// `GetProhibited` and other lockdown errors render as `Error: …` lines so the report stays
/// useful even on locked / retail / MDM-supervised devices.
pub fn format_lockdown_device_report(
    rows: &[(&str, &str, &str, Result<String, String>)],
) -> String {
    use std::collections::BTreeMap;

    // Section title -> ordered Vec of (label, formatted-value, is-multiline).
    let mut sections: BTreeMap<&str, Vec<(String, String, bool)>> = BTreeMap::new();
    let mut label_width: usize = 0;

    for (label, domain, key, result) in rows {
        let section = device_report_section_for(domain, key);
        let display = match result {
            Ok(xml) => {
                let mut s = format_lockdown_getvalue_display(xml);
                if (*domain == "com.apple.disk_usage" || *domain == "com.apple.mobile.disk_usage")
                    && !s.contains('\n')
                {
                    if let Ok(n) = s.trim().parse::<u64>() {
                        s = format!("{}  ({})", s, human_bytes(n));
                    }
                }
                s
            }
            Err(e) => format!("Error: {}", e),
        };
        let multi = display.contains('\n');
        if !multi {
            label_width = label_width.max(label.chars().count());
        }
        sections
            .entry(section)
            .or_default()
            .push(((*label).to_string(), display, multi));
    }

    let mut out = String::new();
    for section in device_report_section_order() {
        let Some(rows) = sections.remove(section) else {
            continue;
        };
        if rows.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(section);
        out.push('\n');
        for _ in 0..section.chars().count() {
            out.push('-');
        }
        out.push('\n');
        for (label, value, multi) in rows {
            if multi {
                out.push_str(&format!("{}:\n{}\n", label, indent_lines(&value, "    ")));
            } else {
                out.push_str(&format!(
                    "  {label:<width$} : {value}\n",
                    label = label,
                    width = label_width,
                    value = value
                ));
            }
        }
    }
    // Anything still in `sections` is a section title we didn't put in `device_report_section_order`.
    for (section, rows) in sections {
        if rows.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(section);
        out.push('\n');
        for _ in 0..section.chars().count() {
            out.push('-');
        }
        out.push('\n');
        for (label, value, multi) in rows {
            if multi {
                out.push_str(&format!("{}:\n{}\n", label, indent_lines(&value, "    ")));
            } else {
                out.push_str(&format!(
                    "  {label:<width$} : {value}\n",
                    label = label,
                    width = label_width,
                    value = value
                ));
            }
        }
    }
    out
}

/// Format a byte count as e.g. `238.42 GiB` / `512 MiB` / `42 KiB` / `9 B`.
/// Used by `format_lockdown_device_report` to annotate storage values.
pub fn human_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;
    if n >= TIB {
        format!("{:.2} TiB", n as f64 / TIB as f64)
    } else if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{} B", n)
    }
}

/// Render `pem` as a plist `<data>` (CFData) value at the given XML indent depth (in tabs),
/// byte-compatible with `plistlib.dumps(...)`: open tag, base64 body wrapped at **68 characters**
/// per line and prefixed with `indent`, closing tag — all newline-terminated. Trailing PEM
/// whitespace is preserved (we keep `cert.public_bytes(Encoding.PEM)`'s final `\n`).
///
/// **Why CFData?** lockdownd expects `DeviceCertificate` / `HostCertificate` / `RootCertificate` /
/// `RootPrivateKey` in the `Pair` request to be `CFData` — exactly what `plistlib` emits when the
/// dict value is `bytes`, which is what pymobiledevice3 (and libimobiledevice) put there. Sending
/// these as `<string>` parses but lockdownd rejects with `InvalidPairRecord` on the type mismatch.
fn pem_as_data_value(pem: &str, indent: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    let mut bytes = pem.as_bytes().to_vec();
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    let b64 = general_purpose::STANDARD.encode(&bytes);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str("<data>\n");
    let chars: Vec<char> = b64.chars().collect();
    for chunk in chars.chunks(68) {
        out.push_str(indent);
        for &c in chunk {
            out.push(c);
        }
        out.push('\n');
    }
    out.push_str(indent);
    out.push_str("</data>");
    out
}

/// **Wire format of the `Pair` request — must match `libimobiledevice/src/lockdown.c`
/// (`lockdownd_do_pair`) byte-for-byte to avoid `InvalidPairRecord`.**
///
/// Crucial differences vs. an in-memory pair record (and vs. `pymobiledevice3.lockdown.pair`):
///
/// 1. **`RootPrivateKey` is stripped** from the wire `PairRecord`. libimobiledevice does
///    `plist_dict_remove_item(request_pair_record, USERPREF_ROOT_PRIVATE_KEY_KEY)` right before
///    sending. The root private key is a **host secret** — sending it to the device makes
///    lockdownd reject the record. This rejection is *deferred*: the first `Pair` still returns
///    `PairingDialogResponsePending` (lockdownd shows the Trust UI optimistically), but after the
///    user accepts Trust the next `Pair` validates the record properly and returns
///    `InvalidPairRecord`. This was the actual root cause of the post-Trust failures.
///    `HostPrivateKey` is also stripped by libimobiledevice; we never put it in `PairRecord` in
///    the first place, so there's nothing to remove.
///
/// 2. **No top-level `HostName`** — libimobiledevice's outer dict is just `Label`, `PairRecord`,
///    `Request`, `ProtocolVersion`, `PairingOptions`. `pymobiledevice3` adds `HostName` but the
///    canonical USB-pair flow on Linux (usbmuxd → idevicepair → libimobiledevice) does not.
///    Lockdownd tolerates extra keys, but staying close to libimobiledevice avoids surprises.
///
/// 3. Cert fields stay as plist **`<data>`** (CFData / `bytes` in `plistlib`), not `<string>`:
///    libimobiledevice writes them with `plist_new_data(...)`. CFData vs. CFString is a strict
///    type check on the lockdownd side.
///
/// Top-level keys are emitted in **alphabetical order** to match `plistlib.dumps(sort_keys=True)`:
/// `Label`, `PairRecord`, `PairingOptions`, `ProtocolVersion`, `Request`. The inner `PairRecord`
/// dict is also alphabetical; `WiFiMACAddress` (when present, e.g. fetched cleartext before the
/// `Pair`) sits after `SystemBUID` because `W` > `S`. CFPropertyList parses any order, but
/// matching the canonical byte layout removes one variable when debugging.
///
/// `_host_name`, `_wifi_mac`, and `_root_private_pem` are accepted but **deliberately not** emitted
/// on the wire (kept in the signature so callers don't have to change shape; the on-disk pair
/// record format still includes them — `WiFiMACAddress` is added back by the *device* in its
/// reply, and `RootPrivateKey` is needed locally for TLS).
///
/// **Why no `WiFiMACAddress` on the wire?** `libimobiledevice`'s `pair_record_generate`
/// (`common/userpref.c`) builds the request `PairRecord` with **only** `{DeviceCertificate,
/// HostCertificate, RootCertificate, HostID, SystemBUID}` — Wi-Fi MAC is **never** sent in a
/// `Pair` request; the device populates it in the reply, and the host saves it locally. Sending
/// it on the wire is one of the unknown extras that triggers post-Trust `InvalidPairRecord` on
/// modern lockdownd.
pub fn pair_plist(
    _host_name: &str,
    host_id: &str,
    system_buid: &str,
    _wifi_mac: Option<&str>,
    device_pem: &str,
    host_pem: &str,
    root_pem: &str,
    _root_private_pem: &str,
) -> String {
    let device_data = pem_as_data_value(device_pem, "\t\t");
    let host_data = pem_as_data_value(host_pem, "\t\t");
    let root_data = pem_as_data_value(root_pem, "\t\t");
    format!(
        "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>Label</key><string>iphone-wasm</string>
\t<key>PairRecord</key>
\t<dict>
\t\t<key>DeviceCertificate</key>
\t\t{}
\t\t<key>HostCertificate</key>
\t\t{}
\t\t<key>HostID</key><string>{}</string>
\t\t<key>RootCertificate</key>
\t\t{}
\t\t<key>SystemBUID</key><string>{}</string>
\t</dict>
\t<key>PairingOptions</key>
\t<dict>
\t\t<key>ExtendedPairingErrors</key><true/>
\t</dict>
\t<key>ProtocolVersion</key><string>2</string>
\t<key>Request</key><string>Pair</string>
</dict>
</plist>",
        device_data, host_data, host_id, root_data, system_buid
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
    let device_data = pem_as_data_value(device_pem, "\t\t");
    let host_data = pem_as_data_value(host_pem, "\t\t");
    let root_data = pem_as_data_value(root_pem, "\t\t");
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
\t\t<key>DeviceCertificate</key>
\t\t{}
\t\t<key>HostCertificate</key>
\t\t{}
\t\t<key>HostID</key><string>{}</string>
\t\t<key>RootCertificate</key>
\t\t{}
\t\t<key>SystemBUID</key><string>{}</string>
{}
\t</dict>
\t<key>ProtocolVersion</key><string>2</string>
    \t<key>Request</key><string>ValidatePair</string>
</dict>
</plist>",
        device_data,
        host_data,
        host_id,
        root_data,
        system_buid,
        wifi_block
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_display_error() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict><key>Error</key><string>GetProhibited</string></dict></plist>"#;
        assert_eq!(
            format_lockdown_getvalue_display(xml),
            "Error: GetProhibited"
        );
    }

    #[test]
    fn format_display_string_value() {
        let xml = r#"<dict><key>Value</key><string>iPhone</string></dict>"#;
        assert_eq!(format_lockdown_getvalue_display(xml), "iPhone");
    }

    #[test]
    fn pair_plist_matches_libimobiledevice_shape() {
        let pem = "-----BEGIN CERTIFICATE-----\nABCDEFGH\n-----END CERTIFICATE-----\n";
        let key = "-----BEGIN PRIVATE KEY-----\nXYZ\n-----END PRIVATE KEY-----\n";
        let xml = pair_plist(
            "framework",
            "host-id",
            "system-buid",
            Some("aa:bb:cc:dd:ee:ff"),
            pem,
            pem,
            pem,
            key,
        );

        // Cert fields must be CFData (`<data>`), not CFString (`<string>`).
        for k in ["DeviceCertificate", "HostCertificate", "RootCertificate"] {
            let key_tag = format!("<key>{}</key>", k);
            let kpos = xml.find(&key_tag).unwrap_or_else(|| panic!("missing {}", k));
            let next = xml[kpos + key_tag.len()..].trim_start();
            assert!(
                next.starts_with("<data>"),
                "{} should be <data>, got: {}",
                k,
                &next[..next.len().min(40)]
            );
        }

        // libimobiledevice strips RootPrivateKey from the wire PairRecord (it's a host secret) —
        // sending it triggers `InvalidPairRecord` after the user accepts Trust on modern iOS.
        // It must NOT appear anywhere in the Pair request.
        assert!(
            !xml.contains("RootPrivateKey"),
            "RootPrivateKey must not be on the wire — libimobiledevice strips it"
        );
        assert!(
            !xml.contains("HostPrivateKey"),
            "HostPrivateKey must never be on the wire"
        );
        // Top-level HostName is not part of libimobiledevice's outer dict; we drop it too.
        assert!(
            !xml.contains("<key>HostName</key>"),
            "Top-level HostName must not be on the wire"
        );

        let parsed: plist::Value = plist::from_bytes(xml.as_bytes()).expect("parse plist");
        let dict = parsed.as_dictionary().unwrap();
        let pair_record = dict.get("PairRecord").unwrap().as_dictionary().unwrap();

        // Cert decodes back to the exact PEM bytes (with trailing newline preserved).
        let dev_bytes = pair_record
            .get("DeviceCertificate")
            .unwrap()
            .as_data()
            .expect("CFData");
        assert_eq!(dev_bytes, pem.as_bytes());

        // String fields stay strings.
        assert_eq!(
            pair_record.get("HostID").unwrap().as_string().unwrap(),
            "host-id"
        );
        // libimobiledevice never sends `WiFiMACAddress` in the request — the *device* puts it in
        // the reply, and the host saves it locally. It must not appear in the wire PairRecord.
        assert!(
            pair_record.get("WiFiMACAddress").is_none(),
            "WiFiMACAddress must not be on the wire (libimobiledevice never sends it)"
        );

        // Allowed PairRecord keys: canonical libimobiledevice request set, no extras.
        let allowed = [
            "DeviceCertificate",
            "HostCertificate",
            "HostID",
            "RootCertificate",
            "SystemBUID",
        ];
        for (k, _) in pair_record.iter() {
            assert!(
                allowed.contains(&k.as_str()),
                "Unexpected PairRecord key: {}",
                k
            );
        }

        // Outer dict matches libimobiledevice (Label, PairRecord, PairingOptions, ProtocolVersion,
        // Request). No HostName.
        let outer_allowed = [
            "Label",
            "PairRecord",
            "PairingOptions",
            "ProtocolVersion",
            "Request",
        ];
        for (k, _) in dict.iter() {
            assert!(
                outer_allowed.contains(&k.as_str()),
                "Unexpected outer key: {}",
                k
            );
        }
    }

    #[test]
    fn format_display_battery_dict() {
        let xml = r#"<plist><dict>
<key>Value</key><dict>
<key>BatteryCurrentCapacity</key><integer>92</integer>
<key>ExternalChargeCapable</key><true/>
<key>IsCharging</key><false/>
</dict></dict></plist>"#;
        let s = format_lockdown_getvalue_display(xml);
        assert!(s.contains("BatteryCurrentCapacity: 92"));
        assert!(s.contains("ExternalChargeCapable: true"));
        assert!(s.contains("IsCharging: false"));
    }

    #[test]
    fn human_bytes_formats_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert!(human_bytes(256_000_000_000).ends_with("GiB"));
    }

    #[test]
    fn report_groups_and_annotates_storage() {
        let identity_xml = r#"<plist><dict><key>Value</key><string>iPhone15,3</string></dict></plist>"#;
        let storage_xml = r#"<plist><dict><key>Value</key><integer>256000000000</integer></dict></plist>"#;
        let battery_xml = r#"<plist><dict><key>Value</key><dict>
<key>BatteryCurrentCapacity</key><integer>87</integer>
<key>FullyCharged</key><false/>
</dict></dict></plist>"#;
        let prohibited = r#"<plist><dict><key>Error</key><string>GetProhibited</string></dict></plist>"#;

        let rows: Vec<(&str, &str, &str, Result<String, String>)> = vec![
            ("ProductType", "", "ProductType", Ok(identity_xml.into())),
            ("PhoneNumber", "", "PhoneNumber", Ok(prohibited.into())),
            (
                "TotalDiskCapacity",
                "com.apple.disk_usage",
                "TotalDiskCapacity",
                Ok(storage_xml.into()),
            ),
            (
                "Mobile.battery",
                "com.apple.mobile.battery",
                "",
                Ok(battery_xml.into()),
            ),
        ];

        let s = format_lockdown_device_report(&rows);

        // Sectioned output, in canonical order.
        let id_pos = s.find("Identity\n").expect("Identity section present");
        let net_pos = s
            .find("Network / cellular\n")
            .expect("Network section present");
        let storage_pos = s
            .find("Storage (disk_usage)\n")
            .expect("Storage section present");
        let bat_pos = s
            .find("Battery (com.apple.mobile.battery)\n")
            .expect("Battery section present");
        assert!(id_pos < net_pos);
        assert!(net_pos < storage_pos);
        assert!(storage_pos < bat_pos);

        // Identity values render as scalar key:value rows.
        assert!(s.contains("ProductType"));
        assert!(s.contains("iPhone15,3"));

        // GetProhibited shows up but doesn't break formatting.
        assert!(s.contains("Error: GetProhibited"));

        // Storage byte counts get a human-readable suffix.
        assert!(s.contains("256000000000"));
        assert!(s.contains("GiB"));

        // Battery dict expands as multi-line, indented sub-block.
        assert!(s.contains("BatteryCurrentCapacity: 87"));
        assert!(s.contains("FullyCharged: false"));
    }
}
