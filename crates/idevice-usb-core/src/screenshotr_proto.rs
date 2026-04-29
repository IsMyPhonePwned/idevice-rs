//! `com.apple.mobile.screenshotr` protocol helpers — pure binary plist build/parse, no I/O.
//! Mirrors `libimobiledevice/src/screenshotr.c` + `device_link_service.c`.
//!
//! Wire format on the (TLS-wrapped) service socket: each message is **`u32` BE length + binary
//! plist (`bplist00`)**. Initial dialogue is a **DeviceLink** version exchange; the screenshot
//! request itself is a `DLMessageProcessMessage` envelope around a regular dictionary.
//!
//! The screenshotr service is only published when a **Developer Disk Image** is mounted on the
//! device. Lockdownd `StartService` returns the well-known error `"InvalidService"` otherwise.

use plist::Value;

/// Lockdown service name — same as **libimobiledevice** `SCREENSHOTR_SERVICE_NAME`.
pub const SCREENSHOTR_SERVICE: &str = "com.apple.mobile.screenshotr";

/// DeviceLink protocol version we advertise. `400.0` is what libimobiledevice screenshotr uses.
pub const SCREENSHOTR_VERSION_MAJOR: u64 = 400;
pub const SCREENSHOTR_VERSION_MINOR: u64 = 0;

/// Cap to refuse absurd `u32 BE` length-prefixed plist frames (PNG screenshots fit comfortably).
pub const MAX_SCREENSHOTR_FRAME: usize = 64 * 1024 * 1024;

fn to_binary_plist(value: &Value) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    value
        .to_writer_binary(&mut buf)
        .map_err(|e| format!("screenshotr: plist serialize: {}", e))?;
    Ok(buf)
}

/// Build the `DLMessageVersionExchange` reply we send to the device after we've received its
/// initial version array: `[ "DLMessageVersionExchange", "DLVersionsOk", <major:uint64> ]`.
pub fn build_dl_versions_ok(major: u64) -> Result<Vec<u8>, String> {
    let arr = Value::Array(vec![
        Value::String("DLMessageVersionExchange".into()),
        Value::String("DLVersionsOk".into()),
        Value::Integer(major.into()),
    ]);
    to_binary_plist(&arr)
}

/// `DLMessageProcessMessage` envelope: `[ "DLMessageProcessMessage", { "MessageType": "ScreenShotRequest" } ]`.
pub fn build_screenshot_request() -> Result<Vec<u8>, String> {
    let mut inner = plist::Dictionary::new();
    inner.insert("MessageType".into(), Value::String("ScreenShotRequest".into()));
    let arr = Value::Array(vec![
        Value::String("DLMessageProcessMessage".into()),
        Value::Dictionary(inner),
    ]);
    to_binary_plist(&arr)
}

/// `[ "DLMessageDisconnect", "___EmptyParameterString___" ]` — best-effort goodbye, matches
/// `device_link_service_disconnect` in libimobiledevice.
pub fn build_disconnect() -> Result<Vec<u8>, String> {
    let arr = Value::Array(vec![
        Value::String("DLMessageDisconnect".into()),
        Value::String("___EmptyParameterString___".into()),
    ]);
    to_binary_plist(&arr)
}

/// Length-prefix a serialized plist for the property_list_service wire format
/// (`u32 big-endian length + payload`). Used for both cleartext and TLS — we send the same
/// bytes, the secondary service TLS layer just encrypts them in place.
pub fn frame_plist_message(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn parse_value(bytes: &[u8]) -> Result<Value, String> {
    plist::from_bytes(bytes).map_err(|e| format!("screenshotr: parse plist: {}", e))
}

fn dl_array(value: &Value) -> Result<&[Value], String> {
    let arr = value
        .as_array()
        .ok_or_else(|| "screenshotr: expected DL* plist array".to_string())?;
    if arr.is_empty() {
        return Err("screenshotr: DL* array is empty".into());
    }
    let cmd = arr[0]
        .as_string()
        .ok_or_else(|| "screenshotr: DL* command is not a string".to_string())?;
    if !cmd.starts_with("DL") {
        return Err(format!("screenshotr: not a DL* message: `{}`", cmd));
    }
    Ok(arr.as_slice())
}

/// Parse the initial `DLMessageVersionExchange` from the device, returning `(major, minor)`.
/// Mirrors the version check in `device_link_service_version_exchange`.
pub fn parse_dl_version_exchange(bytes: &[u8]) -> Result<(u64, u64), String> {
    let v = parse_value(bytes)?;
    let arr = dl_array(&v)?;
    let cmd = arr[0].as_string().unwrap_or("");
    if cmd != "DLMessageVersionExchange" {
        return Err(format!(
            "screenshotr: expected DLMessageVersionExchange, got `{}`",
            cmd
        ));
    }
    if arr.len() < 3 {
        return Err("screenshotr: DLMessageVersionExchange has unexpected format".into());
    }
    let major = arr[1]
        .as_unsigned_integer()
        .or_else(|| arr[1].as_signed_integer().map(|i| i as u64))
        .ok_or_else(|| "screenshotr: DLMessageVersionExchange major is not a number".to_string())?;
    let minor = arr[2]
        .as_unsigned_integer()
        .or_else(|| arr[2].as_signed_integer().map(|i| i as u64))
        .unwrap_or(0);
    Ok((major, minor))
}

/// `(major, minor)` from `parse_dl_version_exchange`: must be **≤** `SCREENSHOTR_VERSION_*`.
/// Returns a human-readable error so the CLI / WASM layer can surface it.
pub fn check_screenshotr_version(major: u64, minor: u64) -> Result<(), String> {
    if major > SCREENSHOTR_VERSION_MAJOR
        || (major == SCREENSHOTR_VERSION_MAJOR && minor > SCREENSHOTR_VERSION_MINOR)
    {
        return Err(format!(
            "screenshotr: device DeviceLink version ({}.{}) > supported ({}.{})",
            major, minor, SCREENSHOTR_VERSION_MAJOR, SCREENSHOTR_VERSION_MINOR
        ));
    }
    Ok(())
}

/// Verify a `DLMessageDeviceReady` reply (sent by the device after our `DLVersionsOk`).
pub fn parse_dl_device_ready(bytes: &[u8]) -> Result<(), String> {
    let v = parse_value(bytes)?;
    let arr = dl_array(&v)?;
    let cmd = arr[0].as_string().unwrap_or("");
    if cmd != "DLMessageDeviceReady" {
        return Err(format!(
            "screenshotr: expected DLMessageDeviceReady, got `{}`",
            cmd
        ));
    }
    Ok(())
}

/// Parse the screenshot `DLMessageProcessMessage` reply and return the raw image bytes
/// (`ScreenShotData`).
pub fn parse_screenshot_reply(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let v = parse_value(bytes)?;
    let arr = dl_array(&v)?;
    let cmd = arr[0].as_string().unwrap_or("");
    if cmd != "DLMessageProcessMessage" {
        return Err(format!(
            "screenshotr: expected DLMessageProcessMessage, got `{}`",
            cmd
        ));
    }
    if arr.len() < 2 {
        return Err("screenshotr: DLMessageProcessMessage has no payload".into());
    }
    let dict = arr[1]
        .as_dictionary()
        .ok_or_else(|| "screenshotr: DLMessageProcessMessage payload is not a dict".to_string())?;
    let mt = dict
        .get("MessageType")
        .and_then(|v| v.as_string())
        .unwrap_or("");
    if mt != "ScreenShotReply" {
        if mt.is_empty() {
            return Err("screenshotr: ScreenShotReply missing MessageType".into());
        }
        return Err(format!(
            "screenshotr: expected ScreenShotReply, got `{}`",
            mt
        ));
    }
    let data = dict
        .get("ScreenShotData")
        .ok_or_else(|| "screenshotr: ScreenShotReply has no ScreenShotData".to_string())?
        .as_data()
        .ok_or_else(|| "screenshotr: ScreenShotData is not <data>".to_string())?;
    Ok(data.to_vec())
}

/// Image format detection used by `idevicescreenshot`: PNG on iOS 9+, TIFF on older releases.
pub fn detect_image_extension(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 4 {
        if bytes.starts_with(b"\x89PNG") {
            return "png";
        }
        if &bytes[..4] == b"MM\x00\x2a" || &bytes[..4] == b"II\x2a\x00" {
            return "tiff";
        }
    }
    "dat"
}

/// MIME type matching the extension returned by [`detect_image_extension`].
pub fn detect_image_mime(bytes: &[u8]) -> &'static str {
    match detect_image_extension(bytes) {
        "png" => "image/png",
        "tiff" => "image/tiff",
        _ => "application/octet-stream",
    }
}

/// `screenshot-YYYY-MM-DD-HH-MM-SS` prefix (UTC), shape borrowed from `idevicescreenshot.c`.
/// Each caller passes its own broken-down time so this crate stays free of date-time deps.
pub fn default_screenshot_basename(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> String {
    format!(
        "screenshot-{:04}-{:02}-{:02}-{:02}-{:02}-{:02}",
        year, month, day, hour, minute, second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_dl_versions_ok() {
        let bytes = build_dl_versions_ok(SCREENSHOTR_VERSION_MAJOR).unwrap();
        let v: Value = plist::from_bytes(&bytes).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].as_string().unwrap(), "DLMessageVersionExchange");
        assert_eq!(arr[1].as_string().unwrap(), "DLVersionsOk");
        assert_eq!(
            arr[2].as_unsigned_integer().unwrap(),
            SCREENSHOTR_VERSION_MAJOR
        );
    }

    #[test]
    fn parses_screenshot_reply_with_png() {
        let mut inner = plist::Dictionary::new();
        inner.insert("MessageType".into(), Value::String("ScreenShotReply".into()));
        inner.insert(
            "ScreenShotData".into(),
            Value::Data(b"\x89PNG\r\n\x1a\nfake-image-bytes".to_vec()),
        );
        let arr = Value::Array(vec![
            Value::String("DLMessageProcessMessage".into()),
            Value::Dictionary(inner),
        ]);
        let mut buf = Vec::new();
        arr.to_writer_binary(&mut buf).unwrap();
        let img = parse_screenshot_reply(&buf).unwrap();
        assert!(img.starts_with(b"\x89PNG"));
        assert_eq!(detect_image_extension(&img), "png");
        assert_eq!(detect_image_mime(&img), "image/png");
    }

    #[test]
    fn rejects_higher_devicelink_version() {
        assert!(check_screenshotr_version(401, 0).is_err());
        assert!(check_screenshotr_version(400, 1).is_err());
        assert!(check_screenshotr_version(400, 0).is_ok());
        assert!(check_screenshotr_version(399, 99).is_ok());
    }

    #[test]
    fn parses_version_exchange_array() {
        let arr = Value::Array(vec![
            Value::String("DLMessageVersionExchange".into()),
            Value::Integer(400u64.into()),
            Value::Integer(0u64.into()),
        ]);
        let mut buf = Vec::new();
        arr.to_writer_binary(&mut buf).unwrap();
        let (maj, min) = parse_dl_version_exchange(&buf).unwrap();
        assert_eq!((maj, min), (400, 0));
    }

    #[test]
    fn detects_tiff_magic() {
        assert_eq!(detect_image_extension(b"MM\x00\x2axxxx"), "tiff");
        assert_eq!(detect_image_extension(b"II\x2a\x00xxxx"), "tiff");
        assert_eq!(detect_image_extension(b"binary-blob"), "dat");
    }

    #[test]
    fn detect_image_mime_matches_extension() {
        assert_eq!(detect_image_mime(b"\x89PNG\r\n\x1a\n"), "image/png");
        assert_eq!(detect_image_mime(b"MM\x00\x2axxxx"), "image/tiff");
        assert_eq!(detect_image_mime(b"random"), "application/octet-stream");
        assert_eq!(detect_image_extension(b""), "dat");
    }

    #[test]
    fn build_screenshot_request_is_valid_dl_envelope() {
        let bytes = build_screenshot_request().unwrap();
        let v: Value = plist::from_bytes(&bytes).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_string().unwrap(), "DLMessageProcessMessage");
        let inner = arr[1].as_dictionary().unwrap();
        assert_eq!(
            inner.get("MessageType").and_then(|v| v.as_string()),
            Some("ScreenShotRequest")
        );
    }

    #[test]
    fn build_disconnect_uses_canonical_empty_parameter_string() {
        let bytes = build_disconnect().unwrap();
        let v: Value = plist::from_bytes(&bytes).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr[0].as_string().unwrap(), "DLMessageDisconnect");
        assert_eq!(arr[1].as_string().unwrap(), "___EmptyParameterString___");
    }

    #[test]
    fn frame_plist_message_prepends_u32_be_length() {
        let payload = b"hello bplist";
        let framed = frame_plist_message(payload);
        assert_eq!(framed.len(), 4 + payload.len());
        let len = u32::from_be_bytes(framed[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, payload.len());
        assert_eq!(&framed[4..], payload);

        // Empty payload still gets a 4-byte length prefix.
        let empty = frame_plist_message(&[]);
        assert_eq!(empty, [0u8; 4]);
    }

    #[test]
    fn parse_dl_device_ready_accepts_canonical_message() {
        let arr = Value::Array(vec![Value::String("DLMessageDeviceReady".into())]);
        let mut buf = Vec::new();
        arr.to_writer_binary(&mut buf).unwrap();
        parse_dl_device_ready(&buf).unwrap();
    }

    #[test]
    fn parse_dl_device_ready_rejects_non_ready_messages() {
        let arr = Value::Array(vec![Value::String("DLMessageDisconnect".into())]);
        let mut buf = Vec::new();
        arr.to_writer_binary(&mut buf).unwrap();
        let err = parse_dl_device_ready(&buf).unwrap_err();
        assert!(err.contains("DLMessageDeviceReady"));

        // Non-DL command is also rejected.
        let arr = Value::Array(vec![Value::String("Something".into())]);
        let mut buf = Vec::new();
        arr.to_writer_binary(&mut buf).unwrap();
        assert!(parse_dl_device_ready(&buf).is_err());
    }

    #[test]
    fn parse_screenshot_reply_rejects_wrong_message_type() {
        let mut inner = plist::Dictionary::new();
        inner.insert("MessageType".into(), Value::String("Bogus".into()));
        inner.insert("ScreenShotData".into(), Value::Data(vec![1, 2, 3]));
        let arr = Value::Array(vec![
            Value::String("DLMessageProcessMessage".into()),
            Value::Dictionary(inner),
        ]);
        let mut buf = Vec::new();
        arr.to_writer_binary(&mut buf).unwrap();
        assert!(parse_screenshot_reply(&buf)
            .unwrap_err()
            .contains("ScreenShotReply"));
    }

    #[test]
    fn parse_screenshot_reply_rejects_missing_data() {
        let mut inner = plist::Dictionary::new();
        inner.insert("MessageType".into(), Value::String("ScreenShotReply".into()));
        let arr = Value::Array(vec![
            Value::String("DLMessageProcessMessage".into()),
            Value::Dictionary(inner),
        ]);
        let mut buf = Vec::new();
        arr.to_writer_binary(&mut buf).unwrap();
        assert!(parse_screenshot_reply(&buf)
            .unwrap_err()
            .contains("ScreenShotData"));
    }

    #[test]
    fn parse_dl_version_exchange_rejects_wrong_command() {
        let arr = Value::Array(vec![
            Value::String("DLMessageBogus".into()),
            Value::Integer(400u64.into()),
            Value::Integer(0u64.into()),
        ]);
        let mut buf = Vec::new();
        arr.to_writer_binary(&mut buf).unwrap();
        assert!(parse_dl_version_exchange(&buf).is_err());
    }

    #[test]
    fn default_screenshot_basename_is_zero_padded() {
        assert_eq!(
            default_screenshot_basename(2026, 1, 2, 3, 4, 5),
            "screenshot-2026-01-02-03-04-05"
        );
    }
}
