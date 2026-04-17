//! Lockdown over WebUSB: cleartext + optional **rustls** after `StartSession` when PEM keys are loaded from the pair-record plist.

use idevice_usb_core::lockdown_proto::{
    format_lockdown_getvalue_display, start_session_enable_ssl, LOCKDOWN_DIAGNOSTIC_GET_VALUES,
    LOCKDOWND_PORT,
};
use wasm_bindgen::prelude::*;
use web_sys::UsbDevice;

use crate::crash_reports_wasm;

use crate::lockdown_tls_wasm::{parse_tls_client_auth, parse_tls_sni};
use crate::pair_record_plist::pair_record_from_xml_plist;
use crate::wasm_log;
use crate::web_usb::{prepare_apple_usb, request_apple_device};
use crate::web_usb_session::{
    pairing_ids_from_mode, pairing_ids_from_plist_xml, WebUsbLockdownPipe,
};

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}

/// `QueryType` on lockdownd (cleartext). **`verbose`**: log mux/TCP details to the browser console.
#[wasm_bindgen(js_name = lockdownQueryTypePickDevice)]
pub async fn lockdown_query_type_pick_device(verbose: bool) -> Result<String, JsValue> {
    let dev = request_apple_device().await?;
    lockdown_query_type(dev, verbose).await
}

#[wasm_bindgen(js_name = lockdownQueryType)]
pub async fn lockdown_query_type(device: UsbDevice, verbose: bool) -> Result<String, JsValue> {
    wasm_log::info("lockdown: QueryType — USB setup + mux + cleartext request");
    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;
    pipe.query_type().await
}

/// Parse **`HostID`** / **`SystemBUID`** from XML pair-record plist bytes (libimobiledevice-style keys).
/// Returns a JS object `{ hostId, systemBuid }` for use with **`lockdownFetchWithPlistXml`** or manual fields.
#[wasm_bindgen(js_name = pairingIdsFromPlistXml)]
pub fn pairing_ids_from_plist_xml_js(plist_xml: &str) -> Result<JsValue, JsValue> {
    let ids = pairing_ids_from_plist_xml(plist_xml)?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("hostId"),
        &JsValue::from_str(&ids.host_id),
    )
    .map_err(|_| JsValue::from_str("pairingIdsFromPlistXml: set hostId"))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("systemBuid"),
        &JsValue::from_str(&ids.system_buid),
    )
    .map_err(|_| JsValue::from_str("pairingIdsFromPlistXml: set systemBuid"))?;
    Ok(obj.into())
}

/// **`QueryType`** → **`StartSession`** → **`GetValue`** batch (cleartext or TLS). Requires a **full** XML pair-record plist
/// (HostID, SystemBUID, and PEM keys). **`tls_client_auth`**: `host` | `root` | `chain`. **`tls_sni`**: `device` | `none`.
#[wasm_bindgen(js_name = lockdownFetchWithPlistXml)]
pub async fn lockdown_fetch_with_plist_xml(
    device: UsbDevice,
    plist_xml: &str,
    verbose: bool,
    tls_client_auth: &str,
    tls_sni: &str,
) -> Result<String, JsValue> {
    wasm_log::info("plist-fetch: parsing full XML pair record (IDs + PEM keys)…");
    let (keys, ids) = pair_record_from_xml_plist(plist_xml).map_err(|e| JsValue::from_str(&e))?;
    wasm_log::info(&format!(
        "plist-fetch: HostID + SystemBUID + TLS keys parsed (host_id {} chars)",
        ids.host_id.len()
    ));

    wasm_log::info("plist-fetch: prepare_apple_usb + mux TCP to lockdownd…");
    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;

    wasm_log::info("plist-fetch: QueryType…");
    let qt = pipe.query_type().await?;

    wasm_log::info("plist-fetch: StartSession (pair-record IDs)…");
    let sess = pipe.start_session_cleartext(&ids).await?;

    if start_session_enable_ssl(&sess) {
        wasm_log::info("plist-fetch: EnableSessionSSL — rustls handshake…");
        pipe
            .upgrade_lockdown_tls(
                &keys,
                parse_tls_client_auth(tls_client_auth),
                parse_tls_sni(tls_sni),
            )
            .await?;
    }

    let mut out = String::from("=== Device info (pair-record plist) ===\n\n");
    out.push_str("### QueryType\n");
    out.push_str(&trunc(&qt, 4000));
    out.push_str("\n\n### GetValue\n");

    for (label, domain, key) in LOCKDOWN_DIAGNOSTIC_GET_VALUES.iter().take(12) {
        wasm_log::info(&format!("plist-fetch: GetValue — {label}…"));
        match pipe.get_value_cleartext(domain, key).await {
            Ok(xml) => {
                let summary = trunc(&format_lockdown_getvalue_display(&xml), 6000);
                out.push_str(&format!("- {label}: {summary}\n"));
                wasm_log::debug_verbose(
                    verbose,
                    &format!("plist-fetch: {label} raw XML {} bytes", xml.len()),
                );
            }
            Err(e) => {
                out.push_str(&format!("- {label}: ERROR {e:?}\n"));
                wasm_log::warn(&format!("plist-fetch: GetValue {label} failed: {e:?}"));
            }
        }
    }

    wasm_log::info("plist-fetch: GetValue — com.apple.mobile.battery…");
    match pipe.get_value_cleartext("com.apple.mobile.battery", "").await {
        Ok(xml) => {
            let summary = trunc(&format_lockdown_getvalue_display(&xml), 8000);
            out.push_str(&format!("\n### Battery\n{summary}\n"));
        }
        Err(e) => {
            out.push_str(&format!("\n### Battery\nERROR: {e:?}\n"));
            wasm_log::warn(&format!("plist-fetch: battery GetValue failed: {e:?}"));
        }
    }

    wasm_log::info("plist-fetch: finished OK");
    Ok(out)
}

/// `QueryType` → **`StartSession`** → **`GetValue`** battery domain. When **`EnableSessionSSL`**, pass **`pair_record_plist_xml`**
/// (full XML plist with PEM keys) so WASM can run lockdown TLS.
#[wasm_bindgen(js_name = lockdownBatteryPickDevice)]
pub async fn lockdown_battery_pick_device(
    mode: &str,
    host_id: &str,
    system_buid: &str,
    verbose: bool,
    pair_record_plist_xml: &str,
    tls_client_auth: &str,
    tls_sni: &str,
) -> Result<String, JsValue> {
    let dev = request_apple_device().await?;
    lockdown_battery(
        dev,
        mode,
        host_id,
        system_buid,
        verbose,
        pair_record_plist_xml,
        tls_client_auth,
        tls_sni,
    )
    .await
}

#[wasm_bindgen(js_name = lockdownBattery)]
pub async fn lockdown_battery(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    verbose: bool,
    pair_record_plist_xml: &str,
    tls_client_auth: &str,
    tls_sni: &str,
) -> Result<String, JsValue> {
    wasm_log::info(&format!(
        "lockdown: battery — pair mode={} (USB + mux + QueryType + StartSession + GetValue)",
        mode.trim()
    ));
    let ids = pairing_ids_from_mode(mode, host_id, system_buid)?;
    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;
    let _qt = pipe.query_type().await?;
    let sess = pipe.start_session_cleartext(&ids).await?;
    if start_session_enable_ssl(&sess) {
        let t = pair_record_plist_xml.trim();
        if t.is_empty() {
            return Ok(format!(
                "StartSession requested TLS (EnableSessionSSL). Pass the full XML pair-record plist text as `pair_record_plist_xml` (including HostPrivateKey, HostCertificate, RootCertificate, RootPrivateKey), or use the native idevice CLI.\n\n--- StartSession (truncated) ---\n{}",
                trunc(&sess, 2000)
            ));
        }
        let (keys, _) = match pair_record_from_xml_plist(t) {
            Ok(v) => v,
            Err(e) => {
                return Ok(format!(
                    "EnableSessionSSL — could not parse pair-record PEM keys from XML plist: {}\n\n--- StartSession (truncated) ---\n{}",
                    e,
                    trunc(&sess, 2000)
                ));
            }
        };
        pipe
            .upgrade_lockdown_tls(
                &keys,
                parse_tls_client_auth(tls_client_auth),
                parse_tls_sni(tls_sni),
            )
            .await?;
    }
    let xml = pipe.get_value_cleartext("com.apple.mobile.battery", "").await?;
    Ok(format!(
        "=== Battery (GetValue) ===\n\n{}",
        trunc(&format_lockdown_getvalue_display(&xml), 12000)
    ))
}

/// Same as battery, then diagnostic **`GetValue`** calls. Use **`pair_record_plist_xml`** when the device requires TLS.
#[wasm_bindgen(js_name = lockdownDiagnosticsPickDevice)]
pub async fn lockdown_diagnostics_pick_device(
    mode: &str,
    host_id: &str,
    system_buid: &str,
    verbose: bool,
    pair_record_plist_xml: &str,
    tls_client_auth: &str,
    tls_sni: &str,
) -> Result<String, JsValue> {
    let dev = request_apple_device().await?;
    lockdown_diagnostics(
        dev,
        mode,
        host_id,
        system_buid,
        verbose,
        pair_record_plist_xml,
        tls_client_auth,
        tls_sni,
    )
    .await
}

#[wasm_bindgen(js_name = lockdownDiagnostics)]
pub async fn lockdown_diagnostics(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    verbose: bool,
    pair_record_plist_xml: &str,
    tls_client_auth: &str,
    tls_sni: &str,
) -> Result<String, JsValue> {
    wasm_log::info(&format!(
        "lockdown: diagnostics — pair mode={} (GetValue batch)",
        mode.trim()
    ));
    let ids = pairing_ids_from_mode(mode, host_id, system_buid)?;
    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;
    let _qt = pipe.query_type().await?;
    let sess = pipe.start_session_cleartext(&ids).await?;
    if start_session_enable_ssl(&sess) {
        let t = pair_record_plist_xml.trim();
        if t.is_empty() {
            return Ok(format!(
                "StartSession requested TLS (EnableSessionSSL). Pass the full XML pair-record plist as `pair_record_plist_xml`, or use the native idevice CLI.\n\n--- StartSession (truncated) ---\n{}",
                trunc(&sess, 2000)
            ));
        }
        let (keys, _) = match pair_record_from_xml_plist(t) {
            Ok(v) => v,
            Err(e) => {
                return Ok(format!(
                    "EnableSessionSSL — could not parse pair-record PEM keys: {}\n\n--- StartSession (truncated) ---\n{}",
                    e,
                    trunc(&sess, 2000)
                ));
            }
        };
        pipe
            .upgrade_lockdown_tls(
                &keys,
                parse_tls_client_auth(tls_client_auth),
                parse_tls_sni(tls_sni),
            )
            .await?;
    }
    let mut out = String::from("=== Diagnostics (GetValue) ===\n");
    out.push_str(&format!(
        "({} queries — not Apple sysdiagnose)\n",
        LOCKDOWN_DIAGNOSTIC_GET_VALUES.len()
    ));
    for (label, domain, key) in LOCKDOWN_DIAGNOSTIC_GET_VALUES {
        wasm_log::info(&format!("diagnostics: GetValue — {label}…"));
        match pipe.get_value_cleartext(domain, key).await {
            Ok(xml) => {
                let block = format_lockdown_getvalue_display(&xml);
                let block = trunc(&block, 10000);
                out.push_str(&format!("\n── {} ──\n{}\n", label, block));
            }
            Err(e) => {
                out.push_str(&format!("\n── {} ──\nERROR: {:?}\n", label, e));
            }
        }
    }
    Ok(out)
}

/// **`crashreportmover`** → **`ping`**, then **`crashreportcopymobile`** AFC — same sequence as **`idevicecrashreport`**.
/// Returns a JS **Array** of `{ name: string, data: Uint8Array }`. Requires a **full** XML pair-record plist (PEM keys) and **`EnableSessionSSL`**.
#[wasm_bindgen(js_name = lockdownCrashReports)]
pub async fn lockdown_crash_reports(
    device: UsbDevice,
    pair_record_plist_xml: &str,
    verbose: bool,
    tls_client_auth: &str,
    tls_sni: &str,
    keep: bool,
    filter_substr: &str,
    remove_all: bool,
) -> Result<JsValue, JsValue> {
    crash_reports_wasm::crash_reports_flow(
        device,
        pair_record_plist_xml,
        verbose,
        tls_client_auth,
        tls_sni,
        keep,
        filter_substr,
        remove_all,
    )
    .await
}

#[wasm_bindgen(js_name = lockdownCrashReportsInfo)]
pub fn lockdown_crash_reports_info() -> String {
    format!(
        "WASM: `lockdownCrashReports` runs crashreportmover + AFC over extra mux pseudo-TCP streams (same as the native tool). \
         Load a full pair-record XML plist, set TLS client cert / SNI like Battery, then call with keep/filter/removeAll flags. \
         Output is an array of {{ name, data }}. Lockdownd port: {}.",
        LOCKDOWND_PORT
    )
}
