//! Lockdown over WebUSB: cleartext + optional **rustls** after `StartSession`, with two pair paths:
//! - **Generated keys** (`mode = random` / `legacy`) → full `Pair` + Trust polling + TLS, like the CLI.
//! - **Pair-record plist** (`mode = plist` or `pair_record_plist_xml` passed) → `StartSession` + TLS directly.

use idevice_usb_core::lockdown_proto::{
    format_lockdown_device_report, format_lockdown_getvalue_display, start_session_enable_ssl,
    LOCKDOWN_DIAGNOSTIC_GET_VALUES, LOCKDOWND_PORT,
};
use idevice_usb_core::PairingIds;
use js_sys::Function;
use std::sync::Mutex;
use wasm_bindgen::prelude::*;
use web_sys::UsbDevice;

use crate::crash_reports_wasm;

use crate::lockdown_tls_wasm::{
    parse_tls_client_auth, parse_tls_sni, LockdownTlsClientAuth, LockdownTlsSni,
};
use crate::pair_record_plist::{pair_record_from_xml_plist, pair_record_to_xml_plist};
use crate::wasm_crypto::{generate_host_keys, WasmHostKeys};
use crate::wasm_log;
use crate::web_usb::{prepare_apple_usb, request_apple_device};
use crate::web_usb_session::{
    pairing_ids_from_mode, pairing_ids_from_plist_xml, WebUsbLockdownPipe,
};

/// Default Trust-wait window for generated-key `Pair`: matches the CLI `--pair-trust-timeout-secs` default.
const DEFAULT_PAIR_TIMEOUT_SECS: u32 = 120;
const DEFAULT_PAIR_POLL_SECS: u32 = 4;

/// RSA-2048 host/root chain built on **Pick device** so **Pair** can reach lockdownd (Trust prompt) sooner.
static PREFETCHED_PAIR_KEYS: Mutex<Option<WasmHostKeys>> = Mutex::new(None);

fn take_prefetched_pair_keys() -> Option<WasmHostKeys> {
    PREFETCHED_PAIR_KEYS
        .lock()
        .ok()
        .and_then(|mut g| g.take())
}

fn host_keys_for_pair() -> Result<WasmHostKeys, JsValue> {
    if let Some(keys) = take_prefetched_pair_keys() {
        wasm_log::info("pair: using prefetched RSA host keys");
        return Ok(keys);
    }
    generate_host_keys().map_err(|e| JsValue::from_str(&e))
}

/// Start generating RSA host keys in the background (call right after `requestAppleDevice`).
/// `lockdownPair` consumes the cache so the Trust prompt is not delayed by key generation.
#[wasm_bindgen(js_name = prefetchPairHostKeys)]
pub fn prefetch_pair_host_keys() {
    if PREFETCHED_PAIR_KEYS
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|_| ()))
        .is_some()
    {
        return;
    }
    wasm_bindgen_futures::spawn_local(async {
        match generate_host_keys() {
            Ok(keys) => {
                if let Ok(mut g) = PREFETCHED_PAIR_KEYS.lock() {
                    *g = Some(keys);
                    wasm_log::info("pair: RSA host keys prefetched — Pair will skip key generation");
                }
            }
            Err(e) => wasm_log::warn(&format!("pair: key prefetch failed: {e}")),
        }
    });
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}

/// How the caller wants to get (keys, ids, should_pair) for a lockdown session.
enum AuthSource {
    /// Pre-existing pair record — `StartSession` directly, no `Pair`.
    Plist { keys: WasmHostKeys, ids: PairingIds },
    /// Generate fresh keys + new ids (random / legacy) — run `Pair` first.
    Generate { ids: PairingIds },
}

fn auth_source(
    mode: &str,
    host_id: &str,
    system_buid: &str,
    pair_record_plist_xml: &str,
) -> Result<AuthSource, JsValue> {
    let plist_text = pair_record_plist_xml.trim();
    if !plist_text.is_empty() {
        let (keys, ids) =
            pair_record_from_xml_plist(plist_text).map_err(|e| JsValue::from_str(&e))?;
        return Ok(AuthSource::Plist { keys, ids });
    }
    let m = mode.trim();
    match m {
        "random" | "legacy" => {
            let ids = pairing_ids_from_mode(m, host_id, system_buid)?;
            Ok(AuthSource::Generate { ids })
        }
        "plist" => Err(JsValue::from_str(
            "pair mode `plist` but no pair-record XML was provided",
        )),
        _ => Err(JsValue::from_str(
            "pair mode must be random, legacy, or plist",
        )),
    }
}

/// Establish a lockdown session: optionally `Pair` (generated keys), then `StartSession` + TLS when
/// **`EnableSessionSSL`** is set. Returns the `WasmHostKeys` used (for secondary service TLS).
async fn establish_lockdown_session(
    pipe: &mut WebUsbLockdownPipe<'_>,
    src: AuthSource,
    tls_client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
) -> Result<(WasmHostKeys, PairingIds, bool), JsValue> {
    let (keys, ids, paired_here) = match src {
        AuthSource::Plist { keys, ids } => {
            wasm_log::info("lockdown: using pair-record plist — skipping Pair");
            (keys, ids, false)
        }
        AuthSource::Generate { ids } => {
            let keys = host_keys_for_pair()?;
            wasm_log::info("lockdown: Pair with freshly generated RSA keys (Trust prompt)…");
            let _qt = pipe.query_type().await?;
            let _ = pipe
                .pair_with_trust_wait(&keys, &ids, DEFAULT_PAIR_TIMEOUT_SECS, DEFAULT_PAIR_POLL_SECS)
                .await?;
            wasm_log::info("lockdown: Pair OK — re-opening mux TCP before StartSession…");
            pipe.reopen_lockdown_tcp().await?;
            (keys, ids, true)
        }
    };
    let _qt = pipe.query_type().await?;
    let sess = pipe.start_session_cleartext(&ids).await?;
    if sess.contains("<key>Error</key>") {
        return Err(JsValue::from_str(&format!(
            "StartSession rejected: {}",
            trunc(&sess, 260).replace('\n', " ")
        )));
    }
    if start_session_enable_ssl(&sess) {
        wasm_log::info("lockdown: EnableSessionSSL — rustls handshake…");
        pipe.upgrade_lockdown_tls(&keys, tls_client_auth, tls_sni)
            .await?;
    } else {
        wasm_log::info("lockdown: StartSession did not enable SSL — continuing cleartext");
    }
    Ok((keys, ids, paired_here))
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
        pipe.upgrade_lockdown_tls(
            &keys,
            parse_tls_client_auth(tls_client_auth),
            parse_tls_sni(tls_sni),
        )
        .await?;
    }

    let mut rows: Vec<(&str, &str, &str, Result<String, String>)> =
        Vec::with_capacity(LOCKDOWN_DIAGNOSTIC_GET_VALUES.len());
    for (label, domain, key) in LOCKDOWN_DIAGNOSTIC_GET_VALUES {
        wasm_log::info(&format!("plist-fetch: GetValue — {label}…"));
        let r = pipe
            .get_value_cleartext(domain, key)
            .await
            .map_err(|e| format!("{e:?}"));
        if let Ok(ref xml) = r {
            wasm_log::debug_verbose(
                verbose,
                &format!("plist-fetch: {label} raw XML {} bytes", xml.len()),
            );
        } else if let Err(ref e) = r {
            wasm_log::warn(&format!("plist-fetch: GetValue {label} failed: {e}"));
        }
        rows.push((label, domain, key, r));
    }

    let mut out = String::from("=== Device report (pair-record plist) ===\n\n");
    out.push_str("QueryType\n---------\n");
    out.push_str(&trunc(&qt, 4000));
    out.push_str("\n\n");
    out.push_str(&format_lockdown_device_report(&rows));

    wasm_log::info("plist-fetch: finished OK");
    Ok(out)
}

/// Pair with **freshly generated** RSA keys (random / legacy ids), wait for Trust on the device,
/// and return the resulting pair-record **XML plist** (HostID / SystemBUID / PEM keys) so the page
/// can save it for subsequent `StartSession` + TLS without re-prompting the user.
#[wasm_bindgen(js_name = lockdownPair)]
pub async fn lockdown_pair(
    device: UsbDevice,
    mode: &str,
    verbose: bool,
) -> Result<String, JsValue> {
    wasm_log::info(&format!(
        "pair: mode={} — generating host keys + Pair + Trust polling",
        mode.trim()
    ));
    let ids = pairing_ids_from_mode(mode, "", "")?;
    let keys = host_keys_for_pair()?;
    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;
    let _qt = pipe.query_type().await?;
    let _ = pipe
        .pair_with_trust_wait(&keys, &ids, DEFAULT_PAIR_TIMEOUT_SECS, DEFAULT_PAIR_POLL_SECS)
        .await?;
    Ok(pair_record_to_xml_plist(&keys, &ids))
}

/// `QueryType` → optional `Pair` (generated keys) → `StartSession` → optional TLS → `GetValue battery`.
/// Pass **`pair_record_plist_xml`** to reuse an existing pair record; otherwise keys are generated based on `mode`.
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
        "lockdown: battery — pair mode={} plist={}B",
        mode.trim(),
        pair_record_plist_xml.trim().len()
    ));
    let src = auth_source(mode, host_id, system_buid, pair_record_plist_xml)?;
    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;
    let (_keys, _ids, _paired) = establish_lockdown_session(
        &mut pipe,
        src,
        parse_tls_client_auth(tls_client_auth),
        parse_tls_sni(tls_sni),
    )
    .await?;
    let xml = pipe.get_value_cleartext("com.apple.mobile.battery", "").await?;
    Ok(format!(
        "=== Battery (GetValue) ===\n\n{}",
        trunc(&format_lockdown_getvalue_display(&xml), 12000)
    ))
}

/// Same as battery, then the diagnostic `GetValue` batch.
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
        "lockdown: diagnostics — pair mode={} plist={}B",
        mode.trim(),
        pair_record_plist_xml.trim().len()
    ));
    let src = auth_source(mode, host_id, system_buid, pair_record_plist_xml)?;
    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;
    let (_keys, _ids, _paired) = establish_lockdown_session(
        &mut pipe,
        src,
        parse_tls_client_auth(tls_client_auth),
        parse_tls_sni(tls_sni),
    )
    .await?;
    let mut rows: Vec<(&str, &str, &str, Result<String, String>)> =
        Vec::with_capacity(LOCKDOWN_DIAGNOSTIC_GET_VALUES.len());
    let mut prohibited = 0usize;
    let mut errors = 0usize;
    for (label, domain, key) in LOCKDOWN_DIAGNOSTIC_GET_VALUES {
        wasm_log::info(&format!("diagnostics: GetValue — {label}…"));
        let r = pipe
            .get_value_cleartext(domain, key)
            .await
            .map_err(|e| format!("{e:?}"));
        match &r {
            Ok(_) => {}
            Err(e) if e.contains("GetProhibited") => prohibited += 1,
            Err(_) => errors += 1,
        }
        rows.push((label, domain, key, r));
    }

    let mut out = String::from("=== Diagnostics (lockdown GetValue snapshot) ===\n");
    out.push_str(&format!(
        "{n} queries — not Apple sysdiagnose. {ok} ok / {prohib} GetProhibited / {err} other errors.\n\n",
        n = rows.len(),
        ok = rows.len() - prohibited - errors,
        prohib = prohibited,
        err = errors
    ));
    out.push_str(&format_lockdown_device_report(&rows));
    Ok(out)
}

/// `crashreportmover` + AFC crash report copy. Works with either a pre-existing pair-record plist or
/// with generated keys (pair mode `random` / `legacy`) — the latter runs a full `Pair` + Trust flow first.
#[wasm_bindgen(js_name = lockdownCrashReports)]
#[allow(clippy::too_many_arguments)]
pub async fn lockdown_crash_reports(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
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
        mode,
        host_id,
        system_buid,
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
        "WASM crashreportmover + AFC over extra mux pseudo-TCP streams. \
         Choose pair mode `random`/`legacy` (Pair + Trust on first run, then StartSession + TLS) \
         or pass a saved pair-record XML plist. Output is an array of {{ name, data }}. \
         Lockdownd port: {}.",
        LOCKDOWND_PORT
    )
}

/// List sysdiagnose `.tar.gz` archives on the device (metadata only; no download).
#[wasm_bindgen(js_name = lockdownSysdiagnoseList)]
#[allow(clippy::too_many_arguments)]
pub async fn lockdown_sysdiagnose_list(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    pair_record_plist_xml: &str,
    verbose: bool,
    tls_client_auth: &str,
    tls_sni: &str,
) -> Result<JsValue, JsValue> {
    crate::sysdiagnose_wasm::sysdiagnose_list_flow(
        device,
        mode,
        host_id,
        system_buid,
        pair_record_plist_xml,
        verbose,
        tls_client_auth,
        tls_sni,
    )
    .await
}

/// Download one sysdiagnose `.tar.gz` by device AFC path (up to ~512 MiB).
#[wasm_bindgen(js_name = lockdownSysdiagnoseDownload)]
#[allow(clippy::too_many_arguments)]
pub async fn lockdown_sysdiagnose_download(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    pair_record_plist_xml: &str,
    verbose: bool,
    tls_client_auth: &str,
    tls_sni: &str,
    device_path: &str,
    on_progress: Option<Function>,
) -> Result<JsValue, JsValue> {
    crate::sysdiagnose_wasm::sysdiagnose_download_flow(
        device,
        mode,
        host_id,
        system_buid,
        pair_record_plist_xml,
        verbose,
        tls_client_auth,
        tls_sni,
        device_path,
        on_progress,
    )
    .await
}

#[wasm_bindgen(js_name = lockdownSysdiagnoseInfo)]
pub fn lockdown_sysdiagnose_info() -> String {
    "List/download sysdiagnose archives from DiagnosticLogs/sysdiagnose via crashreport AFC. \
     Trigger sysdiagnose on the iPhone first (Vol Up + Vol Down + Side button ~0.7s), wait ~5 minutes, \
     then list (returns AFC walk debug + matches). Accepts .tar.gz, -tar.gz, .tgz, .tar. \
     Archives can be large (100–500 MB); browser memory limits apply.".into()
}
