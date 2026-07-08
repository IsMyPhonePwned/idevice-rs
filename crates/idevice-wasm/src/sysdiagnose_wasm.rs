//! List and download Apple **sysdiagnose** archives from the device crash-report AFC tree
//! (`DiagnosticLogs/sysdiagnose/…`), same paths as **libimobiledevice** `idevicecrashreport`.

use async_recursion::async_recursion;
use js_sys::Function;
use wasm_bindgen::prelude::*;
use web_sys::UsbDevice;

use crate::afc_wasm::{AfcSessionWasm, AFC_FOPEN_RDONLY};
use crate::crash_reports_wasm::{crash_reports_flow, open_crash_afc_session};
use crate::lockdown_tls_wasm::{LockdownTlsClientAuth, LockdownTlsSni};
use crate::pair_record_plist::pair_record_from_xml_plist;
use crate::wasm_crypto::{generate_host_keys, WasmHostKeys};
use crate::wasm_log;
use crate::web_usb::prepare_apple_usb;
use crate::web_usb_session::{pairing_ids_from_mode, WebUsbLockdownPipe};

const SYSDIAGNOSE_DIR: &str = "DiagnosticLogs/sysdiagnose";
const SYSDIAGNOSE_PROBE_PATHS: &[&str] = &[
    SYSDIAGNOSE_DIR,
    "./DiagnosticLogs/sysdiagnose",
    "DiagnosticLogs/Sysdiagnose",
    "/DiagnosticLogs/sysdiagnose",
];
const SYSDIAGNOSE_MAX_BYTES: usize = 512 * 1024 * 1024;
const LIST_MAX_DEPTH: u32 = 24;
const LIST_MAX_MATCHES: usize = 64;
const LIST_MAX_SCAN: usize = 2000;

fn invoke_on_progress(on_progress: Option<&Function>, read: usize, total: usize) {
    let Some(cb) = on_progress else { return };
    if total == 0 {
        return;
    }
    let _ = cb.call2(
        &JsValue::NULL,
        &JsValue::from_f64(read as f64),
        &JsValue::from_f64(total as f64),
    );
}

#[derive(Clone)]
struct SysdiagnoseEntry {
    path: String,
    name: String,
    size_bytes: u64,
}

fn push_debug(debug: &mut String, line: &str) {
    debug.push_str(line);
    if !line.ends_with('\n') {
        debug.push('\n');
    }
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// True when `name` looks like a finished sysdiagnose archive (not an in-progress partial).
fn is_finished_archive_name(name: &str) -> bool {
    let n = lower(name);
    if n.contains("in_progress") || n.ends_with(".tmp") || n.ends_with(".log") {
        return false;
    }
    n.ends_with(".tar.gz")
        || n.ends_with("-tar.gz")
        || n.ends_with(".tgz")
        || n.ends_with(".tar")
}

fn looks_like_sysdiagnose_path(rel_path: &str, name: &str) -> bool {
    let p = lower(rel_path);
    let n = lower(name);
    p.contains("sysdiagnose") || n.contains("sysdiagnose") || p.contains("diagnosticlogs")
}

fn afc_status_label(code: u64) -> &'static str {
    match code {
        0 => "SUCCESS",
        8 => "OBJECT_NOT_FOUND",
        9 => "OBJECT_IS_DIR",
        10 => "PERM_DENIED",
        _ => "ERROR",
    }
}

fn explain_afc_err(op: &str, err: &str) -> String {
    let prefix = format!("AFC {op} STATUS error ");
    if let Some(code_str) = err.strip_prefix(&prefix) {
        if let Ok(code) = code_str.trim().parse::<u64>() {
            return format!("{op} → {} ({code})", afc_status_label(code));
        }
    }
    format!("{op} → {err}")
}

fn classify_skip(rel_path: &str, name: &str, st_ifmt: &str) -> Option<&'static str> {
    if st_ifmt == "S_IFDIR" {
        return None;
    }
    let n = lower(name);
    if n.ends_with(".ips") {
        if n.contains("stack") || lower(rel_path).contains("stack") {
            return Some("crash report (.ips stackshot), not the sysdiagnose .tar.gz archive");
        }
        return Some("crash report (.ips), not a sysdiagnose archive");
    }
    if n.contains("sysdiagnose") || looks_like_sysdiagnose_path(rel_path, name) {
        if n.contains("in_progress") {
            return Some("in progress (not finished yet)");
        }
        if n.ends_with(".tmp") || n.ends_with(".log") {
            return Some("partial / log sidecar (not the archive)");
        }
        if !is_finished_archive_name(name) {
            return Some("sysdiagnose-related but not a finished .tar.gz / -tar.gz / .tgz / .tar");
        }
        return None;
    }
    Some("not a sysdiagnose archive (expected DiagnosticLogs/sysdiagnose/*.tar.gz on device AFC)")
}

fn is_sysdiagnose_match(rel_path: &str, name: &str, st_ifmt: &str) -> bool {
    if st_ifmt != "S_IFREG" && st_ifmt != "S_IFLNK" {
        return false;
    }
    if !is_finished_archive_name(name) {
        return false;
    }
    let n = lower(name);
    if n.contains("sysdiagnose") {
        return true;
    }
    looks_like_sysdiagnose_path(rel_path, name)
}

fn is_valid_download_path(path: &str) -> bool {
    let p = path.trim();
    if p.is_empty() {
        return false;
    }
    let name = p.rsplit('/').next().unwrap_or(p);
    is_sysdiagnose_match(p, name, "S_IFREG")
}

fn push_entry(entries: &mut Vec<SysdiagnoseEntry>, path: String, name: String, size_bytes: u64) {
    if entries.len() >= LIST_MAX_MATCHES {
        return;
    }
    if entries.iter().any(|e| e.path == path) {
        return;
    }
    entries.push(SysdiagnoseEntry {
        path,
        name,
        size_bytes,
    });
}

async fn try_add_entry(
    afc: &mut AfcSessionWasm<'_>,
    device_path: &str,
    display_name: &str,
    rel_path: &str,
    scratch: &mut [u8],
    entries: &mut Vec<SysdiagnoseEntry>,
    debug: &mut String,
    verbose: bool,
) -> Result<(), JsValue> {
    let info = match afc.get_file_info_dict(device_path, scratch).await {
        Ok(d) => d,
        Err(e) => {
            push_debug(
                debug,
                &format!("  `{rel_path}` — GET_FILE_INFO failed: {}", explain_afc_err("GET_FILE_INFO", &e)),
            );
            return Ok(());
        }
    };
    let st_ifmt = info
        .get("st_ifmt")
        .map(|s| s.trim())
        .unwrap_or("")
        .to_string();
    let st_size: u64 = info
        .get("st_size")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let link_target = info
        .get("LinkTarget")
        .map(|s| s.trim())
        .unwrap_or("")
        .to_string();
    let extra = if st_ifmt == "S_IFLNK" && !link_target.is_empty() {
        format!(" → LinkTarget={link_target}")
    } else {
        String::new()
    };

    if let Some(reason) = classify_skip(rel_path, display_name, &st_ifmt) {
        push_debug(
            debug,
            &format!("  `{rel_path}`  {st_ifmt}  {st_size} B — skip: {reason}{extra}"),
        );
        return Ok(());
    }

    if is_sysdiagnose_match(rel_path, display_name, &st_ifmt) {
        push_debug(
            debug,
            &format!("  `{rel_path}`  {st_ifmt}  {st_size} B — MATCH{extra}"),
        );
        push_entry(
            entries,
            device_path.to_string(),
            display_name.to_string(),
            st_size,
        );
        wasm_log::debug_verbose(
            verbose,
            &format!("[sysdiagnose] match `{device_path}` ({st_size} bytes)"),
        );
    }
    Ok(())
}

/// `DiagnosticLogs/sysdiagnose` is sometimes absent from the parent `READ_DIR` listing but still
/// reachable directly (or returns PERM_DENIED / NOT_FOUND with useful diagnostics).
async fn probe_sysdiagnose_directories(
    afc: &mut AfcSessionWasm<'_>,
    scratch: &mut [u8],
    entries: &mut Vec<SysdiagnoseEntry>,
    debug: &mut String,
    verbose: bool,
) -> Result<(), JsValue> {
    push_debug(debug, "--- direct `DiagnosticLogs/sysdiagnose` probes ---");
    let mut any_listed = false;

    for path in SYSDIAGNOSE_PROBE_PATHS {
        match afc.get_file_info_dict(path, scratch).await {
            Ok(info) => {
                let st_ifmt = info
                    .get("st_ifmt")
                    .map(|s| s.trim())
                    .unwrap_or("?");
                let st_size = info
                    .get("st_size")
                    .map(|s| s.trim())
                    .unwrap_or("?");
                push_debug(
                    debug,
                    &format!("GET_FILE_INFO `{path}` → {st_ifmt} size={st_size}"),
                );
            }
            Err(e) => push_debug(
                debug,
                &format!("GET_FILE_INFO `{path}`: {}", explain_afc_err("GET_FILE_INFO", &e)),
            ),
        }

        match afc.read_directory(path, scratch).await {
            Ok(names) => {
                any_listed = true;
                push_debug(
                    debug,
                    &format!("READ_DIR `{path}` → {} entr{}", names.len(), if names.len() == 1 { "y" } else { "ies" }),
                );
                if names.is_empty() {
                    push_debug(debug, "  (empty — sysdiagnose folder exists but has no files yet)");
                }
                let prefix = if path.ends_with('/') {
                    path.to_string()
                } else {
                    format!("{path}/")
                };
                for name in names {
                    let device_path = format!("{prefix}{name}");
                    let rel_path = format!("{SYSDIAGNOSE_DIR}/{name}");
                    try_add_entry(
                        afc,
                        &device_path,
                        &name,
                        &rel_path,
                        scratch,
                        entries,
                        debug,
                        verbose,
                    )
                    .await?;
                }
            }
            Err(e) => push_debug(
                debug,
                &format!("READ_DIR `{path}`: {}", explain_afc_err("READ_DIR", &e)),
            ),
        }
    }

    if !any_listed {
        push_debug(
            debug,
            "Note: no `DiagnosticLogs/sysdiagnose` listing succeeded. Files visible in macOS Finder under\n\
             ~/Library/Logs/CrashReporter/MobileDevice/<device>/DiagnosticLogs/sysdiagnose/\n\
             are often **synced copies on the Mac**, not necessarily still present on the device AFC tree.\n\
             Trigger sysdiagnose on the iPhone (Vol Up + Vol Down + Side), wait until it finishes, then list again.",
        );
    }
    Ok(())
}

#[async_recursion(?Send)]
async fn afc_list_sysdiagnose_tree(
    afc: &mut AfcSessionWasm<'_>,
    dev_dir: &str,
    rel_prefix: &str,
    scratch: &mut [u8],
    depth: u32,
    verbose: bool,
    entries: &mut Vec<SysdiagnoseEntry>,
    debug: &mut String,
    scan_count: &mut usize,
) -> Result<(), JsValue> {
    if depth > LIST_MAX_DEPTH || *scan_count >= LIST_MAX_SCAN {
        if depth > LIST_MAX_DEPTH {
            push_debug(debug, &format!("  … depth limit at `{dev_dir}`"));
        }
        return Ok(());
    }

    let list = match afc.read_directory(dev_dir, scratch).await {
        Ok(l) => l,
        Err(e) => {
            push_debug(debug, &explain_afc_err(&format!("READ_DIR `{dev_dir}`"), &e));
            return Ok(());
        }
    };

    push_debug(
        debug,
        &format!(
            "READ_DIR `{dev_dir}` (depth {depth}) → {} entr{}",
            list.len(),
            if list.len() == 1 { "y" } else { "ies" }
        ),
    );
    if list.is_empty() {
        push_debug(debug, "  (empty)");
    }
    wasm_log::info(&format!(
        "[sysdiagnose] READ_DIR `{dev_dir}`: {} entries",
        list.len()
    ));

    let dev_prefix = if dev_dir.ends_with('/') {
        dev_dir.to_string()
    } else {
        format!("{dev_dir}/")
    };

    for name in list {
        if *scan_count >= LIST_MAX_SCAN {
            push_debug(debug, "  … scan limit reached");
            return Ok(());
        }
        *scan_count += 1;

        let source = format!("{dev_prefix}{name}");
        let rel_name = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };

        let info = match afc.get_file_info_dict(&source, scratch).await {
            Ok(d) => d,
            Err(e) => {
                push_debug(
                    debug,
                    &format!("  `{rel_name}` — {}", explain_afc_err("GET_FILE_INFO", &e)),
                );
                wasm_log::warn(&format!("[sysdiagnose] skip `{source}`: {e}"));
                continue;
            }
        };

        let st_ifmt = info
            .get("st_ifmt")
            .map(|s| s.trim())
            .unwrap_or("")
            .to_string();

        wasm_log::debug_verbose(
            verbose,
            &format!("[sysdiagnose]   {rel_name}  {st_ifmt}"),
        );

        if st_ifmt == "S_IFDIR" {
            push_debug(debug, &format!("  `{rel_name}/`  dir"));
            afc_list_sysdiagnose_tree(
                afc,
                &source,
                &rel_name,
                scratch,
                depth + 1,
                verbose,
                entries,
                debug,
                scan_count,
            )
            .await?;
            continue;
        }

        try_add_entry(
            afc,
            &source,
            &name,
            &rel_name,
            scratch,
            entries,
            debug,
            verbose,
        )
        .await?;
    }
    Ok(())
}

async fn afc_read_file_capped(
    afc: &mut AfcSessionWasm<'_>,
    device_path: &str,
    scratch: &mut [u8],
    max_bytes: usize,
    on_progress: Option<&Function>,
) -> Result<Vec<u8>, JsValue> {
    let info = afc
        .get_file_info_dict(device_path, scratch)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    let st_ifmt = info
        .get("st_ifmt")
        .map(|s| s.trim())
        .unwrap_or("");
    if st_ifmt != "S_IFREG" && st_ifmt != "S_IFLNK" {
        return Err(JsValue::from_str(&format!(
            "Not a readable file: {device_path} (st_ifmt={st_ifmt})"
        )));
    }
    let st_size: u64 = info
        .get("st_size")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if st_size as usize > max_bytes {
        return Err(JsValue::from_str(&format!(
            "Sysdiagnose archive too large ({st_size} bytes; browser limit {max_bytes} bytes)"
        )));
    }
    let cap = st_size as usize;

    let h = afc
        .file_open(device_path, AFC_FOPEN_RDONLY, scratch)
        .await
        .map_err(|e| JsValue::from_str(&e))?;

    let mut buf: Vec<u8> = Vec::with_capacity(cap.min(1024 * 1024));
    invoke_on_progress(on_progress, 0, cap);
    while buf.len() < cap {
        let chunk = afc
            .file_read(h, 0x10000, scratch)
            .await
            .map_err(|e| JsValue::from_str(&e))?;
        if chunk.is_empty() {
            break;
        }
        let room = cap - buf.len();
        buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        invoke_on_progress(on_progress, buf.len(), cap);
        if chunk.len() < 0x10000 {
            break;
        }
    }
    afc.file_close(h, scratch)
        .await
        .map_err(|e| JsValue::from_str(&e))?;

    wasm_log::info(&format!(
        "[sysdiagnose] read {} ({} bytes)",
        device_path,
        buf.len()
    ));
    Ok(buf)
}

fn entries_to_js_array(entries: &[SysdiagnoseEntry]) -> Result<JsValue, JsValue> {
    let arr = js_sys::Array::new();
    for e in entries {
        let o = js_sys::Object::new();
        js_sys::Reflect::set(&o, &JsValue::from_str("path"), &JsValue::from_str(&e.path))
            .map_err(|_| JsValue::from_str("Reflect::set path"))?;
        js_sys::Reflect::set(&o, &JsValue::from_str("name"), &JsValue::from_str(&e.name))
            .map_err(|_| JsValue::from_str("Reflect::set name"))?;
        js_sys::Reflect::set(
            &o,
            &JsValue::from_str("sizeBytes"),
            &JsValue::from_f64(e.size_bytes as f64),
        )
        .map_err(|_| JsValue::from_str("Reflect::set sizeBytes"))?;
        arr.push(&o.into());
    }
    Ok(arr.into())
}

fn list_result_to_js(entries: &[SysdiagnoseEntry], debug: &str) -> Result<JsValue, JsValue> {
    let o = js_sys::Object::new();
    js_sys::Reflect::set(
        &o,
        &JsValue::from_str("entries"),
        &entries_to_js_array(entries)?,
    )
    .map_err(|_| JsValue::from_str("Reflect::set entries"))?;
    js_sys::Reflect::set(&o, &JsValue::from_str("debug"), &JsValue::from_str(debug))
        .map_err(|_| JsValue::from_str("Reflect::set debug"))?;
    js_sys::Reflect::set(
        &o,
        &JsValue::from_str("matchCount"),
        &JsValue::from_f64(entries.len() as f64),
    )
    .map_err(|_| JsValue::from_str("Reflect::set matchCount"))?;
    Ok(o.into())
}

async fn prepare_lockdown_keys(
    pipe: &mut WebUsbLockdownPipe<'_>,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    pair_record_plist_xml: &str,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
) -> Result<WasmHostKeys, JsValue> {
    let plist_text = pair_record_plist_xml.trim();
    if !plist_text.is_empty() {
        let (keys, ids) =
            pair_record_from_xml_plist(plist_text).map_err(|e| JsValue::from_str(&e))?;
        let _qt = pipe.query_type().await?;
        let sess = pipe.start_session_cleartext(&ids).await?;
        if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
            return Err(JsValue::from_str(
                "Sysdiagnose AFC requires EnableSessionSSL after StartSession.",
            ));
        }
        pipe.upgrade_lockdown_tls(&keys, client_auth, tls_sni).await?;
        return Ok(keys);
    }
    let ids = pairing_ids_from_mode(mode, host_id, system_buid)?;
    let keys = generate_host_keys().map_err(|e| JsValue::from_str(&e))?;
    let _qt = pipe.query_type().await?;
    let _ = pipe
        .pair_with_trust_wait(&keys, &ids, 120, 4)
        .await?;
    pipe.reopen_lockdown_tcp().await?;
    let _qt2 = pipe.query_type().await?;
    let sess = pipe.start_session_cleartext(&ids).await?;
    if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
        return Err(JsValue::from_str(
            "Sysdiagnose AFC requires EnableSessionSSL after StartSession.",
        ));
    }
    pipe.upgrade_lockdown_tls(&keys, client_auth, tls_sni).await?;
    Ok(keys)
}

#[allow(clippy::too_many_arguments)]
pub async fn sysdiagnose_list_flow(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    pair_record_plist_xml: &str,
    verbose: bool,
    tls_client_auth: &str,
    tls_sni: &str,
) -> Result<JsValue, JsValue> {
    let ca = crate::lockdown_tls_wasm::parse_tls_client_auth(tls_client_auth);
    let sni = crate::lockdown_tls_wasm::parse_tls_sni(tls_sni);

    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;
    let keys = prepare_lockdown_keys(
        &mut pipe,
        mode,
        host_id,
        system_buid,
        pair_record_plist_xml,
        ca,
        sni,
    )
    .await?;

    let mut afc = open_crash_afc_session(&mut pipe, &keys, ca, sni, verbose).await?;
    let mut scratch = vec![0u8; 65536];
    let mut entries: Vec<SysdiagnoseEntry> = Vec::new();
    let mut debug = String::from(
        "AFC (com.apple.crashreportcopymobile, root `.` = /var/mobile/Library/Logs/CrashReporter).\n\
         MATCH = finished sysdiagnose .tar.gz archive. `.ips` stackshots are crash reports, not the archive.\n\n",
    );
    let mut scan_count = 0usize;

    probe_sysdiagnose_directories(
        &mut afc.afc,
        &mut scratch,
        &mut entries,
        &mut debug,
        verbose,
    )
    .await?;

    push_debug(&mut debug, "\n--- full tree walk from `.` ---");
    afc_list_sysdiagnose_tree(
        &mut afc.afc,
        ".",
        "",
        &mut scratch,
        0,
        verbose,
        &mut entries,
        &mut debug,
        &mut scan_count,
    )
    .await?;

    entries.sort_by(|a, b| b.name.cmp(&a.name));
    push_debug(
        &mut debug,
        &format!(
            "\n--- summary: {scan_count} path(s) scanned, {} archive(s) matched ---",
            entries.len()
        ),
    );
    if entries.is_empty() {
        push_debug(
            &mut debug,
            "No finished archives on device AFC. Common causes:\n\
             • `DiagnosticLogs/sysdiagnose/` missing or empty (see direct probes above)\n\
             • sysdiagnose still running (IN_PROGRESS_* / *.tmp in that folder when it appears)\n\
             • you may be viewing **Mac-synced** copies in Finder, not files still on the iPhone\n\
             • trigger on device: Vol Up + Vol Down + Side (~0.7s), wait ~5–10 min, then list again",
        );
    }

    wasm_log::info(&format!(
        "[sysdiagnose] list done: {} match(es) from {scan_count} scanned path(s)",
        entries.len()
    ));
    list_result_to_js(&entries, &debug)
}

#[allow(clippy::too_many_arguments)]
pub async fn sysdiagnose_download_flow(
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
    let path = device_path.trim();
    if path.is_empty() {
        return Err(JsValue::from_str("device_path is required"));
    }
    if !is_valid_download_path(path) {
        return Err(JsValue::from_str(
            "device_path must be a finished sysdiagnose archive (.tar.gz / -tar.gz / .tgz / .tar) \
             under DiagnosticLogs/sysdiagnose",
        ));
    }

    let ca = crate::lockdown_tls_wasm::parse_tls_client_auth(tls_client_auth);
    let sni = crate::lockdown_tls_wasm::parse_tls_sni(tls_sni);

    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;
    let keys = prepare_lockdown_keys(
        &mut pipe,
        mode,
        host_id,
        system_buid,
        pair_record_plist_xml,
        ca,
        sni,
    )
    .await?;

    let mut afc = open_crash_afc_session(&mut pipe, &keys, ca, sni, verbose).await?;
    let mut scratch = vec![0u8; 65536];
    let data = afc_read_file_capped(
        &mut afc.afc,
        path,
        &mut scratch,
        SYSDIAGNOSE_MAX_BYTES,
        on_progress.as_ref(),
    )
    .await?;

    let o = js_sys::Object::new();
    let file_name = path.rsplit('/').next().unwrap_or(path);
    js_sys::Reflect::set(&o, &JsValue::from_str("name"), &JsValue::from_str(file_name))
        .map_err(|_| JsValue::from_str("Reflect::set name"))?;
    js_sys::Reflect::set(&o, &JsValue::from_str("path"), &JsValue::from_str(path))
        .map_err(|_| JsValue::from_str("Reflect::set path"))?;
    let u8 = js_sys::Uint8Array::new_with_length(data.len() as u32);
    u8.copy_from(&data);
    js_sys::Reflect::set(&o, &JsValue::from_str("data"), &u8.into())
        .map_err(|_| JsValue::from_str("Reflect::set data"))?;
    js_sys::Reflect::set(
        &o,
        &JsValue::from_str("byteLength"),
        &JsValue::from_f64(data.len() as f64),
    )
    .map_err(|_| JsValue::from_str("Reflect::set byteLength"))?;
    Ok(o.into())
}

/// Re-export crash-reports pull filtered to sysdiagnose (legacy helper).
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub async fn sysdiagnose_pull_all_flow(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    pair_record_plist_xml: &str,
    verbose: bool,
    tls_client_auth: &str,
    tls_sni: &str,
    keep: bool,
) -> Result<JsValue, JsValue> {
    crash_reports_flow(
        device,
        mode,
        host_id,
        system_buid,
        pair_record_plist_xml,
        verbose,
        tls_client_auth,
        tls_sni,
        keep,
        "sysdiagnose",
        false,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finished_archive_names() {
        assert!(is_finished_archive_name(
            "sysdiagnose_2026.04.17_12-00-00+0200_iPhone.tar.gz"
        ));
        assert!(is_finished_archive_name(
            "sysdiagnose_2026.04.17_12-00-00+0200_iPhone-tar.gz"
        ));
        assert!(!is_finished_archive_name(
            "IN_PROGRESS_sysdiagnose_2026.04.17-tar.gz"
        ));
        assert!(!is_finished_archive_name(
            "sysdiagnose_2026.04.17-diagnostic-summary.log"
        ));
    }

    #[test]
    fn match_paths() {
        assert!(is_sysdiagnose_match(
            "DiagnosticLogs/sysdiagnose/foo.tar.gz",
            "sysdiagnose_2026.tar.gz",
            "S_IFREG"
        ));
        assert!(is_sysdiagnose_match(
            "DiagnosticLogs/sysdiagnose/foo.tar.gz",
            "sysdiagnose_2026.tar.gz",
            "S_IFLNK"
        ));
        assert!(!is_sysdiagnose_match(
            "stacks-2026.ips",
            "stacks-2026.ips",
            "S_IFREG"
        ));
    }

    #[test]
    fn afc_status_names() {
        assert_eq!(afc_status_label(8), "OBJECT_NOT_FOUND");
        assert_eq!(afc_status_label(10), "PERM_DENIED");
    }
}
