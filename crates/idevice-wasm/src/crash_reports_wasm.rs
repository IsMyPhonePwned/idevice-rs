//! `com.apple.crashreportmover` + `com.apple.crashreportcopymobile` (AFC), mirroring `idevice::crash_reports`.

use std::time::Duration;

use async_recursion::async_recursion;
use gloo_timers::future::sleep;
use idevice_usb_core::TcpConn;
use rustls::ClientConnection;
use wasm_bindgen::prelude::*;
use web_sys::UsbDevice;

use crate::afc_wasm::{AfcSessionWasm, AFC_FOPEN_RDONLY};
use crate::lockdown_tls_wasm::{
    handshake_tls_mux_tcp_wasm, tls_read_plain_wasm, LockdownTlsClientAuth, LockdownTlsSni,
};
use crate::pair_record_plist::pair_record_from_xml_plist;
use crate::wasm_crypto::{generate_host_keys, WasmHostKeys};
use crate::wasm_log;
use crate::web_usb::prepare_apple_usb;
use crate::web_usb_mux_hub::WebUsbMuxHub;
use crate::web_usb_session::{pairing_ids_from_mode, WebUsbLockdownPipe};

const MOVER: &str = "com.apple.crashreportmover";
const COPY_MOBILE: &str = "com.apple.crashreportcopymobile";

const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_FILES: usize = 400;
const MAX_DEPTH: u32 = 12;
const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;

async fn wait_mover_ping(
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    tls: &mut ClientConnection,
    verbose: bool,
) -> Result<(), JsValue> {
    let mut acc: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 4096];
    let deadline = js_sys::Date::now() + 60_000.0;
    while js_sys::Date::now() < deadline {
        let n = tls_read_plain_wasm(tls, hub, tcp, &mut scratch, verbose)
            .await
            .map_err(|e| JsValue::from_str(&e))?;
        if n > 0 {
            acc.extend_from_slice(&scratch[..n]);
            if acc.windows(4).any(|w| w == b"ping") {
                wasm_log::info("[crash] crashreportmover → ping OK");
                return Ok(());
            }
            if acc.len() > 65_536 {
                break;
            }
        } else {
            sleep(Duration::from_millis(10)).await;
        }
    }
    Err(JsValue::from_str(
        "Timed out waiting for crashreportmover `ping` (unlock device; crash logs may be empty).",
    ))
}

#[async_recursion(?Send)]
async fn afc_collect_tree(
    afc: &mut AfcSessionWasm<'_>,
    dev_dir: String,
    rel_prefix: String,
    out: &mut Vec<(String, Vec<u8>)>,
    scratch: &mut [u8],
    keep: bool,
    filter: Option<&str>,
    remove_all: bool,
    depth: u32,
    files_left: &mut usize,
    total_left: &mut usize,
) -> Result<(), JsValue> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let list = afc
        .read_directory(&dev_dir, scratch)
        .await
        .map_err(|e| JsValue::from_str(&e))?;

    let dev_prefix = if dev_dir.ends_with('/') {
        dev_dir.clone()
    } else {
        format!("{}/", dev_dir)
    };

    for name in list {
        if *files_left == 0 || *total_left == 0 {
            return Ok(());
        }
        let source = format!("{dev_prefix}{name}");
        let rel_name = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };

        let info = match afc.get_file_info_dict(&source, scratch).await {
            Ok(d) => d,
            Err(e) => {
                wasm_log::warn(&format!("[crash] skip `{}`: {}", source, e));
                continue;
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

        if st_ifmt == "S_IFLNK" {
            if remove_all {
                let _ = afc.remove_path(&source, scratch).await;
            }
            continue;
        }

        if st_ifmt == "S_IFDIR" {
            afc_collect_tree(
                afc,
                source.clone(),
                rel_name.clone(),
                out,
                scratch,
                keep,
                filter,
                remove_all,
                depth + 1,
                files_left,
                total_left,
            )
            .await?;
            if !remove_all && !keep {
                let _ = afc.remove_path(&source, scratch).await;
            }
            continue;
        }

        if st_ifmt == "S_IFREG" {
            if let Some(f) = filter {
                if !source.contains(f) {
                    continue;
                }
            }
            if remove_all {
                let _ = afc.remove_path(&source, scratch).await;
                continue;
            }

            let cap = (st_size as usize).min(MAX_FILE_BYTES).min(*total_left);
            if cap == 0 {
                continue;
            }

            let h = afc
                .file_open(&source, AFC_FOPEN_RDONLY, scratch)
                .await
                .map_err(|e| JsValue::from_str(&e))?;

            let mut buf: Vec<u8> = Vec::new();
            while buf.len() < cap {
                let chunk = afc
                    .file_read(h, 0x1000, scratch)
                    .await
                    .map_err(|e| JsValue::from_str(&e))?;
                if chunk.is_empty() {
                    break;
                }
                let room = cap - buf.len();
                buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
                if chunk.len() < 0x1000 {
                    break;
                }
            }
            afc.file_close(h, scratch)
                .await
                .map_err(|e| JsValue::from_str(&e))?;

            *total_left = total_left.saturating_sub(buf.len());
            *files_left = files_left.saturating_sub(1);
            wasm_log::info(&format!(
                "[crash] copied {} ({} bytes, rel `{}`)",
                source,
                buf.len(),
                rel_name
            ));
            out.push((rel_name, buf));

            if !keep {
                let _ = afc.remove_path(&source, scratch).await;
            }
        }
    }
    Ok(())
}

pub async fn crash_reports_to_js_array<'a>(
    pipe: &'a mut WebUsbLockdownPipe<'a>,
    keys: &WasmHostKeys,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
    verbose: bool,
    keep: bool,
    filter: Option<&str>,
    remove_all: bool,
) -> Result<JsValue, JsValue> {
    let (port, ssl) = pipe.start_service(MOVER).await?;
    if !ssl {
        return Err(JsValue::from_str(
            "crashreportmover: StartService did not request SSL",
        ));
    }
    wasm_log::info("[crash] crashreportmover: secondary TCP + TLS…");
    let mut mover_tcp = pipe.hub.connect_tcp_additional(port).await?;
    let mut mover_tls = handshake_tls_mux_tcp_wasm(
        &mut pipe.hub,
        &mut mover_tcp,
        keys,
        client_auth,
        tls_sni,
        verbose,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))?;

    wait_mover_ping(&mut pipe.hub, &mut mover_tcp, &mut mover_tls, verbose).await?;

    let (port2, ssl2) = pipe.start_service(COPY_MOBILE).await?;
    if !ssl2 {
        return Err(JsValue::from_str(
            "crashreportcopymobile: StartService did not request SSL",
        ));
    }
    wasm_log::info("[crash] crashreportcopymobile: secondary TCP + TLS…");
    let mut afc_tcp = pipe.hub.connect_tcp_additional(port2).await?;
    let afc_tls = handshake_tls_mux_tcp_wasm(
        &mut pipe.hub,
        &mut afc_tcp,
        keys,
        client_auth,
        tls_sni,
        verbose,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))?;

    let mut afc = AfcSessionWasm::new(&mut pipe.hub, afc_tcp, afc_tls, verbose);
    let mut scratch = vec![0u8; 65536];
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut files_left = MAX_FILES;
    let mut total_left = MAX_TOTAL_BYTES;

    afc_collect_tree(
        &mut afc,
        ".".to_string(),
        String::new(),
        &mut out,
        &mut scratch,
        keep,
        filter,
        remove_all,
        0,
        &mut files_left,
        &mut total_left,
    )
    .await?;

    let arr = js_sys::Array::new();
    for (name, data) in out {
        let o = js_sys::Object::new();
        js_sys::Reflect::set(&o, &JsValue::from_str("name"), &JsValue::from_str(&name))
            .map_err(|_| JsValue::from_str("Reflect::set name"))?;
        let u8 = js_sys::Uint8Array::new_with_length(data.len() as u32);
        u8.copy_from(&data);
        js_sys::Reflect::set(&o, &JsValue::from_str("data"), &u8.into())
            .map_err(|_| JsValue::from_str("Reflect::set data"))?;
        arr.push(&o.into());
    }
    Ok(arr.into())
}

#[allow(clippy::too_many_arguments)]
pub async fn crash_reports_flow(
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
    let plist_text = pair_record_plist_xml.trim();
    let ca = crate::lockdown_tls_wasm::parse_tls_client_auth(tls_client_auth);
    let sni = crate::lockdown_tls_wasm::parse_tls_sni(tls_sni);

    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;

    let keys = if !plist_text.is_empty() {
        let (keys, ids) =
            pair_record_from_xml_plist(plist_text).map_err(|e| JsValue::from_str(&e))?;
        wasm_log::info("[crash] pair record plist — StartSession directly");
        let _qt = pipe.query_type().await?;
        let sess = pipe.start_session_cleartext(&ids).await?;
        if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
            return Err(JsValue::from_str(
                "Crash reports require EnableSessionSSL after StartSession — device did not request TLS.",
            ));
        }
        pipe.upgrade_lockdown_tls(&keys, ca, sni).await?;
        keys
    } else {
        let ids = pairing_ids_from_mode(mode, host_id, system_buid)?;
        let keys = generate_host_keys().map_err(|e| JsValue::from_str(&e))?;
        wasm_log::info("[crash] generated keys — Pair + Trust polling…");
        let _qt = pipe.query_type().await?;
        let _ = pipe
            .pair_with_trust_wait(&keys, &ids, 120, 4)
            .await?;
        pipe.reopen_lockdown_tcp().await?;
        let _qt2 = pipe.query_type().await?;
        let sess = pipe.start_session_cleartext(&ids).await?;
        if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
            return Err(JsValue::from_str(
                "Crash reports require EnableSessionSSL after StartSession — device did not request TLS.",
            ));
        }
        pipe.upgrade_lockdown_tls(&keys, ca, sni).await?;
        keys
    };

    let filter = if filter_substr.trim().is_empty() {
        None
    } else {
        Some(filter_substr.trim())
    };

    crash_reports_to_js_array(&mut pipe, &keys, ca, sni, verbose, keep, filter, remove_all).await
}
