//! `com.apple.mobile.screenshotr` over WebUSB mux + secondary TLS, mirroring
//! `idevice::screenshotr` and the libimobiledevice DeviceLink dance:
//!
//! ```text
//! HOST                             DEVICE
//!  ┊                              ←  DLMessageVersionExchange [400, 0]
//!  →  ["DLMessageVersionExchange", "DLVersionsOk", 400]
//!  ┊                              ←  DLMessageDeviceReady
//!  →  ["DLMessageProcessMessage", { ScreenShotRequest }]
//!  ┊                              ←  ["DLMessageProcessMessage", { ScreenShotReply, ScreenShotData }]
//!  →  ["DLMessageDisconnect", "___EmptyParameterString___"]
//! ```
//!
//! Each frame on the wire is `u32 BE length + binary plist (bplist00)`. The screenshotr
//! service is only published when a Developer Disk Image is mounted on the device.

use idevice_usb_core::screenshotr_proto::{
    build_disconnect, build_dl_versions_ok, build_screenshot_request, check_screenshotr_version,
    detect_image_extension, detect_image_mime, frame_plist_message, parse_dl_device_ready,
    parse_dl_version_exchange, parse_screenshot_reply, MAX_SCREENSHOTR_FRAME, SCREENSHOTR_SERVICE,
    SCREENSHOTR_VERSION_MAJOR,
};
use idevice_usb_core::TcpConn;
use rustls::ClientConnection;
use wasm_bindgen::prelude::*;
use web_sys::UsbDevice;

use crate::lockdown_tls_wasm::{
    handshake_tls_mux_tcp_wasm, parse_tls_client_auth, parse_tls_sni, tls_read_plain_wasm,
    tls_write_plain_and_flush_wasm,
};
use crate::pair_record_plist::pair_record_from_xml_plist;
use crate::wasm_crypto::{generate_host_keys, WasmHostKeys};
use crate::wasm_log;
use crate::web_usb::prepare_apple_usb;
use crate::web_usb_mux_hub::WebUsbMuxHub;
use crate::web_usb_session::{pairing_ids_from_mode, WebUsbLockdownPipe};

async fn send_framed_wasm(
    tls: &mut ClientConnection,
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    payload: &[u8],
    verbose: bool,
) -> Result<(), JsValue> {
    let frame = frame_plist_message(payload);
    tls_write_plain_and_flush_wasm(tls, hub, tcp, &frame, verbose)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    Ok(())
}

async fn recv_framed_wasm(
    tls: &mut ClientConnection,
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    verbose: bool,
) -> Result<Vec<u8>, JsValue> {
    let mut acc: Vec<u8> = Vec::new();
    let mut scratch = vec![0u8; 64 * 1024];
    while acc.len() < 4 {
        let n = tls_read_plain_wasm(tls, hub, tcp, &mut scratch, verbose)
            .await
            .map_err(|e| JsValue::from_str(&e))?;
        if n == 0 {
            return Err(JsValue::from_str(
                "screenshotr: TLS stream closed before length prefix",
            ));
        }
        acc.extend_from_slice(&scratch[..n]);
    }
    let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
    if len > MAX_SCREENSHOTR_FRAME {
        return Err(JsValue::from_str(&format!(
            "screenshotr: frame length {} exceeds max {} bytes",
            len, MAX_SCREENSHOTR_FRAME
        )));
    }
    while acc.len() < 4 + len {
        let n = tls_read_plain_wasm(tls, hub, tcp, &mut scratch, verbose)
            .await
            .map_err(|e| JsValue::from_str(&e))?;
        if n == 0 {
            return Err(JsValue::from_str(
                "screenshotr: TLS stream closed mid-frame",
            ));
        }
        acc.extend_from_slice(&scratch[..n]);
    }
    Ok(acc[4..4 + len].to_vec())
}

async fn screenshot_capture<'a>(
    pipe: &'a mut WebUsbLockdownPipe<'a>,
    keys: &WasmHostKeys,
    client_auth: crate::lockdown_tls_wasm::LockdownTlsClientAuth,
    tls_sni: crate::lockdown_tls_wasm::LockdownTlsSni,
    verbose: bool,
) -> Result<Vec<u8>, JsValue> {
    let (port, ssl) = pipe.start_service(SCREENSHOTR_SERVICE).await.map_err(|e| {
        let s = format!("{:?}", e);
        if s.contains("InvalidService") {
            JsValue::from_str(
                "screenshotr: lockdownd `InvalidService` — mount the Developer Disk Image \
                 first (Xcode device pane, or `pymobiledevice3 mounter auto-mount`).",
            )
        } else {
            e
        }
    })?;
    wasm_log::info(&format!(
        "[screenshot] StartService {SCREENSHOTR_SERVICE} → port {port} EnableServiceSSL={ssl}"
    ));
    if !ssl {
        return Err(JsValue::from_str(
            "screenshotr: unexpected EnableServiceSSL=false; modern iOS always requests TLS for screenshotr",
        ));
    }

    let mut svc_tcp = pipe.hub.connect_tcp_additional(port).await?;
    let mut svc_tls = handshake_tls_mux_tcp_wasm(
        &mut pipe.hub,
        &mut svc_tcp,
        keys,
        client_auth,
        tls_sni,
        verbose,
    )
    .await
    .map_err(|e| JsValue::from_str(&e))?;

    let init = recv_framed_wasm(&mut svc_tls, &mut pipe.hub, &mut svc_tcp, verbose).await?;
    let (dev_major, dev_minor) =
        parse_dl_version_exchange(&init).map_err(|e| JsValue::from_str(&e))?;
    wasm_log::info(&format!(
        "[screenshot] DLMessageVersionExchange — device {}.{}, host {}.0",
        dev_major, dev_minor, SCREENSHOTR_VERSION_MAJOR
    ));
    check_screenshotr_version(dev_major, dev_minor).map_err(|e| JsValue::from_str(&e))?;

    let ok = build_dl_versions_ok(SCREENSHOTR_VERSION_MAJOR).map_err(|e| JsValue::from_str(&e))?;
    send_framed_wasm(&mut svc_tls, &mut pipe.hub, &mut svc_tcp, &ok, verbose).await?;

    let ready = recv_framed_wasm(&mut svc_tls, &mut pipe.hub, &mut svc_tcp, verbose).await?;
    parse_dl_device_ready(&ready).map_err(|e| JsValue::from_str(&e))?;
    wasm_log::info("[screenshot] DLMessageDeviceReady — sending ScreenShotRequest");

    let req = build_screenshot_request().map_err(|e| JsValue::from_str(&e))?;
    send_framed_wasm(&mut svc_tls, &mut pipe.hub, &mut svc_tcp, &req, verbose).await?;

    let reply = recv_framed_wasm(&mut svc_tls, &mut pipe.hub, &mut svc_tcp, verbose).await?;
    let img = parse_screenshot_reply(&reply).map_err(|e| JsValue::from_str(&e))?;
    wasm_log::info(&format!(
        "[screenshot] ScreenShotReply — {} bytes ({})",
        img.len(),
        detect_image_extension(&img)
    ));

    if let Ok(bye) = build_disconnect() {
        let _ = send_framed_wasm(&mut svc_tls, &mut pipe.hub, &mut svc_tcp, &bye, verbose).await;
    }

    Ok(img)
}

/// `QueryType` → optional `Pair` (generated keys) → `StartSession` → TLS upgrade →
/// `StartService(com.apple.mobile.screenshotr)` → secondary TLS → DeviceLink handshake →
/// `ScreenShotRequest` → `ScreenShotReply.ScreenShotData`.
///
/// Returns `{ data: Uint8Array, extension: "png" | "tiff" | "dat", mime, byteLength }`. The
/// caller decides whether to render it (`<img src="data:image/...">`), download it, or both.
///
/// **Requires a mounted Developer Disk Image**; otherwise lockdownd answers `InvalidService`
/// and we surface a friendly error.
#[wasm_bindgen(js_name = lockdownScreenshot)]
#[allow(clippy::too_many_arguments)]
pub async fn lockdown_screenshot(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    pair_record_plist_xml: &str,
    verbose: bool,
    tls_client_auth: &str,
    tls_sni: &str,
) -> Result<JsValue, JsValue> {
    let plist_text = pair_record_plist_xml.trim();
    let ca = parse_tls_client_auth(tls_client_auth);
    let sni = parse_tls_sni(tls_sni);

    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;

    let keys = if !plist_text.is_empty() {
        let (keys, ids) =
            pair_record_from_xml_plist(plist_text).map_err(|e| JsValue::from_str(&e))?;
        wasm_log::info("[screenshot] pair record plist — StartSession directly");
        let _qt = pipe.query_type().await?;
        let sess = pipe.start_session_cleartext(&ids).await?;
        if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
            return Err(JsValue::from_str(
                "screenshot: lockdown StartSession did not request TLS, can't reach screenshotr",
            ));
        }
        pipe.upgrade_lockdown_tls(&keys, ca, sni).await?;
        keys
    } else {
        let ids = pairing_ids_from_mode(mode, host_id, system_buid)?;
        let keys = generate_host_keys().map_err(|e| JsValue::from_str(&e))?;
        wasm_log::info("[screenshot] generated keys — Pair + Trust polling…");
        let _qt = pipe.query_type().await?;
        let _ = pipe.pair_with_trust_wait(&keys, &ids, 120, 4).await?;
        pipe.reopen_lockdown_tcp().await?;
        let _qt2 = pipe.query_type().await?;
        let sess = pipe.start_session_cleartext(&ids).await?;
        if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
            return Err(JsValue::from_str(
                "screenshot: lockdown StartSession did not request TLS, can't reach screenshotr",
            ));
        }
        pipe.upgrade_lockdown_tls(&keys, ca, sni).await?;
        keys
    };

    let img = screenshot_capture(&mut pipe, &keys, ca, sni, verbose).await?;

    let ext = detect_image_extension(&img);
    let mime = detect_image_mime(&img);
    let u8arr = js_sys::Uint8Array::new_with_length(img.len() as u32);
    u8arr.copy_from(&img);
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from_str("data"), &u8arr.into())
        .map_err(|_| JsValue::from_str("Reflect::set data"))?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("extension"), &JsValue::from_str(ext))
        .map_err(|_| JsValue::from_str("Reflect::set extension"))?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("mime"), &JsValue::from_str(mime))
        .map_err(|_| JsValue::from_str("Reflect::set mime"))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("byteLength"),
        &JsValue::from_f64(img.len() as f64),
    )
    .map_err(|_| JsValue::from_str("Reflect::set byteLength"))?;
    Ok(obj.into())
}
