//! `com.apple.syslog_relay` — stream device syslog over a secondary mux pseudo-TCP + TLS,
//! mirroring `idevice::syslog_relay`. Driven from JS with two callbacks:
//!
//! - `on_chunk(text: string, totalBytes: number) => boolean | void` — invoked whenever new
//!   bytes are decoded; return **`false`** to ask the relay to stop after the current chunk.
//! - All bytes are also accumulated in a `Vec<u8>` so the page can save the full capture.
//!
//! Caveats inherited from WebUSB `transferIn`:
//! - Reads block until the device sends data. If the phone is idle, a `stop` request only
//!   takes effect once the next syslog line arrives. Generate activity (lock/unlock, open
//!   an app) to flush the pipe.
//! - `EnableServiceSSL=false` (legacy) framing is **`u32` big-endian length + payload**;
//!   `EnableServiceSSL=true` (current iOS) is raw decrypted text.

use std::time::Duration;

use gloo_timers::future::sleep;
use idevice_usb_core::TcpConn;
use rustls::ClientConnection;
use wasm_bindgen::prelude::*;
use web_sys::UsbDevice;

use crate::lockdown_tls_wasm::{
    handshake_tls_mux_tcp_wasm, parse_tls_client_auth, parse_tls_sni, tls_read_plain_wasm,
};
use crate::pair_record_plist::pair_record_from_xml_plist;
use crate::wasm_crypto::{generate_host_keys, WasmHostKeys};
use crate::wasm_log;
use crate::web_usb::prepare_apple_usb;
use crate::web_usb_mux_hub::WebUsbMuxHub;
use crate::web_usb_session::{pairing_ids_from_mode, WebUsbLockdownPipe};

const SYSLOG_RELAY_SERVICE: &str = "com.apple.syslog_relay";
/// Reject syslog frames larger than this (bytes after the u32 length, cleartext relay only).
const MAX_SYSLOG_FRAME: usize = 16 * 1024 * 1024;

/// Reasons we can stop the relay loop. Reported back to JS as the `stoppedReason` field.
#[derive(Copy, Clone, Debug)]
enum StopReason {
    UserStop,
    MaxBytes,
    MaxDuration,
    StreamClosed,
}

impl StopReason {
    fn as_str(self) -> &'static str {
        match self {
            StopReason::UserStop => "user-stop",
            StopReason::MaxBytes => "max-bytes",
            StopReason::MaxDuration => "max-duration",
            StopReason::StreamClosed => "stream-closed",
        }
    }
}

/// Invoke the JS `on_chunk(text, totalBytes)` callback. Returns whether the caller wants
/// the loop to keep going: `true` (or `undefined` / non-`false`) → continue, `false` → stop.
fn invoke_on_chunk(on_chunk: &js_sys::Function, chunk: &[u8], total_bytes: usize) -> bool {
    let text = String::from_utf8_lossy(chunk).into_owned();
    let r = on_chunk.call2(
        &JsValue::NULL,
        &JsValue::from_str(&text),
        &JsValue::from_f64(total_bytes as f64),
    );
    match r {
        Ok(v) => !matches!(v.as_bool(), Some(false)),
        Err(_) => false, // exception in JS → behave like "stop"
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_raw_tls(
    tls: &mut ClientConnection,
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    verbose: bool,
    on_chunk: &js_sys::Function,
    accumulated: &mut Vec<u8>,
    max_bytes: usize,
    deadline_ms: Option<f64>,
) -> Result<StopReason, String> {
    let mut scratch = vec![0u8; 64 * 1024];
    loop {
        if let Some(deadline) = deadline_ms {
            if js_sys::Date::now() >= deadline {
                return Ok(StopReason::MaxDuration);
            }
        }
        let n = tls_read_plain_wasm(tls, hub, tcp, &mut scratch, verbose).await?;
        if n == 0 {
            sleep(Duration::from_millis(20)).await;
            continue;
        }
        accumulated.extend_from_slice(&scratch[..n]);
        let total = accumulated.len();
        let keep_going = invoke_on_chunk(on_chunk, &scratch[..n], total);
        if !keep_going {
            return Ok(StopReason::UserStop);
        }
        if max_bytes != 0 && total >= max_bytes {
            return Ok(StopReason::MaxBytes);
        }
    }
}

/// Drain any whole `[u32 BE length][payload]` frames from `buf`, append them to `accumulated`
/// and dispatch through `on_chunk`. Returns `Some(StopReason)` when the caller asked to stop.
fn drain_framed_cleartext(
    buf: &mut Vec<u8>,
    accumulated: &mut Vec<u8>,
    on_chunk: &js_sys::Function,
    max_bytes: usize,
) -> Result<Option<StopReason>, String> {
    loop {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len == 0 {
            buf.drain(..4);
            continue;
        }
        if len > MAX_SYSLOG_FRAME {
            return Err(format!(
                "syslog frame length {} exceeds max {} bytes",
                len, MAX_SYSLOG_FRAME
            ));
        }
        if buf.len() < 4 + len {
            return Ok(None);
        }
        let payload = &buf[4..4 + len];
        accumulated.extend_from_slice(payload);
        let total = accumulated.len();
        let keep = invoke_on_chunk(on_chunk, payload, total);
        let owned_len = 4 + len;
        buf.drain(..owned_len);
        if !keep {
            return Ok(Some(StopReason::UserStop));
        }
        if max_bytes != 0 && total >= max_bytes {
            return Ok(Some(StopReason::MaxBytes));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_framed_cleartext(
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    on_chunk: &js_sys::Function,
    accumulated: &mut Vec<u8>,
    max_bytes: usize,
    deadline_ms: Option<f64>,
) -> Result<StopReason, String> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if let Some(deadline) = deadline_ms {
            if js_sys::Date::now() >= deadline {
                return Ok(StopReason::MaxDuration);
            }
        }
        let chunk = hub
            .recv_tcp_payload_for(tcp)
            .await
            .map_err(|e| format!("{e:?}"))?;
        if chunk.is_empty() {
            return Ok(StopReason::StreamClosed);
        }
        buf.extend_from_slice(&chunk);
        if let Some(reason) = drain_framed_cleartext(&mut buf, accumulated, on_chunk, max_bytes)? {
            return Ok(reason);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn syslog_run<'a>(
    pipe: &'a mut WebUsbLockdownPipe<'a>,
    keys: &WasmHostKeys,
    client_auth: crate::lockdown_tls_wasm::LockdownTlsClientAuth,
    tls_sni: crate::lockdown_tls_wasm::LockdownTlsSni,
    verbose: bool,
    on_chunk: js_sys::Function,
    max_bytes: usize,
    max_duration_ms: f64,
) -> Result<JsValue, JsValue> {
    let (port, ssl) = pipe.start_service(SYSLOG_RELAY_SERVICE).await?;
    wasm_log::info(&format!(
        "[syslog] StartService {SYSLOG_RELAY_SERVICE} → port {port} EnableServiceSSL={ssl}"
    ));

    let mut sys_tcp = pipe.hub.connect_tcp_additional(port).await?;

    let started_ms = js_sys::Date::now();
    let deadline = if max_duration_ms > 0.0 {
        Some(started_ms + max_duration_ms)
    } else {
        None
    };

    let mut accumulated: Vec<u8> = Vec::new();
    let stop_reason = if ssl {
        wasm_log::info("[syslog] secondary TCP + TLS — streaming raw decrypted text");
        let mut sys_tls = handshake_tls_mux_tcp_wasm(
            &mut pipe.hub,
            &mut sys_tcp,
            keys,
            client_auth,
            tls_sni,
            verbose,
        )
        .await
        .map_err(|e| JsValue::from_str(&e))?;
        relay_raw_tls(
            &mut sys_tls,
            &mut pipe.hub,
            &mut sys_tcp,
            verbose,
            &on_chunk,
            &mut accumulated,
            max_bytes,
            deadline,
        )
        .await
        .map_err(|e| JsValue::from_str(&e))?
    } else {
        wasm_log::info("[syslog] secondary TCP cleartext — u32 BE length-prefixed framing");
        relay_framed_cleartext(
            &mut pipe.hub,
            &mut sys_tcp,
            &on_chunk,
            &mut accumulated,
            max_bytes,
            deadline,
        )
        .await
        .map_err(|e| JsValue::from_str(&e))?
    };

    let elapsed_ms = js_sys::Date::now() - started_ms;
    wasm_log::info(&format!(
        "[syslog] stopped — reason={} bytes={} duration={}ms",
        stop_reason.as_str(),
        accumulated.len(),
        elapsed_ms as i64
    ));

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("bytes"),
        &JsValue::from_f64(accumulated.len() as f64),
    )
    .map_err(|_| JsValue::from_str("Reflect::set bytes"))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("durationMs"),
        &JsValue::from_f64(elapsed_ms),
    )
    .map_err(|_| JsValue::from_str("Reflect::set durationMs"))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("stoppedReason"),
        &JsValue::from_str(stop_reason.as_str()),
    )
    .map_err(|_| JsValue::from_str("Reflect::set stoppedReason"))?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("ssl"), &JsValue::from_bool(ssl))
        .map_err(|_| JsValue::from_str("Reflect::set ssl"))?;
    let total_u8 = js_sys::Uint8Array::new_with_length(accumulated.len() as u32);
    total_u8.copy_from(&accumulated);
    js_sys::Reflect::set(&obj, &JsValue::from_str("data"), &total_u8.into())
        .map_err(|_| JsValue::from_str("Reflect::set data"))?;
    Ok(obj.into())
}

/// `QueryType` → optional `Pair` (generated keys) → `StartSession` → TLS upgrade →
/// `StartService(com.apple.syslog_relay)` → secondary mux TCP + (TLS or cleartext) → stream
/// decoded chunks to `on_chunk(text, totalBytes)`.
///
/// **Stops** when:
/// - `on_chunk` returns `false` → `stoppedReason = "user-stop"`
/// - `accumulated.len() >= max_bytes` (when `max_bytes > 0`) → `"max-bytes"`
/// - `max_duration_ms` elapsed → `"max-duration"`
/// - the device closes the relay (cleartext path only) → `"stream-closed"`
///
/// Returns `{ bytes, durationMs, stoppedReason, ssl, data: Uint8Array }`. The full byte capture
/// is in `data` so the page can offer **Save** without re-decoding strings.
#[wasm_bindgen(js_name = lockdownSyslog)]
#[allow(clippy::too_many_arguments)]
pub async fn lockdown_syslog(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    pair_record_plist_xml: &str,
    verbose: bool,
    tls_client_auth: &str,
    tls_sni: &str,
    on_chunk: js_sys::Function,
    max_bytes: f64,
    max_duration_ms: f64,
) -> Result<JsValue, JsValue> {
    let plist_text = pair_record_plist_xml.trim();
    let ca = parse_tls_client_auth(tls_client_auth);
    let sni = parse_tls_sni(tls_sni);
    let max_bytes_u = if max_bytes > 0.0 {
        max_bytes as usize
    } else {
        0
    };

    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;

    let keys = if !plist_text.is_empty() {
        let (keys, ids) =
            pair_record_from_xml_plist(plist_text).map_err(|e| JsValue::from_str(&e))?;
        wasm_log::info("[syslog] pair record plist — StartSession directly");
        let _qt = pipe.query_type().await?;
        let sess = pipe.start_session_cleartext(&ids).await?;
        if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
            return Err(JsValue::from_str(
                "Syslog relay needs EnableSessionSSL after StartSession — device did not request TLS.",
            ));
        }
        pipe.upgrade_lockdown_tls(&keys, ca, sni).await?;
        keys
    } else {
        let ids = pairing_ids_from_mode(mode, host_id, system_buid)?;
        let keys = generate_host_keys().map_err(|e| JsValue::from_str(&e))?;
        wasm_log::info("[syslog] generated keys — Pair + Trust polling…");
        let _qt = pipe.query_type().await?;
        let _ = pipe.pair_with_trust_wait(&keys, &ids, 120, 4).await?;
        pipe.reopen_lockdown_tcp().await?;
        let _qt2 = pipe.query_type().await?;
        let sess = pipe.start_session_cleartext(&ids).await?;
        if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
            return Err(JsValue::from_str(
                "Syslog relay needs EnableSessionSSL after StartSession — device did not request TLS.",
            ));
        }
        pipe.upgrade_lockdown_tls(&keys, ca, sni).await?;
        keys
    };

    syslog_run(
        &mut pipe,
        &keys,
        ca,
        sni,
        verbose,
        on_chunk,
        max_bytes_u,
        max_duration_ms,
    )
    .await
}
