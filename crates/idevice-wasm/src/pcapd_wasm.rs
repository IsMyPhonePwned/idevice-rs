//! `com.apple.pcapd` over WebUSB mux + secondary TLS, mirroring `idevice::pcapd`.
//!
//! Browser flow:
//!
//! ```text
//! WebUSB ──→ WebUsbLockdownPipe (lockdown TLS) ──→ StartService("com.apple.pcapd")
//!                                                          │
//!                                                          ▼
//!                                            secondary mux TCP + TLS handshake
//!                                                          │
//!                                                          ▼
//!  for every framed plist: parse_pcapd_message → PcapdRecord → libpcap record
//! ```
//!
//! The page receives:
//! - a JS `on_packet({ index, interface, type, direction, pid, comm, bytes })` callback per packet
//!   (returning `false` stops the loop); and
//! - a final `{ bytes, packets, durationMs, stoppedReason, ssl, data: Uint8Array }` object whose
//!   `data` is the **complete `.pcap` file** the page can offer for download — same byte stream a
//!   `tcpdump -w` from the device would produce.

use std::time::Duration;

use gloo_timers::future::sleep;
use idevice_usb_core::pcapd_proto::{
    build_pcap_global_header, build_pcap_record_header, build_pcap_record_payload,
    interface_type_label, parse_pcapd_message, protocol_family_label, PcapdRecord,
    LINKTYPE_ETHERNET, MAX_PCAPD_FRAME, PCAPD_SERVICE, PCAP_DEFAULT_SNAPLEN,
};
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

/// Reasons the relay loop returned. Reflected back to JS as `stoppedReason`.
#[derive(Copy, Clone, Debug)]
enum StopReason {
    UserStop,
    MaxPackets,
    MaxBytes,
    MaxDuration,
    StreamClosed,
}

impl StopReason {
    fn as_str(self) -> &'static str {
        match self {
            StopReason::UserStop => "user-stop",
            StopReason::MaxPackets => "max-packets",
            StopReason::MaxBytes => "max-bytes",
            StopReason::MaxDuration => "max-duration",
            StopReason::StreamClosed => "stream-closed",
        }
    }
}

/// Build the per-packet JS object passed to `on_packet(...)`. Mirrors the native [`PcapEvent`].
fn make_event(rec: &PcapdRecord, packet_index: u64, frame_len: usize) -> Result<JsValue, JsValue> {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("index"),
        &JsValue::from_f64(packet_index as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("interface"),
        &JsValue::from_str(&rec.interface_name),
    )?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("interfaceType"),
        &JsValue::from_str(&interface_type_label(rec.interface_type)),
    )?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("direction"),
        &JsValue::from_str(if rec.io == 0 { "in" } else { "out" }),
    )?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("protocolFamily"),
        &JsValue::from_str(protocol_family_label(rec.protocol_family)),
    )?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("pid"), &JsValue::from_f64(rec.pid as f64))?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("comm"), &JsValue::from_str(&rec.comm))?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("ecomm"), &JsValue::from_str(&rec.ecomm))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("bytes"),
        &JsValue::from_f64(frame_len as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("seconds"),
        &JsValue::from_f64(rec.seconds as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("microseconds"),
        &JsValue::from_f64(rec.microseconds as f64),
    )?;
    Ok(obj.into())
}

/// Apply the same pid / comm / interface filters the CLI exposes — case-sensitive equality, like
/// pymobiledevice3 (we don't try to be clever with substring matches).
fn record_matches_filters(rec: &PcapdRecord, process: &str, interface: &str) -> bool {
    if !process.is_empty() {
        let pid_str = rec.pid.to_string();
        if process != pid_str && process != rec.comm && process != rec.ecomm {
            return false;
        }
    }
    if !interface.is_empty() && interface != rec.interface_name {
        return false;
    }
    true
}

fn record_timestamp(rec: &PcapdRecord) -> (u32, u32) {
    if rec.seconds != 0 {
        return (rec.seconds, rec.microseconds);
    }
    let now_ms = js_sys::Date::now();
    let secs = (now_ms / 1000.0) as u32;
    let us = ((now_ms - (secs as f64) * 1000.0) * 1000.0) as u32;
    (secs, us)
}

/// Pull every complete `<u32 BE length><bplist>` frame out of `buf`, write the libpcap record into
/// `pcap` and dispatch through `on_packet`. Returns `Some(StopReason)` when the caller asked to
/// stop, `None` to keep reading.
#[allow(clippy::too_many_arguments)]
fn drain_frames(
    buf: &mut Vec<u8>,
    pcap: &mut Vec<u8>,
    on_packet: &js_sys::Function,
    process: &str,
    interface: &str,
    packets_written: &mut u64,
    max_packets: u64,
    max_bytes: u64,
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
        if len > MAX_PCAPD_FRAME {
            return Err(format!(
                "pcap frame length {} exceeds max {} bytes",
                len, MAX_PCAPD_FRAME
            ));
        }
        if buf.len() < 4 + len {
            return Ok(None);
        }
        let plist_bytes: Vec<u8> = buf.drain(..4 + len).collect();
        let payload = &plist_bytes[4..4 + len];
        let rec = match parse_pcapd_message(payload) {
            Ok(r) => r,
            Err(e) => {
                wasm_log::warn(&format!("[pcap] dropping malformed frame: {}", e));
                continue;
            }
        };
        if !record_matches_filters(&rec, process, interface) {
            continue;
        }
        let frame = build_pcap_record_payload(&rec);
        let (sec, usec) = record_timestamp(&rec);
        let header = build_pcap_record_header(sec, usec, frame.len() as u32);
        pcap.extend_from_slice(&header);
        pcap.extend_from_slice(&frame);
        *packets_written = packets_written.saturating_add(1);

        let event = make_event(&rec, *packets_written, frame.len()).map_err(|_| {
            "pcap: failed to allocate JS event object — likely OOM".to_string()
        })?;
        let cb_result = on_packet
            .call1(&JsValue::NULL, &event)
            .map_err(|_| "pcap: on_packet threw".to_string())?;
        if matches!(cb_result.as_bool(), Some(false)) {
            return Ok(Some(StopReason::UserStop));
        }
        if max_packets != 0 && *packets_written >= max_packets {
            return Ok(Some(StopReason::MaxPackets));
        }
        if max_bytes != 0 && (pcap.len() as u64) >= max_bytes {
            return Ok(Some(StopReason::MaxBytes));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_pcap_tls(
    tls: &mut ClientConnection,
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    verbose: bool,
    on_packet: &js_sys::Function,
    pcap: &mut Vec<u8>,
    process: &str,
    interface: &str,
    max_packets: u64,
    max_bytes: u64,
    deadline_ms: Option<f64>,
) -> Result<(StopReason, u64), String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut scratch = vec![0u8; 64 * 1024];
    let mut packets_written = 0u64;
    loop {
        if let Some(deadline) = deadline_ms {
            if js_sys::Date::now() >= deadline {
                return Ok((StopReason::MaxDuration, packets_written));
            }
        }
        let n = tls_read_plain_wasm(tls, hub, tcp, &mut scratch, verbose).await?;
        if n == 0 {
            sleep(Duration::from_millis(20)).await;
            continue;
        }
        buf.extend_from_slice(&scratch[..n]);
        if let Some(reason) = drain_frames(
            &mut buf,
            pcap,
            on_packet,
            process,
            interface,
            &mut packets_written,
            max_packets,
            max_bytes,
        )? {
            return Ok((reason, packets_written));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_pcap_cleartext(
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    on_packet: &js_sys::Function,
    pcap: &mut Vec<u8>,
    process: &str,
    interface: &str,
    max_packets: u64,
    max_bytes: u64,
    deadline_ms: Option<f64>,
) -> Result<(StopReason, u64), String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut packets_written = 0u64;
    loop {
        if let Some(deadline) = deadline_ms {
            if js_sys::Date::now() >= deadline {
                return Ok((StopReason::MaxDuration, packets_written));
            }
        }
        let chunk = hub
            .recv_tcp_payload_for(tcp)
            .await
            .map_err(|e| format!("{e:?}"))?;
        if chunk.is_empty() {
            return Ok((StopReason::StreamClosed, packets_written));
        }
        buf.extend_from_slice(&chunk);
        if let Some(reason) = drain_frames(
            &mut buf,
            pcap,
            on_packet,
            process,
            interface,
            &mut packets_written,
            max_packets,
            max_bytes,
        )? {
            return Ok((reason, packets_written));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn pcap_run<'a>(
    pipe: &'a mut WebUsbLockdownPipe<'a>,
    keys: &WasmHostKeys,
    client_auth: crate::lockdown_tls_wasm::LockdownTlsClientAuth,
    tls_sni: crate::lockdown_tls_wasm::LockdownTlsSni,
    verbose: bool,
    on_packet: js_sys::Function,
    process: String,
    interface: String,
    max_packets: u64,
    max_bytes: u64,
    max_duration_ms: f64,
) -> Result<JsValue, JsValue> {
    let (port, ssl) = pipe.start_service(PCAPD_SERVICE).await?;
    wasm_log::info(&format!(
        "[pcap] StartService {PCAPD_SERVICE} → port {port} EnableServiceSSL={ssl}"
    ));

    let mut svc_tcp = pipe.hub.connect_tcp_additional(port).await?;

    let mut pcap: Vec<u8> = build_pcap_global_header(PCAP_DEFAULT_SNAPLEN, LINKTYPE_ETHERNET);

    let started_ms = js_sys::Date::now();
    let deadline = if max_duration_ms > 0.0 {
        Some(started_ms + max_duration_ms)
    } else {
        None
    };

    let (stop_reason, packets) = if ssl {
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
        relay_pcap_tls(
            &mut svc_tls,
            &mut pipe.hub,
            &mut svc_tcp,
            verbose,
            &on_packet,
            &mut pcap,
            &process,
            &interface,
            max_packets,
            max_bytes,
            deadline,
        )
        .await
        .map_err(|e| JsValue::from_str(&e))?
    } else {
        relay_pcap_cleartext(
            &mut pipe.hub,
            &mut svc_tcp,
            &on_packet,
            &mut pcap,
            &process,
            &interface,
            max_packets,
            max_bytes,
            deadline,
        )
        .await
        .map_err(|e| JsValue::from_str(&e))?
    };

    let elapsed_ms = js_sys::Date::now() - started_ms;
    wasm_log::info(&format!(
        "[pcap] stopped — reason={} packets={} bytes={} duration={}ms",
        stop_reason.as_str(),
        packets,
        pcap.len(),
        elapsed_ms as i64
    ));

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from_str("packets"), &JsValue::from_f64(packets as f64))
        .map_err(|_| JsValue::from_str("Reflect::set packets"))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("bytes"),
        &JsValue::from_f64(pcap.len() as f64),
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
    let total_u8 = js_sys::Uint8Array::new_with_length(pcap.len() as u32);
    total_u8.copy_from(&pcap);
    js_sys::Reflect::set(&obj, &JsValue::from_str("data"), &total_u8.into())
        .map_err(|_| JsValue::from_str("Reflect::set data"))?;
    Ok(obj.into())
}

/// `QueryType` → optional `Pair` (generated keys) → `StartSession` → TLS upgrade →
/// `StartService(com.apple.pcapd)` → secondary mux TCP + TLS → libpcap stream.
///
/// **Stops** when:
/// - `on_packet` returns `false` → `stoppedReason = "user-stop"`
/// - `packets >= max_packets` (when `max_packets > 0`) → `"max-packets"`
/// - `pcap_bytes >= max_bytes` (when `max_bytes > 0`) → `"max-bytes"`
/// - `max_duration_ms` elapsed → `"max-duration"`
/// - the device closes the relay (cleartext path only) → `"stream-closed"`
///
/// `data` in the resulting object is a **complete libpcap file** (`LINKTYPE_ETHERNET`, snaplen
/// 65535). The page can blob+download it directly into Wireshark / `tcpdump -r`.
#[wasm_bindgen(js_name = lockdownPcap)]
#[allow(clippy::too_many_arguments)]
pub async fn lockdown_pcap(
    device: UsbDevice,
    mode: &str,
    host_id: &str,
    system_buid: &str,
    pair_record_plist_xml: &str,
    verbose: bool,
    tls_client_auth: &str,
    tls_sni: &str,
    on_packet: js_sys::Function,
    process_filter: &str,
    interface_filter: &str,
    max_packets: f64,
    max_bytes: f64,
    max_duration_ms: f64,
) -> Result<JsValue, JsValue> {
    let plist_text = pair_record_plist_xml.trim();
    let ca = parse_tls_client_auth(tls_client_auth);
    let sni = parse_tls_sni(tls_sni);
    let max_packets_u = if max_packets > 0.0 {
        max_packets as u64
    } else {
        0
    };
    let max_bytes_u = if max_bytes > 0.0 { max_bytes as u64 } else { 0 };

    let eps = prepare_apple_usb(&device).await?;
    let mut pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;

    let keys = if !plist_text.is_empty() {
        let (keys, ids) =
            pair_record_from_xml_plist(plist_text).map_err(|e| JsValue::from_str(&e))?;
        wasm_log::info("[pcap] pair record plist — StartSession directly");
        let _qt = pipe.query_type().await?;
        let sess = pipe.start_session_cleartext(&ids).await?;
        if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
            return Err(JsValue::from_str(
                "pcap: lockdown StartSession did not request TLS, can't reach pcapd",
            ));
        }
        pipe.upgrade_lockdown_tls(&keys, ca, sni).await?;
        keys
    } else {
        let ids = pairing_ids_from_mode(mode, host_id, system_buid)?;
        let keys = generate_host_keys().map_err(|e| JsValue::from_str(&e))?;
        wasm_log::info("[pcap] generated keys — Pair + Trust polling…");
        let _qt = pipe.query_type().await?;
        let _ = pipe.pair_with_trust_wait(&keys, &ids, 120, 4).await?;
        pipe.reopen_lockdown_tcp().await?;
        let _qt2 = pipe.query_type().await?;
        let sess = pipe.start_session_cleartext(&ids).await?;
        if !idevice_usb_core::lockdown_proto::start_session_enable_ssl(&sess) {
            return Err(JsValue::from_str(
                "pcap: lockdown StartSession did not request TLS, can't reach pcapd",
            ));
        }
        pipe.upgrade_lockdown_tls(&keys, ca, sni).await?;
        keys
    };

    pcap_run(
        &mut pipe,
        &keys,
        ca,
        sni,
        verbose,
        on_packet,
        process_filter.to_string(),
        interface_filter.to_string(),
        max_packets_u,
        max_bytes_u,
        max_duration_ms,
    )
    .await
}
