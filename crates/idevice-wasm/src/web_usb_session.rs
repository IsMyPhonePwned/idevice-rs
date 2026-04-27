//! Length-prefixed lockdown plists over **WebUSB** mux + pseudo-TCP, with optional **rustls**.
//! Uses [`crate::web_usb_mux_hub::WebUsbMuxHub`] so secondary pseudo-TCP (e.g. AFC) shares one USB bulk pair.

use std::time::Duration;

use gloo_timers::future::sleep;
use idevice_usb_core::lockdown_proto::{
    get_value_xml, pair_plist, parse_start_service_response, start_service_xml, start_session_xml,
    PairingIds, GET_DEVICE_PUBLIC_KEY_XML, LOCKDOWND_PORT, QUERY_TYPE_XML,
};
use idevice_usb_core::TcpConn;
use rustls::ClientConnection;
use wasm_bindgen::prelude::*;
use web_sys::UsbDevice;

use crate::lockdown_tls_wasm::{
    handshake_tls_mux_tcp_wasm, tls_read_plain_wasm, tls_write_plain_and_flush_wasm,
    LockdownTlsClientAuth, LockdownTlsSni,
};
use crate::wasm_crypto::{build_device_certificate, WasmHostKeys};
use crate::wasm_log;
use crate::web_usb::AppleEndpoints;
use crate::web_usb_mux_hub::WebUsbMuxHub;

fn log_verbose(verbose: bool, msg: &str) {
    wasm_log::debug_verbose(verbose, msg);
}

/// Active lockdown TLS session + receive reassembly buffer for length-prefixed plists.
pub(crate) struct LockdownTlsState {
    pub conn: ClientConnection,
    pub rx_acc: Vec<u8>,
}

pub struct WebUsbLockdownPipe<'a> {
    pub(crate) hub: WebUsbMuxHub<'a>,
    pub(crate) conn: TcpConn,
    verbose: bool,
    tls: Option<LockdownTlsState>,
}

impl<'a> WebUsbLockdownPipe<'a> {
    pub async fn connect(
        dev: &'a UsbDevice,
        eps: AppleEndpoints,
        verbose: bool,
    ) -> Result<Self, JsValue> {
        let mut hub = WebUsbMuxHub::new_usb_mux(dev, eps, verbose).await?;
        let conn = hub.connect_tcp_initial(LOCKDOWND_PORT).await?;
        wasm_log::info("mux: pseudo-TCP to lockdownd — cleartext stream ready");

        Ok(Self {
            hub,
            conn,
            verbose,
            tls: None,
        })
    }

    /// Run **rustls** on the lockdownd stream after cleartext `StartSession` with `EnableSessionSSL`.
    pub async fn upgrade_lockdown_tls(
        &mut self,
        keys: &WasmHostKeys,
        client_auth: LockdownTlsClientAuth,
        tls_sni: LockdownTlsSni,
    ) -> Result<(), JsValue> {
        let tls_conn = handshake_tls_mux_tcp_wasm(
            &mut self.hub,
            &mut self.conn,
            keys,
            client_auth,
            tls_sni,
            self.verbose,
        )
        .await
        .map_err(|e| JsValue::from_str(&e))?;
        self.tls = Some(LockdownTlsState {
            conn: tls_conn,
            rx_acc: Vec::new(),
        });
        Ok(())
    }

    pub async fn recv_tcp_payload(&mut self) -> Result<Vec<u8>, JsValue> {
        self.hub.recv_tcp_payload_for(&mut self.conn).await
    }

    pub async fn send_tcp_payload(&mut self, payload: &[u8]) -> Result<(), JsValue> {
        self.hub.send_tcp_payload_for(&mut self.conn, payload).await
    }

    pub async fn send_lockdown_xml(&mut self, xml: &str) -> Result<(), JsValue> {
        let plist = xml.as_bytes();
        let mut frame = Vec::with_capacity(4 + plist.len());
        frame.extend_from_slice(&(plist.len() as u32).to_be_bytes());
        frame.extend_from_slice(plist);
        if self.tls.is_some() {
            let mut st = self.tls.take().ok_or_else(|| {
                JsValue::from_str("internal: TLS state missing during send_lockdown_xml")
            })?;
            let r = tls_write_plain_and_flush_wasm(
                &mut st.conn,
                &mut self.hub,
                &mut self.conn,
                &frame,
                self.verbose,
            )
            .await;
            self.tls = Some(st);
            r.map_err(|e| JsValue::from_str(&e))?;
        } else {
            self.send_tcp_payload(&frame).await?;
        }
        Ok(())
    }

    pub fn mux_version(&self) -> u8 {
        self.conn.mux_version
    }

    pub async fn recv_lockdown_xml(&mut self) -> Result<String, JsValue> {
        if self.tls.is_some() {
            let mut st = self.tls.take().ok_or_else(|| {
                JsValue::from_str("internal: TLS state missing during recv_lockdown_xml")
            })?;
            loop {
                if st.rx_acc.len() >= 4 {
                    let len = u32::from_be_bytes([
                        st.rx_acc[0],
                        st.rx_acc[1],
                        st.rx_acc[2],
                        st.rx_acc[3],
                    ]) as usize;
                    if st.rx_acc.len() >= 4 + len {
                        let xml =
                            String::from_utf8_lossy(&st.rx_acc[4..4 + len]).to_string();
                        st.rx_acc.drain(..4 + len);
                        self.tls = Some(st);
                        log_verbose(
                            self.verbose,
                            &format!("[wasm] lockdown RX plist (TLS) {} bytes", len),
                        );
                        return Ok(xml);
                    }
                }
                let mut buf = [0u8; 16_384];
                let n = match tls_read_plain_wasm(
                    &mut st.conn,
                    &mut self.hub,
                    &mut self.conn,
                    &mut buf,
                    self.verbose,
                )
                .await
                {
                    Ok(n) => n,
                    Err(e) => {
                        self.tls = Some(st);
                        return Err(JsValue::from_str(&e));
                    }
                };
                if n == 0 {
                    self.tls = Some(st);
                    return Err(JsValue::from_str("TLS read returned 0"));
                }
                st.rx_acc.extend_from_slice(&buf[..n]);
                if st.rx_acc.len() > 8 * 1024 * 1024 {
                    self.tls = Some(st);
                    return Err(JsValue::from_str("lockdown response too large"));
                }
            }
        }

        let mut acc: Vec<u8> = Vec::new();
        loop {
            if acc.len() >= 4 {
                let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
                if acc.len() >= 4 + len {
                    let xml = String::from_utf8_lossy(&acc[4..4 + len]).to_string();
                    log_verbose(
                        self.verbose,
                        &format!("[wasm] lockdown RX plist {} bytes", len),
                    );
                    return Ok(xml);
                }
            }
            let chunk = self.recv_tcp_payload().await?;
            acc.extend_from_slice(&chunk);
            if acc.len() > 8 * 1024 * 1024 {
                return Err(JsValue::from_str("lockdown response too large"));
            }
        }
    }

    pub async fn query_type(&mut self) -> Result<String, JsValue> {
        self.send_lockdown_xml(QUERY_TYPE_XML).await?;
        self.recv_lockdown_xml().await
    }

    pub async fn start_session_cleartext(
        &mut self,
        ids: &PairingIds,
    ) -> Result<String, JsValue> {
        let xml = start_session_xml(&ids.host_id, &ids.system_buid);
        self.send_lockdown_xml(&xml).await?;
        self.recv_lockdown_xml().await
    }

    pub async fn get_value_cleartext(
        &mut self,
        domain: &str,
        key: &str,
    ) -> Result<String, JsValue> {
        let xml = get_value_xml(domain, key);
        self.send_lockdown_xml(&xml).await?;
        self.recv_lockdown_xml().await
    }

    /// **`StartService`** on lockdownd (cleartext or TLS per current session).
    pub async fn start_service(&mut self, service: &str) -> Result<(u16, bool), JsValue> {
        let xml = start_service_xml(service);
        self.send_lockdown_xml(&xml).await?;
        let reply = self.recv_lockdown_xml().await?;
        parse_start_service_response(&reply).map_err(|e| JsValue::from_str(&e))
    }

    /// Cleartext **`GetValue DevicePublicKey`** → **PEM** (`-----BEGIN …-----`). Base64 `<data>` block
    /// in the reply is the PEM text itself, same as `idevice::lockdown`.
    pub async fn get_device_public_key_pem(&mut self) -> Result<String, JsValue> {
        self.send_lockdown_xml(GET_DEVICE_PUBLIC_KEY_XML).await?;
        let xml = self.recv_lockdown_xml().await?;
        let start = xml
            .find("<data>")
            .ok_or_else(|| JsValue::from_str("GetDevicePublicKey: no <data> tag"))?
            + 6;
        let end = xml
            .find("</data>")
            .ok_or_else(|| JsValue::from_str("GetDevicePublicKey: no </data> tag"))?;
        let b64: String = xml[start..end].chars().filter(|c| !c.is_whitespace()).collect();
        use base64::{engine::general_purpose, Engine as _};
        let decoded = general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("GetDevicePublicKey base64: {}", e)))?;
        String::from_utf8(decoded)
            .map_err(|e| JsValue::from_str(&format!("GetDevicePublicKey utf8: {}", e)))
    }

    /// Build a libimobiledevice/pymobiledevice3-shaped `Pair` plist (PEM certs as `<string>`).
    pub async fn build_pair_request_xml(
        &mut self,
        keys: &WasmHostKeys,
        ids: &PairingIds,
    ) -> Result<String, JsValue> {
        if !keys.can_sign_device_leaf() {
            return Err(JsValue::from_str(
                "Pair: keys were loaded from a pair-record plist (no root CA); use generated keys",
            ));
        }
        let device_pub_pem = self.get_device_public_key_pem().await?;
        let device_cert_pem = build_device_certificate(&device_pub_pem, keys)
            .map_err(|e| JsValue::from_str(&format!("build device cert: {}", e)))?;
        let xml = pair_plist(
            "iphone-wasm",
            &ids.host_id,
            &ids.system_buid,
            None,
            &device_cert_pem,
            &keys.host_cert_pem,
            &keys.root_cert_pem,
            &keys.root_private_pem,
        );
        Ok(xml)
    }

    /// Send a `Pair` plist, return lockdownd's reply (unchanged XML).
    pub async fn pair_exchange(&mut self, xml: &str) -> Result<String, JsValue> {
        self.send_lockdown_xml(xml).await?;
        self.recv_lockdown_xml().await
    }

    /// Drop the current lockdownd TCP and open a fresh mux pseudo-TCP stream.
    /// libimobiledevice does this between `Pair` retries and before `StartSession` + TLS.
    pub async fn reopen_lockdown_tcp(&mut self) -> Result<(), JsValue> {
        let new_conn = self.hub.connect_tcp_additional(LOCKDOWND_PORT).await?;
        self.conn = new_conn;
        self.tls = None;
        Ok(())
    }

    /// Call `Pair`; while lockdownd returns `PairingDialogResponsePending` / `PasswordProtected`,
    /// retry the **same** Pair plist (same device cert bytes) on the **same** mux TCP every
    /// `poll_secs`. This mirrors `pymobiledevice3._request_pair`.
    ///
    /// **Do not** reopen the mux pseudo-TCP between retries: lockdownd treats the new connection
    /// as a fresh session and drops the pending pair state, so the next `Pair` returns
    /// `InvalidPairRecord` even though the certs / `HostID` are perfectly fine. Likewise, **do
    /// not** add a long sleep on `PairingDialogResponsePending` — some lockdownd builds invalidate
    /// the pending pair if the host pauses too long after the dialog appears (we used to wait 15 s
    /// here and it caused exactly that symptom).
    pub async fn pair_with_trust_wait(
        &mut self,
        keys: &WasmHostKeys,
        ids: &PairingIds,
        timeout_secs: u32,
        poll_secs: u32,
    ) -> Result<String, JsValue> {
        let pair_xml = self.build_pair_request_xml(keys, ids).await?;
        wasm_log::info(&format!(
            "[pair] HostID={} SystemBUID={} (Pair plist {} bytes)",
            ids.host_id,
            ids.system_buid,
            pair_xml.len()
        ));
        let mut reply = self.pair_exchange(&pair_xml).await?;
        let deadline_ms = js_sys::Date::now() + (timeout_secs.max(1) as f64) * 1000.0;
        let mut logged_wait_hint = false;
        let poll = poll_secs.max(1);
        loop {
            let pending = reply.contains("PairingDialogResponsePending")
                || reply.contains("PasswordProtected");
            if !pending {
                break;
            }
            if js_sys::Date::now() >= deadline_ms {
                return Err(JsValue::from_str(&format!(
                    "Timed out after {}s waiting for unlock + Trust on the device. Complete the \
                     prompt on the iPhone and retry (increase timeout if you need more time).",
                    timeout_secs
                )));
            }
            if !logged_wait_hint {
                wasm_log::info(&format!(
                    "[pair] Waiting for unlock / Trust / passcode on the device (timeout {}s)…",
                    timeout_secs
                ));
                logged_wait_hint = true;
            }
            sleep(Duration::from_secs(poll as u64)).await;
            reply = self.pair_exchange(&pair_xml).await?;
        }
        if reply.contains("<key>Error</key>") {
            return Err(JsValue::from_str(&format!(
                "Pair was rejected by lockdownd: {}",
                reply.replace('\n', " ").chars().take(260).collect::<String>()
            )));
        }
        wasm_log::info(&format!("[pair] Pair OK ({} bytes)", reply.len()));
        Ok(reply)
    }
}

/// Read **`HostID`** and **`SystemBUID`** `<string>` values from an **XML** pair-record plist (root dict).
pub fn pairing_ids_from_plist_xml(xml: &str) -> Result<PairingIds, JsValue> {
    if xml.len() >= 6 && xml.as_bytes().starts_with(b"bplist") {
        return Err(JsValue::from_str(
            "pair-record plist is binary (bplist); use an XML plist or paste HostID / SystemBUID",
        ));
    }
    let host_id = plist_string_for_key(xml, "HostID")?;
    let system_buid = plist_string_for_key(xml, "SystemBUID")?;
    let host_id = host_id.trim().to_string();
    let system_buid = system_buid.trim().to_string();
    if host_id.is_empty() || system_buid.is_empty() {
        return Err(JsValue::from_str(
            "plist: empty HostID or SystemBUID after trim",
        ));
    }
    Ok(PairingIds {
        host_id,
        system_buid,
    })
}

fn plist_string_for_key(xml: &str, key: &str) -> Result<String, JsValue> {
    let token = format!("<key>{key}</key>");
    let i = xml.find(&token).ok_or_else(|| {
        JsValue::from_str(&format!("plist: missing {token} (XML pair record?)"))
    })?;
    let after = xml[i + token.len()..].trim_start();
    let rest = after.strip_prefix("<string>").ok_or_else(|| {
        JsValue::from_str(&format!(
            "plist: value after {key} is not <string>…</string>"
        ))
    })?;
    let end = rest
        .find("</string>")
        .ok_or_else(|| JsValue::from_str(&format!("plist: {key} missing </string>")))?;
    Ok(rest[..end].to_string())
}

pub fn pairing_ids_from_mode(mode: &str, host_id: &str, system_buid: &str) -> Result<PairingIds, JsValue> {
    match mode.trim() {
        "random" => Ok(PairingIds::new_v4()),
        "legacy" => Ok(PairingIds::legacy_host_and_system()),
        "plist" => {
            let h = host_id.trim();
            let s = system_buid.trim();
            if h.is_empty() || s.is_empty() {
                return Err(JsValue::from_str(
                    "plist mode: set HostID and SystemBUID (from pair-record plist or by hand)",
                ));
            }
            Ok(PairingIds {
                host_id: h.to_string(),
                system_buid: s.to_string(),
            })
        }
        _ => Err(JsValue::from_str(
            "pair mode must be random, legacy, or plist",
        )),
    }
}
