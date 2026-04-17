//! Length-prefixed lockdown plists over **WebUSB** mux + pseudo-TCP, with optional **rustls**.
//! Uses [`crate::web_usb_mux_hub::WebUsbMuxHub`] so secondary pseudo-TCP (e.g. AFC) shares one USB bulk pair.

use idevice_usb_core::lockdown_proto::{
    get_value_xml, start_session_xml, PairingIds, LOCKDOWND_PORT, QUERY_TYPE_XML,
};
use idevice_usb_core::TcpConn;
use rustls::ClientConnection;
use idevice_usb_core::lockdown_proto::{parse_start_service_response, start_service_xml};
use wasm_bindgen::prelude::*;
use web_sys::UsbDevice;

use crate::lockdown_tls_wasm::{
    handshake_tls_mux_tcp_wasm, tls_read_plain_wasm, tls_write_plain_and_flush_wasm,
    LockdownTlsClientAuth, LockdownTlsSni,
};
use crate::wasm_crypto::WasmHostKeys;
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
