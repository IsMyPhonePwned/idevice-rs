//! Blocking lockdownd over **USB mux** (libusb) or **usbmuxd** (Unix socket). **TLS uses rustls**.
//! Default TLS credentials match **pymobiledevice3** / WASM (`host` leaf); `root` matches **libimobiledevice** OpenSSL when your pair record does too.

pub use crate::lockdown_rustls::{LockdownTlsClientAuth, LockdownTlsSni};

use std::cell::RefCell;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use rustls::ClientConnection;

use crate::crypto::build_device_certificate;
use crate::mux_io::CleartextMuxIo;
use crate::mux_link::MuxLink;
use crate::usb::{prepare_mux_interface, AppleUsb};
use idevice_usb_core::TcpConn;
use idevice_usb_core::{lockdown_proto, PairingIds};

/// Underlying cleartext transport to lockdownd.
pub enum LockdownTransport {
    Usb(Rc<RefCell<MuxLink>>),
    #[cfg(unix)]
    Socket(Rc<RefCell<crate::socket_mux::SocketMuxLink>>),
}

pub struct LockdownClient {
    transport: LockdownTransport,
    app_rx_buffer: Vec<u8>,
    tls: Option<ClientConnection>,
    /// TLS **application** cleartext logging (set from `enable_ssl` when `tls_debug` is true).
    tls_payload_trace: bool,
}

impl LockdownClient {
    /// Drop the current session and open a **fresh** lockdownd connection (USB pseudo-TCP or usbmuxd tunnel).
    pub fn reopen_lockdown_tcp(&mut self) -> Result<(), String> {
        self.tls.take();
        self.tls_payload_trace = false;
        self.app_rx_buffer.clear();
        match &mut self.transport {
            LockdownTransport::Usb(mux) => {
                let mut ml = mux.borrow_mut();
                ml.clear_usb_rx_buffer();
                let hub_rc = ml.hub.clone();
                let eps = ml.hub.borrow().eps;
                let mut mux_tx_next = hub_rc.borrow().mux_tx_seq;
                let new_conn = {
                    let mut hub = hub_rc.borrow_mut();
                    TcpConn::handshake_and_connect(
                        &mut *hub,
                        &eps,
                        idevice_usb_core::lockdown_proto::LOCKDOWND_PORT,
                        &mut mux_tx_next,
                    )?
                };
                hub_rc.borrow_mut().mux_tx_seq = mux_tx_next;
                ml.conn = new_conn;
            }
            #[cfg(unix)]
            LockdownTransport::Socket(s) => {
                s.borrow_mut().reopen_lockdown()?;
            }
        }
        self.exchange_query_type()?;
        Ok(())
    }

    pub fn new(mut usb: AppleUsb) -> Result<Self, String> {
        let eps = usb.eps.clone();
        crate::console_log!(
            "[lockdown] USB setup: configuration_value={} interface_number={} alternate_setting={} ep_out={} ep_in={}",
            usb.target_config,
            usb.target_iface,
            usb.target_alt,
            eps.ep_out,
            eps.ep_in
        );

        prepare_mux_interface(&mut usb)?;

        let mut mux_tx_next = 1u16;
        let conn = TcpConn::handshake_and_connect(
            &mut usb,
            &eps,
            lockdown_proto::LOCKDOWND_PORT,
            &mut mux_tx_next,
        )?;

        let mux = Rc::new(RefCell::new(MuxLink::new(usb, eps, conn, mux_tx_next)));

        let mut client = Self {
            transport: LockdownTransport::Usb(mux),
            app_rx_buffer: Vec::new(),
            tls: None,
            tls_payload_trace: false,
        };
        client.exchange_query_type()?;
        Ok(client)
    }

    /// Lockdownd over **usbmuxd** (same as libimobiledevice when the daemon owns USB).
    #[cfg(unix)]
    pub fn new_usbmuxd(
        stream: std::os::unix::net::UnixStream,
        socket_path: std::path::PathBuf,
        device_id: u32,
    ) -> Result<Self, String> {
        crate::console_log!(
            "[lockdown] usbmuxd tunnel: device_id={} socket={}",
            device_id,
            socket_path.display()
        );
        let link = Rc::new(RefCell::new(crate::socket_mux::SocketMuxLink::new(
            stream,
            socket_path,
            device_id,
        )));
        let mut client = Self {
            transport: LockdownTransport::Socket(link),
            app_rx_buffer: Vec::new(),
            tls: None,
            tls_payload_trace: false,
        };
        client.exchange_query_type()?;
        Ok(client)
    }

    fn exchange_query_type(&mut self) -> Result<(), String> {
        self.send_request(lockdown_proto::QUERY_TYPE_XML)?;
        let xml = self.receive_response()?;
        let preview: String = xml.chars().take(280).collect();
        crate::console_log!("[lockdown] QueryType response (truncated): {}", preview);
        Ok(())
    }

    pub fn enable_ssl(
        &mut self,
        keys: &crate::crypto::HostKeys,
        client_auth: LockdownTlsClientAuth,
        tls_sni: LockdownTlsSni,
        tls_settle_ms: u64,
        tls_debug: bool,
    ) -> Result<(), String> {
        crate::console_log!("=== SECURING TLS SESSION (rustls / idevice-style mux I/O) ===");

        self.app_rx_buffer.clear();

        if tls_settle_ms > 0 {
            crate::console_log!(
                "[lockdown] Pausing for iOS socket transition ({} ms; from `--lockdown-tls-settle-ms`)…",
                tls_settle_ms
            );
        }
        if tls_settle_ms > 500 {
            crate::console_log!(
                "[lockdown] WARNING: delays over ~500 ms before TLS ClientHello can cause lockdownd to \
                 close the mux TCP session (plaintext `sessionUpcall`). Prefer a small value or `0`."
            );
        }
        thread::sleep(Duration::from_millis(tls_settle_ms));

        match &mut self.transport {
            LockdownTransport::Usb(m) => m.borrow_mut().hub.borrow_mut().verbose_tcp = tls_debug,
            #[cfg(unix)]
            LockdownTransport::Socket(_) => {}
        }

        let conn = match &mut self.transport {
            LockdownTransport::Usb(mux) => {
                let c = match crate::lockdown_rustls::handshake_lockdown_tls(
                    mux.clone(),
                    keys,
                    client_auth,
                    tls_sni,
                    tls_debug,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        mux.borrow_mut().hub.borrow_mut().verbose_tcp = false;
                        return Err(e);
                    }
                };
                mux.borrow_mut().hub.borrow_mut().verbose_tcp = false;
                c
            }
            #[cfg(unix)]
            LockdownTransport::Socket(link) => crate::lockdown_rustls::handshake_lockdown_tls(
                link.clone(),
                keys,
                client_auth,
                tls_sni,
                tls_debug,
            )?,
        };
        self.tls = Some(conn);
        self.tls_payload_trace = tls_debug;
        Ok(())
    }

    pub fn send_request(&mut self, xml: &str) -> Result<(), String> {
        let plist = xml.as_bytes();
        let mut payload = Vec::with_capacity(4 + plist.len());
        payload.extend_from_slice(&(plist.len() as u32).to_be_bytes());
        payload.extend_from_slice(plist);

        if let Some(ref mut tls) = self.tls {
            crate::console_log!(
                "[lockdown] Encrypting {} byte XML payload (rustls)…",
                payload.len()
            );
            let trace = self.tls_payload_trace;
            match &mut self.transport {
                LockdownTransport::Usb(mux) => {
                    crate::lockdown_rustls::tls_write_plain_and_flush(
                        tls,
                        &mut *mux.borrow_mut(),
                        &payload,
                        trace,
                    )?;
                }
                #[cfg(unix)]
                LockdownTransport::Socket(s) => {
                    crate::lockdown_rustls::tls_write_plain_and_flush(
                        tls,
                        &mut *s.borrow_mut(),
                        &payload,
                        trace,
                    )?;
                }
            }
        } else {
            match &mut self.transport {
                LockdownTransport::Usb(mux) => mux.borrow_mut().send_raw(&payload)?,
                #[cfg(unix)]
                LockdownTransport::Socket(s) => s.borrow_mut().send_raw(&payload)?,
            }
        }

        Ok(())
    }

    pub fn receive_response(&mut self) -> Result<String, String> {
        loop {
            if self.app_rx_buffer.len() >= 4 {
                let len = u32::from_be_bytes([
                    self.app_rx_buffer[0],
                    self.app_rx_buffer[1],
                    self.app_rx_buffer[2],
                    self.app_rx_buffer[3],
                ]) as usize;
                if self.app_rx_buffer.len() >= 4 + len {
                    let xml = String::from_utf8_lossy(&self.app_rx_buffer[4..4 + len]).to_string();
                    self.app_rx_buffer.drain(..4 + len);
                    return Ok(xml);
                }
            }

            if let Some(ref mut tls) = self.tls {
                let mut buf = [0u8; 16384];
                let trace = self.tls_payload_trace;
                let n = match &mut self.transport {
                    LockdownTransport::Usb(mux) => {
                        crate::lockdown_rustls::tls_read_plain(
                            tls,
                            &mut *mux.borrow_mut(),
                            &mut buf,
                            trace,
                        )?
                    }
                    #[cfg(unix)]
                    LockdownTransport::Socket(s) => {
                        crate::lockdown_rustls::tls_read_plain(
                            tls,
                            &mut *s.borrow_mut(),
                            &mut buf,
                            trace,
                        )?
                    }
                };
                if n == 0 {
                    return Err("lockdownd connection closed (rustls read returned 0)".into());
                }
                self.app_rx_buffer.extend_from_slice(&buf[..n]);
            } else {
                let tcp_payload = match &mut self.transport {
                    LockdownTransport::Usb(mux) => mux.borrow_mut().recv_tcp_payload()?,
                    #[cfg(unix)]
                    LockdownTransport::Socket(s) => s.borrow_mut().recv_tcp_payload()?,
                };
                self.app_rx_buffer.extend_from_slice(&tcp_payload);
            }
        }
    }

    fn cli_host_name_for_pair() -> String {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "idevice".to_string())
    }

    fn try_wifi_mac_address(&mut self) -> Option<String> {
        for key in ["WiFiAddress", "BluetoothAddress"] {
            let req = lockdown_proto::get_value_xml("", key);
            if self.send_request(&req).is_err() {
                continue;
            }
            let Ok(xml) = self.receive_response() else {
                continue;
            };
            if let Some(s) = lockdown_proto::parse_get_value_string(&xml) {
                let t = s.trim();
                if !t.is_empty() {
                    crate::console_log!(
                        "[lockdown] Pair record WiFiMACAddress from GetValue `{}` (len {})",
                        key,
                        t.len()
                    );
                    return Some(t.to_string());
                }
            }
        }
        crate::console_log!(
            "[lockdown] No WiFi/BT MAC from GetValue before Pair (WiFiMACAddress omitted from plist)"
        );
        None
    }

    pub fn build_pair_request_xml(
        &mut self,
        keys: &crate::crypto::HostKeys,
        ids: &PairingIds,
    ) -> Result<String, String> {
        let wifi_mac = self.try_wifi_mac_address();
        let host_name = Self::cli_host_name_for_pair();

        self.send_request(lockdown_proto::GET_DEVICE_PUBLIC_KEY_XML)?;
        let pubkey_res = self.receive_response()?;
        if crate::diagnostic_trace_enabled() {
            crate::console_log!(
                "[crypto] Pair: GetDevicePublicKey response: {} bytes",
                pubkey_res.len()
            );
        }

        let start = pubkey_res.find("<data>").ok_or("No <data> tag")? + 6;
        let end = pubkey_res.find("</data>").ok_or("No </data> tag")?;
        let b64 = pubkey_res[start..end].replace(['\n', '\t'], "");

        use base64::{engine::general_purpose, Engine as _};
        let pubkey_pem = general_purpose::STANDARD
            .decode(b64)
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .map_err(|_| "Base64 decode failed")?;

        let device_cert_pem = build_device_certificate(&pubkey_pem, keys)?;

        let pair_xml = lockdown_proto::pair_plist(
            &host_name,
            &ids.host_id,
            &ids.system_buid,
            wifi_mac.as_deref(),
            &device_cert_pem,
            &keys.host_cert_pem,
            &keys.root_cert_pem,
            &keys.root_private_pem,
        );
        if crate::diagnostic_trace_enabled() {
            let head: String = pair_xml.chars().take(220).collect::<String>().replace('\n', " ");
            crate::console_log!(
                "[crypto] Built Pair plist: {} bytes (preview): {}",
                pair_xml.len(),
                head
            );
        }
        Ok(pair_xml)
    }

    pub fn pair_exchange(&mut self, pair_xml: &str) -> Result<String, String> {
        if crate::diagnostic_trace_enabled() {
            crate::console_log!(
                "[crypto] pair_exchange → sending Pair request: {} bytes",
                pair_xml.len()
            );
        }
        self.send_request(pair_xml)?;
        let resp = self.receive_response()?;
        if crate::diagnostic_trace_enabled() {
            crate::console_log!(
                "[crypto] pair_exchange ← response: {} bytes",
                resp.len()
            );
        }
        Ok(resp)
    }

    pub fn pair(
        &mut self,
        keys: &crate::crypto::HostKeys,
        ids: &PairingIds,
    ) -> Result<String, String> {
        let xml = self.build_pair_request_xml(keys, ids)?;
        self.pair_exchange(&xml)
    }

    pub fn validate_pair(
        &mut self,
        keys: &crate::crypto::HostKeys,
        ids: &PairingIds,
    ) -> Result<String, String> {
        self.send_request(lockdown_proto::GET_DEVICE_PUBLIC_KEY_XML)?;
        let pubkey_res = self.receive_response()?;
        if crate::diagnostic_trace_enabled() {
            crate::console_log!(
                "[crypto] ValidatePair: GetDevicePublicKey response {} bytes",
                pubkey_res.len()
            );
        }

        let start = pubkey_res.find("<data>").ok_or("No <data> tag")? + 6;
        let end = pubkey_res.find("</data>").ok_or("No </data> tag")?;
        let b64 = pubkey_res[start..end].replace(['\n', '\t'], "");

        use base64::{engine::general_purpose, Engine as _};
        let pubkey_pem = general_purpose::STANDARD
            .decode(b64)
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .map_err(|_| "Base64 decode failed")?;

        let device_cert_pem = build_device_certificate(&pubkey_pem, keys)?;

        let xml = lockdown_proto::validate_pair_plist(
            &ids.host_id,
            &ids.system_buid,
            None,
            &device_cert_pem,
            &keys.host_cert_pem,
            &keys.root_cert_pem,
        );
        if crate::diagnostic_trace_enabled() {
            crate::console_log!(
                "[crypto] ValidatePair plist: {} bytes",
                xml.len()
            );
        }

        self.send_request(&xml)?;
        let out = self.receive_response()?;
        if crate::diagnostic_trace_enabled() {
            crate::console_log!(
                "[crypto] ValidatePair response: {} bytes",
                out.len()
            );
        }
        Ok(out)
    }

    pub fn start_session(&mut self, ids: &PairingIds) -> Result<String, String> {
        let session_xml = lockdown_proto::start_session_xml(&ids.host_id, &ids.system_buid);
        if crate::diagnostic_trace_enabled() {
            crate::console_log!(
                "[crypto] StartSession request: {} bytes",
                session_xml.len()
            );
        }
        self.send_request(&session_xml)?;
        let res = self.receive_response()?;
        if crate::diagnostic_trace_enabled() {
            crate::console_log!(
                "[crypto] StartSession response: {} bytes",
                res.len()
            );
        }
        Ok(res)
    }

    pub fn get_value(&mut self, domain: &str, key: &str) -> Result<String, String> {
        let req = lockdown_proto::get_value_xml(domain, key);
        self.send_request(&req)?;
        self.receive_response()
    }

    pub fn start_service(&mut self, service: &str) -> Result<(u16, bool), String> {
        let req = lockdown_proto::start_service_xml(service);
        self.send_request(&req)?;
        let xml = self.receive_response()?;
        lockdown_proto::parse_start_service_response(&xml)
    }

    /// USB mux hub for secondary pseudo-TCP (AFC, etc.). **`None`** when using **usbmuxd** tunnel only.
    pub fn mux_hub(&self) -> Option<Rc<RefCell<crate::mux_link::MuxHub>>> {
        match &self.transport {
            LockdownTransport::Usb(m) => Some(m.borrow().hub.clone()),
            #[cfg(unix)]
            LockdownTransport::Socket(_) => None,
        }
    }

    pub fn mux_link(&self) -> Option<Rc<RefCell<crate::mux_link::MuxLink>>> {
        match &self.transport {
            LockdownTransport::Usb(m) => Some(m.clone()),
            #[cfg(unix)]
            LockdownTransport::Socket(_) => None,
        }
    }
}

impl Drop for LockdownClient {
    fn drop(&mut self) {
        self.tls.take();
        if let LockdownTransport::Usb(m) = &mut self.transport {
            let iface = m.borrow().hub.borrow().usb.target_iface;
            let _ = m.borrow_mut().hub.borrow_mut().usb.handle.release_interface(iface);
        }
    }
}
