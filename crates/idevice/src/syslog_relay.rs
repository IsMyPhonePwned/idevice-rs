//! **`com.apple.syslog_relay`** — stream device logs to any [`std::io::Write`] (stdout or a file).
//!
//! **`EnableServiceSSL` false** (legacy cleartext relay): messages are **`u32` big-endian length** + payload,
//! matching **libimobiledevice** `tools/idevicesyslog.c`.
//!
//! **`EnableServiceSSL` true** (typical on current iOS): TLS application data is **raw syslog text** — not
//! length-prefixed (the old framing would mis-read `"Apr "`… as a 32-bit length).
//!
//! Requires a **direct USB mux** (secondary pseudo-TCP), like crash reports — not available when lockdown is only over **usbmuxd** tunnel.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use rustls::ClientConnection;

use crate::crypto::HostKeys;
use crate::lockdown::LockdownClient;
use crate::lockdown_rustls::{
    handshake_service_tls, tls_read_plain_service, LockdownTlsClientAuth, LockdownTlsSni,
};
use crate::mux_link::MuxHub;
use idevice_usb_core::TcpConn;

/// Lockdown service name (matches **libimobiledevice** / **`idevicesyslog`**).
pub const SYSLOG_RELAY_SERVICE: &str = "com.apple.syslog_relay";

/// Reject syslog frames larger than this (bytes of payload after the 4-byte length prefix).
const MAX_SYSLOG_FRAME: usize = 16 * 1024 * 1024;

type MuxHubRc = Rc<RefCell<MuxHub>>;

/// After **`StartSession` → TLS** on lockdown, call **`StartService`** for syslog relay and copy
/// data to **`out`** until the connection closes or an error occurs.
pub fn relay_syslog<W: Write>(
    client: &mut LockdownClient,
    keys: &HostKeys,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
    tls_debug: bool,
    mut out: W,
) -> Result<(), String> {
    let mux = client.mux_link().ok_or(
        "syslog relay needs direct USB mux (a second pseudo-TCP to the relay port). \
         When usbmuxd holds the device, use Apple `idevicesyslog` from libimobiledevice, \
         or stop usbmuxd briefly for exclusive USB.",
    )?;

    let (port, ssl) = client.start_service(SYSLOG_RELAY_SERVICE)?;
    crate::console_log!(
        "[syslog] StartService {} → port {} EnableServiceSSL={}",
        SYSLOG_RELAY_SERVICE,
        port,
        ssl
    );

    let hub = client
        .mux_hub()
        .ok_or_else(|| "syslog: internal error (no mux hub)".to_string())?;

    let tcp = Rc::new(RefCell::new(
        mux.borrow().connect_service_tcp(port)?,
    ));

    if ssl {
        let mut tls = handshake_service_tls(
            hub.clone(),
            tcp.clone(),
            keys,
            client_auth,
            tls_sni,
            tls_debug,
        )?;
        relay_raw_tls(&mut tls, &hub, &tcp, tls_debug, &mut out)?;
    } else {
        relay_framed_cleartext(&hub, &tcp, &mut out)?;
    }
    Ok(())
}

/// TLS syslog relay: write decrypted application data directly to `out` (no u32 length prefix).
fn relay_raw_tls<W: Write>(
    tls: &mut ClientConnection,
    hub: &MuxHubRc,
    tcp: &Rc<RefCell<TcpConn>>,
    tls_debug: bool,
    out: &mut W,
) -> Result<(), String> {
    let mut scratch = [0u8; 64 * 1024];
    loop {
        let n = tls_read_plain_service(tls, hub, tcp, &mut scratch, tls_debug)?;
        if n == 0 {
            return Ok(());
        }
        out.write_all(&scratch[..n])
            .map_err(|e| format!("syslog output: {}", e))?;
        out.flush().ok();
    }
}

fn drain_framed<W: Write>(buf: &mut Vec<u8>, out: &mut W) -> Result<(), String> {
    loop {
        if buf.len() < 4 {
            return Ok(());
        }
        let len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
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
            return Ok(());
        }
        out.write_all(&buf[4..4 + len])
            .map_err(|e| format!("syslog output: {}", e))?;
        out.flush().ok();
        buf.drain(..4 + len);
    }
}

fn relay_framed_cleartext<W: Write>(
    hub: &MuxHubRc,
    tcp: &Rc<RefCell<TcpConn>>,
    out: &mut W,
) -> Result<(), String> {
    let mut buf = Vec::new();
    loop {
        let chunk = {
            let mut h = hub.borrow_mut();
            let mut t = tcp.borrow_mut();
            h.recv_tcp_payload_for(&mut *t)?
        };
        if chunk.is_empty() {
            return Err("syslog: connection closed (empty mux segment)".into());
        }
        buf.extend_from_slice(&chunk);
        drain_framed(&mut buf, out)?;
    }
}

