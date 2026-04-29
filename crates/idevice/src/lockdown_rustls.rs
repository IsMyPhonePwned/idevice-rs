//! Lockdownd TLS over mux pseudo-TCP using **rustls**, aligned with [jkcoxson/idevice](https://github.com/jkcoxson/idevice):
//! root CA in a [`rustls::RootCertStore`], [`rustls::client::WebPkiServerVerifier`] for signature algorithms,
//! a verifier that skips server-name / trust-anchor checks (see upstream `idevice/src/sni.rs`), **SNI `Device`**,
//! **Client auth** defaults to **root + root key** (libimobiledevice `idevice_connection_enable_ssl`); use `host` for pymobiledevice3 / idevice rust `sni.rs`. Explicit **`write_tls` / `read_tls`** mux I/O.
//!
//! Reference excerpts: `docs/lockdown-tls-idevice-reference.md`.

use std::cell::RefCell;
use std::io::{Cursor, Read, Write};
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{VerifierBuilderError, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};

use crate::crypto::HostKeys;
use crate::mux_io::CleartextMuxIo;
use crate::mux_link::MuxHub;
use idevice_usb_core::TcpConn;

/// TLS ClientHello SNI. [jkcoxson/idevice](https://github.com/jkcoxson/idevice) uses `Device`; libimobiledevice sends none.
#[cfg_attr(feature = "with-clap", derive(clap::ValueEnum))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum LockdownTlsSni {
    /// Set SNI to `Device` — matches idevice `ServerName::try_from("Device")` + `tokio_rustls::TlsConnector::connect`.
    #[default]
    Device,
    /// No SNI extension — rustls uses an IP `ServerName` so the ClientHello omits SNI (rustls only sends SNI for DNS names).
    None,
}

/// Which client certificate lockdownd sees during TLS (see CLI `--help`).
#[cfg_attr(feature = "with-clap", derive(clap::ValueEnum))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum LockdownTlsClientAuth {
    /// Root cert + root private key — matches **libimobiledevice** `idevice_connection_enable_ssl`
    /// (`SSL_CTX_use_certificate` + root key from the pair record). Use with libimobiledevice-shaped pair records.
    Root,
    /// Host leaf + host key — **pymobiledevice3** `ssl_file()` / jkcoxson idevice `sni.rs`; matches the cert chain built in `Pair` here and in WASM `tls.rs`.
    #[default]
    Host,
    /// Host leaf + root CA in the chain, host key.
    Chain,
}

// --- jkcoxson/idevice `sni.rs`-style: accept any server cert, but use webpki for signature schemes / TLS sig verify.

#[derive(Debug)]
struct LockdownIdeviceVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for LockdownIdeviceVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn client_cert_chain_and_key(
    keys: &HostKeys,
    mode: LockdownTlsClientAuth,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    match mode {
        LockdownTlsClientAuth::Host => (
            vec![CertificateDer::from(keys.host_cert_der.clone())],
            PrivateKeyDer::Pkcs8(keys.private_key_der.clone().into()),
        ),
        LockdownTlsClientAuth::Chain => (
            vec![
                CertificateDer::from(keys.host_cert_der.clone()),
                CertificateDer::from(keys.root_cert_der.clone()),
            ],
            PrivateKeyDer::Pkcs8(keys.private_key_der.clone().into()),
        ),
        LockdownTlsClientAuth::Root => (
            vec![CertificateDer::from(keys.root_cert_der.clone())],
            PrivateKeyDer::Pkcs8(keys.root_private_der.clone().into()),
        ),
    }
}

/// Mirrors idevice `sni::create_client_config` (verifier + root store). Offer **TLS 1.3 and 1.2** so newer lockdownd can pick 1.3 while older devices stay on 1.2.
fn build_client_config(
    keys: &HostKeys,
    client_auth: LockdownTlsClientAuth,
) -> Result<ClientConfig, String> {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(CertificateDer::from(keys.root_cert_der.clone()))
        .map_err(|e| format!("rustls root_store.add(root CA): {}", e))?;

    let (certs, key_der) = client_cert_chain_and_key(keys, client_auth);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = Arc::new(root_store);
    let inner = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .map_err(|e: VerifierBuilderError| format!("WebPkiServerVerifier::build: {}", e))?;
    let verifier = Arc::new(LockdownIdeviceVerifier { inner });

    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("rustls protocol versions: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key_der)
        .map_err(|e| format!("rustls client auth: {}", e))
}

fn server_name(tls_sni: LockdownTlsSni) -> Result<ServerName<'static>, String> {
    match tls_sni {
        LockdownTlsSni::None => Ok(ServerName::IpAddress(Ipv4Addr::new(127, 0, 0, 1).into())),
        LockdownTlsSni::Device => "Device"
            .try_into()
            .map_err(|_| "invalid TLS server name `Device`".to_string()),
    }
}

fn hex_prefix(data: &[u8], n: usize) -> String {
    let take = n.min(data.len());
    let mut s = String::with_capacity(take * 3);
    for (i, b) in data.iter().take(take).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{:02X}", b));
    }
    if data.len() > take {
        s.push_str(" …");
    }
    s
}

fn first_byte_note(b: Option<u8>) -> &'static str {
    match b {
        Some(0x16) => "likely TLS handshake record",
        Some(0x14) => "likely TLS change_cipher_spec",
        Some(0x17) => "likely TLS application_data",
        Some(0x15) => "likely TLS alert",
        Some(0) => "likely non-TLS (often plist len or `\\0session…`)",
        Some(_) => "unknown first byte",
        None => "empty",
    }
}

fn log_tls_application_cleartext(direction: &str, label: &str, payload: &[u8]) {
    let preview: String = String::from_utf8_lossy(payload)
        .chars()
        .take(220)
        .map(|c| if c == '\n' || c == '\t' { c } else if c.is_control() { '·' } else { c })
        .collect();
    crate::console_log!(
        "[lockdown] TLS cleartext {} {}: {} bytes | hex[0..min(32)]={} | text≈ {}",
        direction,
        label,
        payload.len(),
        hex_prefix(payload, 32),
        preview
    );
}

fn mux_write_all_tls_with(
    conn: &mut ClientConnection,
    write_tcp: &mut impl FnMut(&[u8]) -> Result<(), String>,
    debug: bool,
    phase: &str,
    mut snapshot: impl FnMut() -> String,
) -> Result<usize, String> {
    let mut total = 0usize;
    let mut chunk_idx = 0usize;
    while conn.wants_write() {
        let mut buf = [0u8; 16_384];
        let n = conn
            .write_tls(&mut buf.as_mut_slice())
            .map_err(|e| format!("rustls write_tls: {}", e))?;
        if n == 0 {
            break;
        }
        total += n;
        if debug {
            crate::console_log!(
                "[lockdown] {} write_tls[{}]: {} bytes, first bytes [{}] ({})",
                phase,
                chunk_idx,
                n,
                hex_prefix(&buf[..n], 24),
                first_byte_note(buf.first().copied())
            );
            crate::console_log!("[lockdown] {} before mux OUT: {}", phase, snapshot());
        }
        write_tcp(&buf[..n])?;
        if debug {
            crate::console_log!("[lockdown] {} after mux OUT: {}", phase, snapshot());
        }
        chunk_idx += 1;
    }
    Ok(total)
}

fn mux_write_all_tls<M: CleartextMuxIo + ?Sized>(
    conn: &mut ClientConnection,
    mux: &mut M,
    debug: bool,
    phase: &str,
) -> Result<usize, String> {
    let mut total = 0usize;
    let mut chunk_idx = 0usize;
    while conn.wants_write() {
        let mut buf = [0u8; 16_384];
        let n = conn
            .write_tls(&mut buf.as_mut_slice())
            .map_err(|e| format!("rustls write_tls: {}", e))?;
        if n == 0 {
            break;
        }
        total += n;
        if debug {
            crate::console_log!(
                "[lockdown] {} write_tls[{}]: {} bytes, first bytes [{}] ({})",
                phase,
                chunk_idx,
                n,
                hex_prefix(&buf[..n], 24),
                first_byte_note(buf.first().copied())
            );
            crate::console_log!(
                "[lockdown] {} before mux OUT: {}",
                phase,
                mux.transport_snapshot()
            );
        }
        mux.send_raw(&buf[..n])?;
        if debug {
            crate::console_log!(
                "[lockdown] {} after mux OUT: {}",
                phase,
                mux.transport_snapshot()
            );
        }
        chunk_idx += 1;
    }
    Ok(total)
}

fn feed_tls_from_tcp_segment(
    conn: &mut ClientConnection,
    chunk: &[u8],
    debug: bool,
    phase: &str,
    seg_idx: usize,
) -> Result<(), String> {
    if debug {
        crate::console_log!(
            "[lockdown] {} read segment[{}]: {} bytes, first bytes [{}] ({})",
            phase,
            seg_idx,
            chunk.len(),
            hex_prefix(chunk, 32),
            first_byte_note(chunk.first().copied())
        );
    }
    let mut cur = Cursor::new(chunk);
    while (cur.position() as usize) < chunk.len() {
        let pos_before = cur.position();
        let n = conn
            .read_tls(&mut cur)
            .map_err(|e| format!("rustls read_tls: {}", e))?;
        if let Err(e) = conn.process_new_packets() {
            return Err(tls_io_err_hint(chunk, e));
        }
        if debug && n > 0 {
            crate::console_log!(
                "[lockdown] {} read_tls consumed {} bytes from segment[{}] (cursor {}/{})",
                phase,
                n,
                seg_idx,
                cur.position(),
                chunk.len()
            );
        }
        if n == 0 && cur.position() == pos_before {
            return Err(format!(
                "rustls read_tls made no progress ({} bytes left in TCP segment)",
                chunk.len() - pos_before as usize
            ));
        }
    }
    Ok(())
}

fn tls_io_err_hint(chunk: &[u8], e: Error) -> String {
    let lossy = String::from_utf8_lossy(chunk);
    if lossy.contains("sessionUpcall") || lossy.contains("connection closed") {
        return format!(
            "rustls: {} (peer sent plaintext on the mux stream — often `\\0sessionUpcall connection closed`; \
             confirm Trust / passcode; default client auth is `--lockdown-tls-client-auth host` (pymobiledevice3 / WASM). Try `root`/`chain`, `--pair-ids random`, SNI `device`/`none`, \
             close other usbmux/lockdown clients, or adjust `--lockdown-tls-settle-ms`)",
            e
        );
    }
    format!("rustls: {}", e)
}

/// Perform the TLS handshake: flush **all** pending TLS writes before the first cleartext read.
pub fn handshake_lockdown_tls<M: CleartextMuxIo + ?Sized>(
    mux: Rc<RefCell<M>>,
    keys: &HostKeys,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
    debug: bool,
) -> Result<ClientConnection, String> {
    let cfg = Arc::new(build_client_config(keys, client_auth)?);
    let name = server_name(tls_sni)?;
    let mut conn = ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;

    crate::console_log!(
        "[lockdown] TLS config: idevice-style (root in RootCertStore + WebPkiServerVerifier sig schemes; server cert/name not enforced), client_auth={:?}, SNI mode={:?}, protocols=TLS1.3+TLS1.2",
        client_auth,
        tls_sni
    );
    if debug {
        crate::console_log!("[lockdown] TLS debug: handshake logging ON (`--lockdown-tls-debug`)");
    }
    crate::console_log!(
        "[lockdown] rustls: start handshake (write-first mux I/O); {}",
        mux.borrow().transport_snapshot()
    );

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut iter: u32 = 0;
    while conn.is_handshaking() {
        iter += 1;
        if Instant::now() > deadline {
            return Err("rustls TLS handshake timed out (120 s)".into());
        }
        if debug || iter <= 3 || iter % 10 == 0 {
            crate::console_log!(
                "[lockdown] handshake loop iter={} is_handshaking={} wants_read={} wants_write={}",
                iter,
                conn.is_handshaking(),
                conn.wants_read(),
                conn.wants_write()
            );
        }
        {
            let mut m = mux.borrow_mut();
            let wrote = mux_write_all_tls(&mut conn, &mut *m, debug, "handshake")?;
            if debug && wrote > 0 {
                crate::console_log!(
                    "[lockdown] handshake iter={}: mux wrote {} TLS bytes (sum of write_tls chunks)",
                    iter,
                    wrote
                );
            }
        }
        if !conn.is_handshaking() {
            break;
        }
        if conn.wants_read() {
            let chunk = mux.borrow_mut().recv_tcp_payload()?;
            if chunk.is_empty() {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            feed_tls_from_tcp_segment(&mut conn, &chunk, debug, "handshake", iter as usize)?;
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }

    let mut m = mux.borrow_mut();
    let _ = mux_write_all_tls(&mut conn, &mut *m, debug, "handshake-final")?;

    let snap = m.transport_snapshot();
    let suite = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "?".into());
    crate::console_log!(
        "[lockdown] TLS OK (rustls): cipher suite {} | {}",
        suite,
        snap
    );
    Ok(conn)
}

pub fn tls_write_plain_and_flush<M: CleartextMuxIo + ?Sized>(
    conn: &mut ClientConnection,
    mux: &mut M,
    payload: &[u8],
    trace_plain: bool,
) -> Result<(), String> {
    if trace_plain {
        log_tls_application_cleartext("TX", "lockdown", payload);
    }
    conn.writer()
        .write_all(payload)
        .map_err(|e| format!("rustls plaintext write: {}", e))?;
    conn.writer().flush().ok();
    let _ = mux_write_all_tls(conn, mux, trace_plain, "app-tls-record")?;
    Ok(())
}

pub fn tls_read_plain<M: CleartextMuxIo + ?Sized>(
    conn: &mut ClientConnection,
    mux: &mut M,
    buf: &mut [u8],
    trace_plain: bool,
) -> Result<usize, String> {
    let mut mux_seg: usize = 0;
    loop {
        let mut r = conn.reader();
        match r.read(buf) {
            Ok(n) => {
                if trace_plain && n > 0 {
                    log_tls_application_cleartext("RX", "lockdown", &buf[..n]);
                }
                return Ok(n);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(format!("rustls plaintext read: {}", e)),
        }
        drop(r);
        if !conn.wants_read() {
            return Err(
                "rustls: plaintext read WouldBlock but connection does not want_read — protocol stall"
                    .into(),
            );
        }
        let chunk = mux.recv_tcp_payload()?;
        if chunk.is_empty() {
            return Err("lockdownd connection closed (empty mux segment while reading TLS)".into());
        }
        feed_tls_from_tcp_segment(conn, &chunk, trace_plain, "app-read", mux_seg)?;
        mux_seg = mux_seg.saturating_add(1);
    }
}

fn mux_tcp_snapshot_hc(tcp: &TcpConn) -> String {
    format!(
        "sport={} dport={} seq={} ack={} mux_v={}",
        tcp.sport, tcp.dport, tcp.seq, tcp.ack, tcp.mux_version
    )
}

/// TLS client on a brokered mux TCP stream (**`EnableServiceSSL`**), same certs as lockdownd.
pub fn handshake_service_tls(
    hub: Rc<RefCell<MuxHub>>,
    tcp: Rc<RefCell<TcpConn>>,
    keys: &HostKeys,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
    debug: bool,
) -> Result<ClientConnection, String> {
    let cfg = Arc::new(build_client_config(keys, client_auth)?);
    let name = server_name(tls_sni)?;
    let mut tls_conn = ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;

    crate::console_log!(
        "[service-tls] rustls (same client_auth={:?}, SNI={:?} as lockdownd)",
        client_auth,
        tls_sni
    );

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut iter: u32 = 0;
    while tls_conn.is_handshaking() {
        iter += 1;
        if Instant::now() > deadline {
            return Err("service TLS handshake timed out (120 s)".into());
        }
        if debug || iter <= 3 || iter % 20 == 0 {
            crate::console_log!(
                "[service-tls] iter={} handshaking={} wants_read={} wants_write={}",
                iter,
                tls_conn.is_handshaking(),
                tls_conn.wants_read(),
                tls_conn.wants_write()
            );
        }
        {
            let mut h = hub.borrow_mut();
            let mut t = tcp.borrow_mut();
            let snap_s = mux_tcp_snapshot_hc(&t);
            mux_write_all_tls_with(
                &mut tls_conn,
                &mut |p| h.send_raw_for(&mut *t, p),
                debug,
                "service-handshake",
                move || snap_s.clone(),
            )?;
        }
        if !tls_conn.is_handshaking() {
            break;
        }
        if tls_conn.wants_read() {
            let chunk = {
                let mut h = hub.borrow_mut();
                let mut t = tcp.borrow_mut();
                h.recv_tcp_payload_for(&mut *t)?
            };
            if chunk.is_empty() {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            feed_tls_from_tcp_segment(
                &mut tls_conn,
                &chunk,
                debug,
                "service-handshake",
                iter as usize,
            )?;
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }

    {
        let mut h = hub.borrow_mut();
        let mut t = tcp.borrow_mut();
        let snap_s = mux_tcp_snapshot_hc(&t);
        let _ = mux_write_all_tls_with(
            &mut tls_conn,
            &mut |p| h.send_raw_for(&mut *t, p),
            debug,
            "service-handshake-final",
            move || snap_s.clone(),
        )?;
    }

    let suite = tls_conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "?".into());
    crate::console_log!("[service-tls] OK: cipher {}", suite);
    Ok(tls_conn)
}

pub fn tls_write_plain_and_flush_service(
    tls: &mut ClientConnection,
    hub: &Rc<RefCell<MuxHub>>,
    tcp: &Rc<RefCell<TcpConn>>,
    payload: &[u8],
    trace_plain: bool,
) -> Result<(), String> {
    if trace_plain {
        log_tls_application_cleartext("TX", "service", payload);
    }
    tls.writer()
        .write_all(payload)
        .map_err(|e| format!("rustls plaintext write: {}", e))?;
    tls.writer().flush().ok();
    let mut h = hub.borrow_mut();
    let mut t = tcp.borrow_mut();
    let snap_s = mux_tcp_snapshot_hc(&t);
    let _ = mux_write_all_tls_with(
        tls,
        &mut |p| h.send_raw_for(&mut *t, p),
        trace_plain,
        "service-app-tls-record",
        move || snap_s.clone(),
    )?;
    Ok(())
}

pub fn tls_read_plain_service(
    tls: &mut ClientConnection,
    hub: &Rc<RefCell<MuxHub>>,
    tcp: &Rc<RefCell<TcpConn>>,
    buf: &mut [u8],
    trace_plain: bool,
) -> Result<usize, String> {
    let mut mux_seg: usize = 0;
    loop {
        // 1. Always drain decrypted plaintext FIRST. iOS lockdownd often delivers multiple
        //    back-to-back TLS records (e.g. pcapd bursts) inside a single mux segment, and rustls
        //    enforces a 16 KiB plaintext-buffer cap (`MAX_PLAINTEXT_SIZE`). If we feed the whole
        //    segment before draining, the next `read_tls` returns `received plaintext buffer
        //    full`. Reading first short-circuits this for free whenever there's anything ready.
        let mut r = tls.reader();
        match r.read(buf) {
            Ok(n) if n > 0 => {
                if trace_plain {
                    log_tls_application_cleartext("RX", "service", &buf[..n]);
                }
                return Ok(n);
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(format!("rustls plaintext read: {}", e)),
        }
        drop(r);
        if !tls.wants_read() {
            return Err(
                "rustls: service plaintext WouldBlock but connection does not want_read".into(),
            );
        }

        // 2. Pull the next ciphertext bytes. Prefer leftovers from a previous segment (the
        //    pending-TLS-in stash) over a fresh USB read so ciphertext order is preserved.
        let mut chunk: Vec<u8> = std::mem::take(&mut tcp.borrow_mut().pending_tls_in);
        if chunk.is_empty() {
            chunk = {
                let mut h = hub.borrow_mut();
                let mut t = tcp.borrow_mut();
                h.recv_tcp_payload_for(&mut *t)?
            };
            if chunk.is_empty() {
                return Err("service TLS: empty mux segment".into());
            }
        }

        // 3. Feed it incrementally, draining plaintext between each `read_tls` so we never blow
        //    past `MAX_PLAINTEXT_SIZE`. Whatever rustls couldn't accept goes back on the stash
        //    and the next loop iteration will retry after the caller drains via step (1).
        let consumed = feed_tls_from_tcp_segment_incremental(
            tls,
            &chunk,
            trace_plain,
            "service-app-read",
            mux_seg,
        )?;
        if consumed < chunk.len() {
            tcp.borrow_mut().pending_tls_in = chunk[consumed..].to_vec();
        }
        mux_seg = mux_seg.saturating_add(1);
    }
}

/// Feed `chunk` into rustls one record at a time, stopping early when rustls's plaintext buffer
/// is full so the caller can drain with `tls.reader().read(...)`. Returns the number of bytes
/// actually consumed from `chunk`; the remainder belongs back on `TcpConn::pending_tls_in`.
fn feed_tls_from_tcp_segment_incremental(
    conn: &mut ClientConnection,
    chunk: &[u8],
    debug: bool,
    phase: &str,
    seg_idx: usize,
) -> Result<usize, String> {
    if debug {
        crate::console_log!(
            "[lockdown] {} feed segment[{}]: {} bytes, first bytes [{}] ({})",
            phase,
            seg_idx,
            chunk.len(),
            hex_prefix(chunk, 32),
            first_byte_note(chunk.first().copied())
        );
    }
    let mut cur = Cursor::new(chunk);
    while (cur.position() as usize) < chunk.len() {
        let pos_before = cur.position();
        let n = match conn.read_tls(&mut cur) {
            Ok(n) => n,
            Err(e) if is_plaintext_buffer_full(&e) => {
                // rustls is telling us "drain plaintext before giving me more ciphertext".
                // Return what we consumed; caller will drain in step (1) and resume.
                if debug {
                    crate::console_log!(
                        "[lockdown] {} segment[{}]: rustls plaintext buffer full at {}/{}, deferring tail",
                        phase,
                        seg_idx,
                        pos_before,
                        chunk.len()
                    );
                }
                return Ok(pos_before as usize);
            }
            Err(e) => return Err(format!("rustls read_tls: {}", e)),
        };
        if let Err(e) = conn.process_new_packets() {
            return Err(tls_io_err_hint(chunk, e));
        }
        if debug && n > 0 {
            crate::console_log!(
                "[lockdown] {} read_tls consumed {} bytes from segment[{}] (cursor {}/{})",
                phase,
                n,
                seg_idx,
                cur.position(),
                chunk.len()
            );
        }
        if n == 0 && cur.position() == pos_before {
            return Err(format!(
                "rustls read_tls made no progress ({} bytes left in TCP segment)",
                chunk.len() - pos_before as usize
            ));
        }
        // After each successful record feed, peek at decrypted state: if rustls now has
        // plaintext queued, stop and let the caller drain it before pumping more ciphertext.
        if conn.process_new_packets().is_ok()
            && (cur.position() as usize) < chunk.len()
            && plaintext_buffer_at_cap(conn)
        {
            if debug {
                crate::console_log!(
                    "[lockdown] {} segment[{}]: deferring {} bytes (plaintext queue near cap)",
                    phase,
                    seg_idx,
                    chunk.len() - cur.position() as usize
                );
            }
            return Ok(cur.position() as usize);
        }
    }
    Ok(chunk.len())
}

/// rustls 0.23 surfaces this case as `io::Error::other("received plaintext buffer full")`. We
/// match by message because it's the documented public contract; keeping the substring loose
/// future-proofs against minor wording tweaks (`"plaintext buffer full"` etc.).
fn is_plaintext_buffer_full(e: &std::io::Error) -> bool {
    let s = e.to_string();
    s.contains("plaintext buffer full") || s.contains("plaintext buffer is full")
}

/// Heuristic: stop feeding ciphertext when rustls already has at least `~14 KiB` of decrypted
/// plaintext queued. We can't query rustls's exact buffer fill on stable, but
/// `process_new_packets()`'s `IoState::plaintext_bytes_to_read()` is close enough — and we leave
/// 2 KiB headroom under the documented 16 KiB cap to avoid a hard rejection on the next record.
fn plaintext_buffer_at_cap(conn: &mut ClientConnection) -> bool {
    match conn.process_new_packets() {
        Ok(state) => state.plaintext_bytes_to_read() >= 14 * 1024,
        Err(_) => false, // Real errors are surfaced by the caller; treat unknown as "keep going".
    }
}
