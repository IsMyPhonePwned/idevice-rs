//! Lockdownd / service TLS over mux pseudo-TCP (**rustls**), async WebUSB I/O.

use std::io::{Cursor, Read, Write};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use gloo_timers::future::sleep;
use idevice_usb_core::TcpConn;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{VerifierBuilderError, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};

use crate::wasm_crypto::WasmHostKeys;
use crate::wasm_log;
use crate::web_usb_mux_hub::WebUsbMuxHub;

/// TLS ClientHello SNI: `Device` matches jkcoxson/idevice; `None` omits SNI (IP placeholder).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum LockdownTlsSni {
    #[default]
    Device,
    None,
}

/// Which client certificate lockdownd sees (see `idevice` CLI `--lockdown-tls-client-auth`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum LockdownTlsClientAuth {
    Root,
    #[default]
    Host,
    Chain,
}

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
    keys: &WasmHostKeys,
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

fn build_client_config(
    keys: &WasmHostKeys,
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

fn tls_js_err(e: impl core::fmt::Debug) -> String {
    format!("{:?}", e)
}

async fn mux_write_all_tls_wasm(
    tls: &mut ClientConnection,
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    debug: bool,
    phase: &str,
) -> Result<usize, String> {
    let mut total = 0usize;
    let mut chunk_idx = 0usize;
    while tls.wants_write() {
        let mut buf = [0u8; 16_384];
        let n = tls
            .write_tls(&mut buf.as_mut_slice())
            .map_err(|e| format!("rustls write_tls: {}", e))?;
        if n == 0 {
            break;
        }
        total += n;
        if debug {
            wasm_log::debug_verbose(
                debug,
                &format!(
                    "[wasm-tls] {} write_tls[{}]: {} bytes",
                    phase, chunk_idx, n
                ),
            );
        }
        hub
            .send_tcp_payload_for(tcp, &buf[..n])
            .await
            .map_err(tls_js_err)?;
        chunk_idx += 1;
    }
    Ok(total)
}

fn feed_tls_from_tcp_segment(
    tls: &mut ClientConnection,
    chunk: &[u8],
    _phase: &str,
    _seg_idx: usize,
) -> Result<(), String> {
    let mut cur = Cursor::new(chunk);
    while (cur.position() as usize) < chunk.len() {
        let pos_before = cur.position();
        let n = tls
            .read_tls(&mut cur)
            .map_err(|e| format!("rustls read_tls: {}", e))?;
        if let Err(e) = tls.process_new_packets() {
            return Err(tls_io_err_hint(chunk, e));
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
            "rustls: {} (peer sent plaintext — often pairing/trust; try TLS client auth `root` or `chain`)",
            e
        );
    }
    format!("rustls: {}", e)
}

/// TLS handshake on a mux pseudo-TCP stream (lockdownd or a **StartService** port).
pub async fn handshake_tls_mux_tcp_wasm(
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    keys: &WasmHostKeys,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
    debug: bool,
) -> Result<ClientConnection, String> {
    let cfg = Arc::new(build_client_config(keys, client_auth)?);
    let name = server_name(tls_sni)?;
    let mut tls = ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;

    wasm_log::info(&format!(
        "[wasm-tls] handshake start (client_auth={:?}, sni={:?})",
        client_auth, tls_sni
    ));

    let deadline_ms = js_sys::Date::now() + 120_000.0;
    let mut iter: u32 = 0;
    while tls.is_handshaking() {
        iter += 1;
        if js_sys::Date::now() > deadline_ms {
            return Err("rustls TLS handshake timed out (120 s)".into());
        }
        if debug || iter <= 3 || iter % 10 == 0 {
            wasm_log::debug_verbose(
                debug,
                &format!(
                    "[wasm-tls] iter={} handshaking wants_read={} wants_write={}",
                    iter,
                    tls.wants_read(),
                    tls.wants_write()
                ),
            );
        }
        mux_write_all_tls_wasm(&mut tls, hub, tcp, debug, "handshake").await?;
        if !tls.is_handshaking() {
            break;
        }
        if tls.wants_read() {
            let chunk = hub.recv_tcp_payload_for(tcp).await.map_err(tls_js_err)?;
            if chunk.is_empty() {
                sleep(Duration::from_millis(50)).await;
                continue;
            }
            feed_tls_from_tcp_segment(&mut tls, &chunk, "handshake", iter as usize)?;
        } else {
            sleep(Duration::from_millis(5)).await;
        }
    }

    let _ = mux_write_all_tls_wasm(&mut tls, hub, tcp, debug, "handshake-final").await?;

    let suite = tls
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "?".into());
    wasm_log::info(&format!("[wasm-tls] OK cipher suite {}", suite));
    Ok(tls)
}

pub async fn tls_write_plain_and_flush_wasm(
    tls: &mut ClientConnection,
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    payload: &[u8],
    trace_plain: bool,
) -> Result<(), String> {
    if trace_plain {
        wasm_log::debug_verbose(trace_plain, &format!("[wasm-tls] TX plain {} bytes", payload.len()));
    }
    tls.writer()
        .write_all(payload)
        .map_err(|e| format!("rustls plaintext write: {}", e))?;
    tls.writer().flush().ok();
    let _ = mux_write_all_tls_wasm(tls, hub, tcp, trace_plain, "app-tls-record").await?;
    Ok(())
}

pub async fn tls_read_plain_wasm(
    tls: &mut ClientConnection,
    hub: &mut WebUsbMuxHub<'_>,
    tcp: &mut TcpConn,
    buf: &mut [u8],
    trace_plain: bool,
) -> Result<usize, String> {
    let mut mux_seg: usize = 0;
    loop {
        // 1. Drain decrypted plaintext FIRST. iOS lockdownd often delivers multiple back-to-back
        //    TLS records (e.g. pcapd / syslog bursts) inside a single mux segment, and rustls
        //    enforces a 16 KiB plaintext-buffer cap (`MAX_PLAINTEXT_SIZE`). Feeding the whole
        //    segment before draining causes `read_tls` to error with `received plaintext buffer
        //    full`. Reading first short-circuits this whenever there's anything ready.
        let mut r = tls.reader();
        match r.read(buf) {
            Ok(n) if n > 0 => {
                if trace_plain {
                    wasm_log::debug_verbose(trace_plain, &format!("[wasm-tls] RX plain {} bytes", n));
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
                "rustls: plaintext read WouldBlock but connection does not want_read".into(),
            );
        }

        // 2. Pull next ciphertext bytes — leftover stash takes precedence over a fresh USB read so
        //    record order is preserved across calls.
        let mut chunk: Vec<u8> = std::mem::take(&mut tcp.pending_tls_in);
        if chunk.is_empty() {
            chunk = hub.recv_tcp_payload_for(tcp).await.map_err(tls_js_err)?;
            if chunk.is_empty() {
                return Err("TLS: empty mux segment while reading".into());
            }
        }

        // 3. Feed incrementally; whatever rustls couldn't accept goes back on the stash and the
        //    next loop iteration will retry after the caller drains in step (1).
        let consumed = feed_tls_from_tcp_segment_incremental(tls, &chunk, "app-read", mux_seg)?;
        if consumed < chunk.len() {
            tcp.pending_tls_in = chunk[consumed..].to_vec();
        }
        mux_seg = mux_seg.saturating_add(1);
    }
}

/// Feed `chunk` into rustls one record at a time, stopping early when its plaintext queue is
/// near the documented 16 KiB cap so the caller can drain via `tls.reader().read(...)`. Returns
/// the number of bytes actually consumed; the remainder belongs back on `TcpConn::pending_tls_in`.
fn feed_tls_from_tcp_segment_incremental(
    tls: &mut ClientConnection,
    chunk: &[u8],
    _phase: &str,
    _seg_idx: usize,
) -> Result<usize, String> {
    let mut cur = Cursor::new(chunk);
    while (cur.position() as usize) < chunk.len() {
        let pos_before = cur.position();
        let n = match tls.read_tls(&mut cur) {
            Ok(n) => n,
            Err(e) if is_plaintext_buffer_full(&e) => {
                // rustls is asking us to drain plaintext before it accepts more ciphertext.
                return Ok(pos_before as usize);
            }
            Err(e) => return Err(format!("rustls read_tls: {}", e)),
        };
        if let Err(e) = tls.process_new_packets() {
            return Err(tls_io_err_hint(chunk, e));
        }
        if n == 0 && cur.position() == pos_before {
            return Err(format!(
                "rustls read_tls made no progress ({} bytes left in TCP segment)",
                chunk.len() - pos_before as usize
            ));
        }
        // Stop pumping once rustls has ~14 KiB of plaintext queued so the next record never trips
        // the 16 KiB cap. The caller will drain in `tls_read_plain_wasm`'s step (1).
        if (cur.position() as usize) < chunk.len() && plaintext_buffer_at_cap(tls) {
            return Ok(cur.position() as usize);
        }
    }
    Ok(chunk.len())
}

/// rustls 0.23 surfaces this case as `io::Error::other("received plaintext buffer full")`. We
/// match by message because it's the documented public contract.
fn is_plaintext_buffer_full(e: &std::io::Error) -> bool {
    let s = e.to_string();
    s.contains("plaintext buffer full") || s.contains("plaintext buffer is full")
}

/// Heuristic that mirrors the native crate: use `IoState::plaintext_bytes_to_read()` and stop
/// feeding 2 KiB before the documented cap so the next ciphertext record always fits.
fn plaintext_buffer_at_cap(tls: &mut ClientConnection) -> bool {
    match tls.process_new_packets() {
        Ok(state) => state.plaintext_bytes_to_read() >= 14 * 1024,
        Err(_) => false,
    }
}

pub fn parse_tls_client_auth(s: &str) -> LockdownTlsClientAuth {
    match s.trim().to_ascii_lowercase().as_str() {
        "root" => LockdownTlsClientAuth::Root,
        "chain" => LockdownTlsClientAuth::Chain,
        _ => LockdownTlsClientAuth::Host,
    }
}

pub fn parse_tls_sni(s: &str) -> LockdownTlsSni {
    match s.trim().to_ascii_lowercase().as_str() {
        "none" => LockdownTlsSni::None,
        _ => LockdownTlsSni::Device,
    }
}
