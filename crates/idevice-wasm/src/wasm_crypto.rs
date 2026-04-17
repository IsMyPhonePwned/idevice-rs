//! Pair-record PEM → DER for **rustls** client auth (same logic as `idevice::crypto::host_keys_from_pair_record_pems`).

use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};

/// DER material for lockdown TLS (host leaf + root CA + keys).
#[derive(Clone)]
pub struct WasmHostKeys {
    pub host_cert_der: Vec<u8>,
    pub root_cert_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub root_private_der: Vec<u8>,
}

fn first_pem_certificate_der(pem_text: &str) -> Result<Vec<u8>, String> {
    for entry in pem::parse_many(pem_text).map_err(|e| format!("PEM parse: {}", e))? {
        if entry.tag() == "CERTIFICATE" {
            return Ok(entry.into_contents());
        }
    }
    Err("no PEM CERTIFICATE block found".into())
}

/// Build keys from a **libimobiledevice** / **usbmuxd** pairing record (XML or binary plist parsed upstream).
pub fn host_keys_from_pair_record_pems(
    host_private_pem: String,
    host_cert_pem: String,
    root_cert_pem: String,
    root_private_pem: String,
) -> Result<WasmHostKeys, String> {
    let host_cert_der = first_pem_certificate_der(&host_cert_pem)?;
    let root_cert_der = first_pem_certificate_der(&root_cert_pem)?;

    let host_rsa = RsaPrivateKey::from_pkcs8_pem(host_private_pem.trim())
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(host_private_pem.trim()))
        .map_err(|e| format!("HostPrivateKey: {}", e))?;
    let private_key_der = host_rsa
        .to_pkcs8_der()
        .map_err(|e| format!("host PKCS#8 DER: {}", e))?
        .as_bytes()
        .to_vec();

    let root_rsa = RsaPrivateKey::from_pkcs8_pem(root_private_pem.trim())
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(root_private_pem.trim()))
        .map_err(|e| format!("RootPrivateKey: {}", e))?;
    let root_private_der = root_rsa
        .to_pkcs8_der()
        .map_err(|e| format!("root PKCS#8 DER: {}", e))?
        .as_bytes()
        .to_vec();

    Ok(WasmHostKeys {
        host_cert_der,
        root_cert_der,
        private_key_der,
        root_private_der,
    })
}
