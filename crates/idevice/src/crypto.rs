use std::sync::Arc;

use rcgen::{
    Certificate, CertificateParams, CustomExtension, DistinguishedName, Error, IsCa, KeyPair,
    KeyUsagePurpose, RemoteKeyPair, SignatureAlgorithm,
};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::{RsaPrivateKey, RsaPublicKey};

#[derive(Clone)]
pub struct HostKeys {
    pub private_key_pem: String,
    pub host_cert_pem: String,
    pub root_cert_pem: String,
    pub root_private_pem: String,
    pub host_cert_der: Vec<u8>,
    pub root_cert_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub root_private_der: Vec<u8>,
    /// In-memory root CA only for **generated** keys (signing the device leaf in [`build_device_certificate`]).
    /// **`None`** for plist-loaded keys (TLS uses PEM/DER only; libimobiledevice roots may use signature OIDs rcgen cannot parse).
    root_ca: Option<Arc<Certificate>>,
}

impl HostKeys {
    /// `true` if this bundle can sign a **device** leaf for **`Pair`** (not available for plist-loaded keys).
    pub fn can_sign_device_leaf(&self) -> bool {
        self.root_ca.is_some()
    }
}

fn generate_rsa_keypair() -> Result<(KeyPair, String, Vec<u8>), String> {
    let mut rng = rand::thread_rng();
    let rsa_key =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("RSA generation error: {}", e))?;
    let private_pem = rsa_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("PEM encoding error: {}", e))?
        .to_string();
    let private_der = rsa_key
        .to_pkcs8_der()
        .map_err(|e| format!("DER encoding error: {}", e))?
        .as_bytes()
        .to_vec();
    let key_pair = KeyPair::from_pem(&private_pem)
        .map_err(|e| format!("Failed to parse PEM into KeyPair: {:?}", e))?;
    Ok((key_pair, private_pem, private_der))
}

/// PKCS#1 RSA + SHA-256, matching pymobiledevice3 / libimobiledevice for iOS ≥ 4.
fn cert_alg() -> &'static SignatureAlgorithm {
    &rcgen::PKCS_RSA_SHA256
}

fn sha256_cert_prefix(der: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, der);
    let h = d.as_ref();
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

/// id-ce-basicConstraints (2.5.29.19), end-entity: **empty `SEQUENCE`** (`30 00`) — **cryptography** /
/// **pymobiledevice3** `BasicConstraints(ca=False)`.
const BASIC_CONSTRAINTS_END_ENTITY_DER: &[u8] = &[0x30, 0x00];
/// Same extension, **CA** root: `SEQUENCE { cA BOOLEAN TRUE }` (`30 03 01 01 ff`) — **pymobiledevice3** root has
/// **only** this (no SubjectKeyIdentifier). rcgen’s `IsCa::Ca` adds an SKI Apple may reject during `Pair` validation.
const BASIC_CONSTRAINTS_CA_DER: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0xFF];
const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
/// id-ce-subjectKeyIdentifier (2.5.29.14); extnValue is **`OCTET STRING`** (`04 14` + 20 bytes) per RFC 5280.
const OID_SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];

/// Root + host + device certs shaped like [`pymobiledevice3.ca`](https://github.com/doronz88/pymobiledevice3/blob/master/pymobiledevice3/ca.py):
/// empty DNs, serial **1** on each cert, root **BC-only CA** (custom ext, no SKI), host leaf **KU + BC** (custom ext),
/// device leaf **KU + BC + SKI** (custom exts) with SKI = **SHA-1(PKCS#1 RSAPublicKey DER)** like **cryptography**.
pub fn generate_host_keys() -> Result<HostKeys, String> {
    crate::console_log!(
        "[crypto] Generating Root and Host RSA-2048 Keys (pymobiledevice3-style chain)…"
    );
    let (root_key_pair, root_private_pem, root_private_der) = generate_rsa_keypair()?;
    let (host_key_pair, private_pem, private_der) = generate_rsa_keypair()?;

    let mut root_params = CertificateParams::default();
    root_params.distinguished_name = DistinguishedName::new();
    root_params.alg = cert_alg();
    root_params.serial_number = Some(1u64.into());
    root_params.is_ca = IsCa::NoCa;
    root_params.key_usages = Vec::new();
    let mut root_bc =
        CustomExtension::from_oid_content(OID_BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_CA_DER.to_vec());
    root_bc.set_criticality(true);
    root_params.custom_extensions.push(root_bc);
    root_params.key_pair = Some(root_key_pair);
    let root_cert =
        Certificate::from_params(root_params).map_err(|e| format!("Root cert fail: {:?}", e))?;
    let root_cert_pem = root_cert
        .serialize_pem()
        .map_err(|e| format!("Root PEM fail: {:?}", e))?;
    let root_cert_der = root_cert
        .serialize_der()
        .map_err(|e| format!("Root DER fail: {:?}", e))?;

    let mut host_params = CertificateParams::default();
    host_params.distinguished_name = DistinguishedName::new();
    host_params.alg = cert_alg();
    host_params.serial_number = Some(1u64.into());
    host_params.is_ca = IsCa::NoCa;
    host_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    let mut host_bc = CustomExtension::from_oid_content(
        OID_BASIC_CONSTRAINTS,
        BASIC_CONSTRAINTS_END_ENTITY_DER.to_vec(),
    );
    host_bc.set_criticality(true);
    host_params.custom_extensions.push(host_bc);
    host_params.key_pair = Some(host_key_pair);
    let host_cert =
        Certificate::from_params(host_params).map_err(|e| format!("Host cert fail: {:?}", e))?;

    let host_cert_pem = host_cert
        .serialize_pem_with_signer(&root_cert)
        .map_err(|e| format!("Host PEM fail: {:?}", e))?;
    let host_cert_der = host_cert
        .serialize_der_with_signer(&root_cert)
        .map_err(|e| format!("Host DER fail: {:?}", e))?;

    let keys = HostKeys {
        private_key_pem: private_pem,
        host_cert_pem,
        root_cert_pem,
        root_private_pem,
        host_cert_der,
        root_cert_der,
        private_key_der: private_der,
        root_private_der,
        root_ca: Some(Arc::new(root_cert)),
    };
    if crate::diagnostic_trace_enabled() {
        crate::console_log!(
            "[crypto] Generated host chain: host_cert_sha256[0:8]={} host_der={}B root_der={}B",
            sha256_cert_prefix(&keys.host_cert_der),
            keys.host_cert_der.len(),
            keys.root_cert_der.len()
        );
    }
    Ok(keys)
}

struct IPhonePubKey(Vec<u8>);
impl RemoteKeyPair for IPhonePubKey {
    fn public_key(&self) -> &[u8] {
        &self.0
    }
    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::RingUnspecified)
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        cert_alg()
    }
}

pub fn build_device_certificate(
    iphone_pub_key_pem: &str,
    keys: &HostKeys,
) -> Result<String, String> {
    crate::console_log!("[crypto] Parsing iPhone Public Key...");
    let device_pub = RsaPublicKey::from_public_key_pem(iphone_pub_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(iphone_pub_key_pem))
        .map_err(|e| format!("Failed to parse iPhone Public Key: {:?}", e))?;

    let spki_der = device_pub
        .to_public_key_der()
        .map_err(|e| format!("Failed to create SPKI DER: {:?}", e))?;
    let spki_len = spki_der.as_bytes().len();
    let dummy_keypair = KeyPair::from_remote(Box::new(IPhonePubKey(spki_der.into_vec())))
        .map_err(|e| format!("Failed to wrap iPhone key: {:?}", e))?;

    let mut device_params = CertificateParams::default();
    device_params.distinguished_name = DistinguishedName::new();
    device_params.alg = cert_alg();
    device_params.serial_number = Some(1u64.into());
    device_params.is_ca = IsCa::NoCa;
    let pkcs1_der = device_pub
        .to_pkcs1_der()
        .map_err(|e| format!("Device PKCS#1 DER (for SKI): {:?}", e))?;
    let ski = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        pkcs1_der.as_bytes(),
    );
    let mut device_bc = CustomExtension::from_oid_content(
        OID_BASIC_CONSTRAINTS,
        BASIC_CONSTRAINTS_END_ENTITY_DER.to_vec(),
    );
    device_bc.set_criticality(true);
    device_params.custom_extensions.push(device_bc);
    let mut ski_der = Vec::with_capacity(2 + 20);
    ski_der.extend_from_slice(&[0x04, 0x14]);
    ski_der.extend_from_slice(ski.as_ref());
    let mut device_ski = CustomExtension::from_oid_content(OID_SUBJECT_KEY_IDENTIFIER, ski_der);
    device_ski.set_criticality(false);
    device_params.custom_extensions.push(device_ski);
    device_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    device_params.key_pair = Some(dummy_keypair);
    let device_cert = Certificate::from_params(device_params)
        .map_err(|e| format!("Device cert fail: {:?}", e))?;

    let root_ca = keys.root_ca.as_ref().ok_or_else(|| {
        "cannot build device certificate from a plist-loaded pair record (no rcgen root CA); use generated keys for `Pair`"
            .to_string()
    })?;
    let pem = device_cert
        .serialize_pem_with_signer(root_ca.as_ref())
        .map_err(|e| format!("Failed to sign device cert: {:?}", e))?;
    if crate::diagnostic_trace_enabled() {
        crate::console_log!(
            "[crypto] Device leaf PEM: {} bytes (device SPKI {} bytes)",
            pem.len(),
            spki_len
        );
    }
    Ok(pem)
}

fn first_pem_certificate_der(pem_text: &str) -> Result<Vec<u8>, String> {
    for entry in pem::parse_many(pem_text).map_err(|e| format!("PEM parse: {}", e))? {
        if entry.tag() == "CERTIFICATE" {
            return Ok(entry.into_contents());
        }
    }
    Err("no PEM CERTIFICATE block found".into())
}

/// Build [`HostKeys`] from a **libimobiledevice** / **usbmuxd** pairing record (e.g. `/var/lib/lockdown/<UDID>.plist`).
/// Used for **`StartSession` + TLS** without re-pairing. **`--lockdown-tls-client-auth root`** often matches OpenSSL-style records.
pub fn host_keys_from_pair_record_pems(
    host_private_pem: String,
    host_cert_pem: String,
    root_cert_pem: String,
    root_private_pem: String,
) -> Result<HostKeys, String> {
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

    let keys = HostKeys {
        private_key_pem: host_private_pem,
        host_cert_pem,
        root_cert_pem,
        root_private_pem,
        host_cert_der,
        root_cert_der,
        private_key_der,
        root_private_der,
        root_ca: None,
    };
    if crate::diagnostic_trace_enabled() {
        crate::console_log!(
            "[crypto] Loaded HostKeys from pair record: host_cert_der={}B root_cert_der={}B host_priv_der={}B root_priv_der={}B | host_cert_sha256[0:8]={}",
            keys.host_cert_der.len(),
            keys.root_cert_der.len(),
            keys.private_key_der.len(),
            keys.root_private_der.len(),
            sha256_cert_prefix(&keys.host_cert_der)
        );
    }
    Ok(keys)
}
