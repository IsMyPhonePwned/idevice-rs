//! Host keys for WASM lockdown TLS + `Pair` — same pymobiledevice3-style chain as `idevice::crypto`.
//!
//! Two entry points:
//! - [`generate_host_keys`] builds a fresh root / host / device chain (with an in-memory `rcgen::Certificate`
//!   root CA we can later use to **sign the device leaf** inside [`build_device_certificate`]).
//! - [`host_keys_from_pair_record_pems`] loads a libimobiledevice / usbmuxd pair-record (PEM) for
//!   `StartSession` + TLS only — `root_ca` is `None` because libimobiledevice roots may use OIDs rcgen
//!   cannot re-parse, and we never need to re-sign a device leaf for a plist record.

use std::sync::Arc;

use rcgen::{
    Certificate, CertificateParams, CustomExtension, DistinguishedName, Error, IsCa, KeyPair,
    KeyUsagePurpose, RemoteKeyPair, SignatureAlgorithm,
};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use time::{Duration, OffsetDateTime};

use crate::wasm_log;

/// `NotBefore` clock-skew margin — matches **pymobiledevice3** (`now - timedelta(minutes=1)`).
/// rcgen defaults `NotBefore` to **`now()`**, which sits a few seconds in the future from the
/// device's clock and can flip lockdownd to `InvalidPairRecord` right after the user taps Trust.
const PAIR_CERT_NOT_BEFORE_SKEW: Duration = Duration::minutes(1);
/// Validity span — pymobiledevice3 uses **`365 * 10` days** (`get_validity_bounds(years=10)`).
const PAIR_CERT_VALIDITY: Duration = Duration::days(365 * 10);

fn pair_cert_validity_window() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (now - PAIR_CERT_NOT_BEFORE_SKEW, now + PAIR_CERT_VALIDITY)
}

/// Host / root / device key+cert bundle used by WASM lockdown TLS and `Pair`.
#[derive(Clone)]
pub struct WasmHostKeys {
    pub private_key_pem: String,
    pub host_cert_pem: String,
    pub root_cert_pem: String,
    pub root_private_pem: String,
    pub host_cert_der: Vec<u8>,
    pub root_cert_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub root_private_der: Vec<u8>,
    /// In-memory root CA only for **generated** keys (signs the device leaf in [`build_device_certificate`]).
    /// **`None`** for plist-loaded keys (we only run TLS with PEM/DER material there).
    pub(crate) root_ca: Option<Arc<Certificate>>,
}

impl WasmHostKeys {
    /// `true` if this bundle can sign a **device** leaf for `Pair` (not available for plist-loaded keys).
    pub fn can_sign_device_leaf(&self) -> bool {
        self.root_ca.is_some()
    }
}

fn generate_rsa_keypair() -> Result<(KeyPair, String, Vec<u8>), String> {
    let mut rng = rand::thread_rng();
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| format!("RSA generation error: {}", e))?;
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

/// id-ce-basicConstraints (2.5.29.19), end-entity: empty `SEQUENCE` (`30 00`) — same DER shape as
/// Python `cryptography`'s `BasicConstraints(ca=False)`.
const BASIC_CONSTRAINTS_END_ENTITY_DER: &[u8] = &[0x30, 0x00];
/// Same extension, CA root: `SEQUENCE { cA BOOLEAN TRUE }` (`30 03 01 01 ff`).
const BASIC_CONSTRAINTS_CA_DER: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0xFF];
const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
/// id-ce-subjectKeyIdentifier (2.5.29.14); extnValue is `OCTET STRING` (`04 14` + 20 bytes) per RFC 5280.
const OID_SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];

/// Root + host chain identical to [`idevice::crypto::generate_host_keys`] (pymobiledevice3 shape):
/// empty DNs, serial **1**, root has `BasicConstraints(CA=TRUE)` only, host leaf has
/// `BC(CA=FALSE) + KeyUsage(digitalSignature, keyEncipherment)`. `NotBefore` = `now - 1 minute`,
/// `NotAfter` = `now + 10 years` — matches `pymobiledevice3.ca.get_validity_bounds()`.
pub fn generate_host_keys() -> Result<WasmHostKeys, String> {
    wasm_log::info("[crypto] Generating Root and Host RSA-2048 keys (pymobiledevice3 chain)…");
    let (root_key_pair, root_private_pem, root_private_der) = generate_rsa_keypair()?;
    let (host_key_pair, private_pem, private_der) = generate_rsa_keypair()?;

    let (not_before, not_after) = pair_cert_validity_window();

    let mut root_params = CertificateParams::default();
    root_params.distinguished_name = DistinguishedName::new();
    root_params.alg = cert_alg();
    // libimobiledevice (`common/userpref.c`) sets `ASN1_INTEGER_set(sn, 0)` for **all three**
    // pair certs. usbmuxd-saved working pair records confirm `Serial = 0`. RFC 5280 frowns on
    // serial=0 but lockdownd accepts it (and only it, on some iOS releases) — match canonically.
    root_params.serial_number = Some(0u64.into());
    root_params.is_ca = IsCa::NoCa;
    root_params.key_usages = Vec::new();
    root_params.not_before = not_before;
    root_params.not_after = not_after;
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
    host_params.serial_number = Some(0u64.into());
    host_params.is_ca = IsCa::NoCa;
    host_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    host_params.not_before = not_before;
    host_params.not_after = not_after;
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

    wasm_log::info(&format!(
        "[crypto] Host chain ready (host DER {} B, root DER {} B)",
        host_cert_der.len(),
        root_cert_der.len()
    ));

    Ok(WasmHostKeys {
        private_key_pem: private_pem,
        host_cert_pem,
        root_cert_pem,
        root_private_pem,
        host_cert_der,
        root_cert_der,
        private_key_der: private_der,
        root_private_der,
        root_ca: Some(Arc::new(root_cert)),
    })
}

/// See [`crate::wasm_crypto::IPhonePubKey`] note in the native crate: the bytes returned by
/// [`RemoteKeyPair::public_key`] become the BIT STRING content of the cert's SPKI, so they must
/// be the **raw `RSAPublicKey` DER** (PKCS#1: modulus + exponent), not a full SPKI.
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

/// Sign a **device** leaf for `Pair`. Matches `pymobiledevice3.ca.build_device_certificate`:
/// `BasicConstraints(CA=FALSE)`, `KeyUsage(digitalSignature, keyEncipherment)`, and a
/// `SubjectKeyIdentifier` = SHA-1 of the device's PKCS#1 RSAPublicKey DER.
pub fn build_device_certificate(
    iphone_pub_key_pem: &str,
    keys: &WasmHostKeys,
) -> Result<String, String> {
    let device_pub = RsaPublicKey::from_public_key_pem(iphone_pub_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(iphone_pub_key_pem))
        .map_err(|e| format!("iPhone public key: {:?}", e))?;

    let raw_pkcs1 = device_pub
        .to_pkcs1_der()
        .map_err(|e| format!("device RSAPublicKey DER: {:?}", e))?;
    let dummy_keypair =
        KeyPair::from_remote(Box::new(IPhonePubKey(raw_pkcs1.as_bytes().to_vec())))
            .map_err(|e| format!("wrap iPhone key: {:?}", e))?;

    let mut device_params = CertificateParams::default();
    device_params.distinguished_name = DistinguishedName::new();
    device_params.alg = cert_alg();
    device_params.serial_number = Some(0u64.into());
    device_params.is_ca = IsCa::NoCa;
    let (not_before, not_after) = pair_cert_validity_window();
    device_params.not_before = not_before;
    device_params.not_after = not_after;

    let pkcs1_der = device_pub
        .to_pkcs1_der()
        .map_err(|e| format!("device PKCS#1 DER: {:?}", e))?;
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
        "cannot build device certificate from a plist-loaded pair record (no rcgen root CA); \
         use generated keys for `Pair`"
            .to_string()
    })?;
    device_cert
        .serialize_pem_with_signer(root_ca.as_ref())
        .map_err(|e| format!("sign device cert: {:?}", e))
}

fn first_pem_certificate_der(pem_text: &str) -> Result<Vec<u8>, String> {
    for entry in pem::parse_many(pem_text).map_err(|e| format!("PEM parse: {}", e))? {
        if entry.tag() == "CERTIFICATE" {
            return Ok(entry.into_contents());
        }
    }
    Err("no PEM CERTIFICATE block found".into())
}

/// Build [`WasmHostKeys`] from a libimobiledevice / usbmuxd pair-record (PEM keys inside the plist).
/// Used for `StartSession` + TLS without re-pairing. `root_ca` is `None` (no device-leaf signing).
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
        private_key_pem: host_private_pem,
        host_cert_pem,
        root_cert_pem,
        root_private_pem,
        host_cert_der,
        root_cert_der,
        private_key_der,
        root_private_der,
        root_ca: None,
    })
}
