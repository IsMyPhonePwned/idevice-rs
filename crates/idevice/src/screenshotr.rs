//! `com.apple.mobile.screenshotr` — capture a PNG/TIFF from the device.
//!
//! Mirrors `libimobiledevice/tools/idevicescreenshot.c` + `src/screenshotr.c`. The service is
//! only exposed when a **Developer Disk Image** is mounted; lockdownd otherwise rejects
//! `StartService` with `InvalidService`. The transport is the usual secondary mux pseudo-TCP
//! upgraded to **TLS** (same client certs as lockdown), then the **DeviceLink** dance:
//!
//! ```text
//! HOST                                    DEVICE
//!  ┊                              ←  DLMessageVersionExchange [400, 0]
//!  →  DLMessageVersionExchange ["DLVersionsOk", 400]
//!  ┊                              ←  DLMessageDeviceReady
//!  →  DLMessageProcessMessage { MessageType: ScreenShotRequest }
//!  ┊                              ←  DLMessageProcessMessage { MessageType: ScreenShotReply, ScreenShotData: <png> }
//!  →  DLMessageDisconnect "___EmptyParameterString___"
//! ```
//!
//! Each frame on the wire is `u32 BE length + binary plist (bplist00)` — same as
//! `property_list_service_send/receive_plist`.

use std::cell::RefCell;
use std::rc::Rc;

use rustls::ClientConnection;

use crate::crypto::HostKeys;
use crate::lockdown::LockdownClient;
use crate::lockdown_rustls::{
    handshake_service_tls, tls_read_plain_service, tls_write_plain_and_flush_service,
    LockdownTlsClientAuth, LockdownTlsSni,
};
use crate::mux_link::MuxHub;
use idevice_usb_core::screenshotr_proto::{
    build_disconnect, build_dl_versions_ok, build_screenshot_request, check_screenshotr_version,
    detect_image_extension, frame_plist_message, parse_dl_device_ready, parse_dl_version_exchange,
    parse_screenshot_reply, MAX_SCREENSHOTR_FRAME, SCREENSHOTR_SERVICE,
    SCREENSHOTR_VERSION_MAJOR,
};
use idevice_usb_core::TcpConn;

type MuxHubRc = Rc<RefCell<MuxHub>>;

/// Result of a successful capture: raw image bytes + detected extension (`png`, `tiff`, or `dat`).
pub struct Screenshot {
    pub data: Vec<u8>,
    pub extension: &'static str,
}

/// `StartSession → TLS` must already be established on `client`. Opens the secondary
/// `screenshotr` TLS service, performs the DeviceLink handshake and captures one frame.
pub fn take_screenshot(
    client: &mut LockdownClient,
    keys: &HostKeys,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
    tls_debug: bool,
) -> Result<Screenshot, String> {
    let mux = client.mux_link().ok_or(
        "screenshotr needs direct USB mux (a second pseudo-TCP to the relay port). \
         When usbmuxd holds the device, use Apple `idevicescreenshot` from libimobiledevice.",
    )?;

    let (port, ssl) = client.start_service(SCREENSHOTR_SERVICE).map_err(|e| {
        if e.contains("InvalidService") {
            format!(
                "screenshotr: lockdownd `InvalidService` — mount the Developer Disk Image first \
                 (Xcode device pane / `pymobiledevice3 mounter auto-mount`). Underlying: {}",
                e
            )
        } else {
            format!("screenshotr StartService: {}", e)
        }
    })?;
    crate::console_log!(
        "[screenshot] StartService {} → port {} EnableServiceSSL={}",
        SCREENSHOTR_SERVICE,
        port,
        ssl
    );

    if !ssl {
        return Err(
            "screenshotr: unexpected EnableServiceSSL=false; modern iOS always asks for TLS".into(),
        );
    }

    let hub = client
        .mux_hub()
        .ok_or_else(|| "screenshot: internal error (no mux hub)".to_string())?;

    let tcp = Rc::new(RefCell::new(mux.borrow().connect_service_tcp(port)?));
    let mut tls = handshake_service_tls(
        hub.clone(),
        tcp.clone(),
        keys,
        client_auth,
        tls_sni,
        tls_debug,
    )?;

    let (dev_major, dev_minor) = recv_dl_version(&mut tls, &hub, &tcp, tls_debug)?;
    crate::console_log!(
        "[screenshot] DLMessageVersionExchange — device {}.{}, host {}.0",
        dev_major,
        dev_minor,
        SCREENSHOTR_VERSION_MAJOR
    );
    check_screenshotr_version(dev_major, dev_minor)?;

    let ok = build_dl_versions_ok(SCREENSHOTR_VERSION_MAJOR)?;
    send_framed(&mut tls, &hub, &tcp, &ok, tls_debug)?;

    let ready = recv_framed(&mut tls, &hub, &tcp, tls_debug)?;
    parse_dl_device_ready(&ready)?;
    crate::console_log!("[screenshot] DLMessageDeviceReady — sending ScreenShotRequest");

    let req = build_screenshot_request()?;
    send_framed(&mut tls, &hub, &tcp, &req, tls_debug)?;

    let reply = recv_framed(&mut tls, &hub, &tcp, tls_debug)?;
    let img = parse_screenshot_reply(&reply)?;
    let extension = detect_image_extension(&img);
    crate::console_log!(
        "[screenshot] ScreenShotReply — {} bytes ({})",
        img.len(),
        extension
    );

    let bye = build_disconnect()?;
    let _ = send_framed(&mut tls, &hub, &tcp, &bye, tls_debug);

    Ok(Screenshot {
        data: img,
        extension,
    })
}

fn recv_dl_version(
    tls: &mut ClientConnection,
    hub: &MuxHubRc,
    tcp: &Rc<RefCell<TcpConn>>,
    debug: bool,
) -> Result<(u64, u64), String> {
    let bytes = recv_framed(tls, hub, tcp, debug)?;
    parse_dl_version_exchange(&bytes)
}

fn send_framed(
    tls: &mut ClientConnection,
    hub: &MuxHubRc,
    tcp: &Rc<RefCell<TcpConn>>,
    payload: &[u8],
    debug: bool,
) -> Result<(), String> {
    let frame = frame_plist_message(payload);
    tls_write_plain_and_flush_service(tls, hub, tcp, &frame, debug)?;
    Ok(())
}

fn recv_framed(
    tls: &mut ClientConnection,
    hub: &MuxHubRc,
    tcp: &Rc<RefCell<TcpConn>>,
    debug: bool,
) -> Result<Vec<u8>, String> {
    let mut acc: Vec<u8> = Vec::new();
    let mut scratch = vec![0u8; 64 * 1024];

    while acc.len() < 4 {
        read_more(tls, hub, tcp, &mut scratch, &mut acc, debug)?;
    }
    let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
    if len > MAX_SCREENSHOTR_FRAME {
        return Err(format!(
            "screenshotr: frame length {} exceeds max {} bytes",
            len, MAX_SCREENSHOTR_FRAME
        ));
    }
    while acc.len() < 4 + len {
        read_more(tls, hub, tcp, &mut scratch, &mut acc, debug)?;
    }
    let payload = acc[4..4 + len].to_vec();
    Ok(payload)
}

fn read_more(
    tls: &mut ClientConnection,
    hub: &MuxHubRc,
    tcp: &Rc<RefCell<TcpConn>>,
    scratch: &mut [u8],
    acc: &mut Vec<u8>,
    debug: bool,
) -> Result<(), String> {
    let n = tls_read_plain_service(tls, hub, tcp, scratch, debug)?;
    if n == 0 {
        return Err("screenshotr: TLS stream closed mid-frame".into());
    }
    acc.extend_from_slice(&scratch[..n]);
    Ok(())
}
