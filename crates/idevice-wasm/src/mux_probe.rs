//! WebUSB mux + pseudo-TCP to lockdownd (port **62078**). See **`web_usb_session`** for cleartext lockdown.

use idevice_usb_core::lockdown_proto::LOCKDOWND_PORT;
use wasm_bindgen::prelude::*;
use web_sys::UsbDevice;

use crate::wasm_log;
use crate::web_usb::{prepare_apple_usb, request_apple_device};
use crate::web_usb_session::WebUsbLockdownPipe;

/// Request an Apple USB device (picker) and complete mux **VERSION** (+ **SETUP**) + TCP handshake to **lockdownd**.
/// **`verbose`**: log mux/TCP framing to the browser **`console`** (same spirit as `--lockdown-tls-debug` on the host).
#[wasm_bindgen(js_name = muxLockdownHandshakePickDevice)]
pub async fn mux_lockdown_handshake_pick_device(verbose: bool) -> Result<String, JsValue> {
    let dev = request_apple_device().await?;
    mux_lockdown_handshake(dev, verbose).await
}

/// After **`requestAppleDevice()`**, run mux + TCP handshake to **lockdownd**.
#[wasm_bindgen(js_name = muxLockdownHandshake)]
pub async fn mux_lockdown_handshake(device: UsbDevice, verbose: bool) -> Result<String, JsValue> {
    wasm_log::info("mux handshake: prepare_apple_usb…");
    let eps = prepare_apple_usb(&device).await?;
    wasm_log::info("mux handshake: WebUsbLockdownPipe::connect (VERSION, SETUP?, TCP to lockdownd)…");
    let pipe = WebUsbLockdownPipe::connect(&device, eps, verbose).await?;
    Ok(format!(
        "mux v{} — pseudo-TCP to lockdownd port {} OK (cleartext path ready).",
        pipe.mux_version(),
        LOCKDOWND_PORT
    ))
}
