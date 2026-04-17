//! WebAssembly + **WebUSB** entry: Apple mux **VERSION** (+ **SETUP** for mux v2) and pseudo-**TCP**
//! **SYN → SYN-ACK → ACK** to **lockdownd** (port **62078**), sharing **`iphone-usb-core`** with **`iphone-cli`**.
//!
//! Full pairing / TLS / diagnostics stay in the native CLI; the browser build proves the USB path
//! and mux framing in Chromium (secure context + WebUSB permission).

use wasm_bindgen::prelude::*;

mod mux_probe;
mod web_usb;

/// One-time panic hook → `console.error` (helps debug WASM panics in DevTools).
#[wasm_bindgen(start)]
pub fn wasm_start_hook() {
    console_error_panic_hook::set_once();
}

/// `navigator.usb.requestDevice` (Apple VID **0x05ac**). Call from a **click** handler.
#[wasm_bindgen(js_name = requestAppleDevice)]
pub async fn request_apple_device_js() -> Result<web_sys::UsbDevice, JsValue> {
    web_usb::request_apple_device().await
}
