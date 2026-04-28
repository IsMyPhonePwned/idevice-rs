//! WebAssembly + **WebUSB**: Apple mux, pseudo-TCP to **lockdownd**, cleartext lockdown, and optional **rustls**
//! lockdown TLS when a **full** XML pair-record plist (PEM keys) is provided — same idea as the native `idevice` crate.
//!
//! Progress is logged to the browser **`console`** with prefix **`[idevice-wasm]`** (`info` / `warn`, plus
//! **`debug`** when **`verbose`** is true).

use wasm_bindgen::prelude::*;

mod afc_wasm;
mod crash_reports_wasm;
mod lockdown_tls_wasm;
mod lockdown_wasm;
mod mux_probe;
mod pair_record_plist;
mod screenshotr_wasm;
mod syslog_wasm;
mod wasm_crypto;
mod wasm_log;
mod web_usb;
mod web_usb_mux_hub;
mod web_usb_session;

/// One-time panic hook → `console.error` (helps debug WASM panics in DevTools).
#[wasm_bindgen(start)]
pub fn wasm_start_hook() {
    console_error_panic_hook::set_once();
}
