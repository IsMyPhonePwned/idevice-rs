//! Always-on and **verbose**-gated lines to the browser **`console`** (`[idevice-wasm]` prefix).

use wasm_bindgen::JsValue;
use web_sys::console;

#[inline]
pub fn info(msg: &str) {
    console::log_1(&JsValue::from_str(&format!("[idevice-wasm] {msg}")));
}

#[inline]
pub fn warn(msg: &str) {
    console::warn_1(&JsValue::from_str(&format!("[idevice-wasm] {msg}")));
}

#[inline]
pub fn debug_verbose(verbose: bool, msg: &str) {
    if verbose {
        console::debug_1(&JsValue::from_str(&format!("[idevice-wasm] {msg}")));
    }
}
