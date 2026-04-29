use idevice_usb_core::{
    APPLE_VENDOR_CLASS, APPLE_VENDOR_SUBCLASS, SELECT_CONFIGURATION_FAILED_LINUX_HINT,
    WEBUSB_CHROMIUM_USB_BUSY_EXPLAINER,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::wasm_log;
use web_sys::{
    Usb, UsbAlternateInterface, UsbConfiguration, UsbDevice, UsbDeviceFilter,
    UsbDeviceRequestOptions, UsbDirection, UsbEndpoint, UsbEndpointType, UsbInterface,
};

#[derive(Clone, Copy, Debug)]
pub struct AppleEndpoints {
    pub ep_out: u8,
    pub ep_in: u8,
}

/// `navigator.usb.requestDevice` with Apple **VID 0x05ac** (must run from a user gesture).
///
/// Fails with a human-friendly diagnostic when `navigator.usb` isn't accessible — the WebUSB
/// API is only exposed in a [secure context](https://developer.mozilla.org/docs/Web/Security/Secure_Contexts)
/// (HTTPS or `localhost`/`127.0.0.1`) on Chromium-based browsers, so users hitting this from
/// `file://` or Firefox/Safari otherwise saw an opaque `Cannot read properties of undefined`
/// crash deep in the wasm-bindgen runtime.
#[wasm_bindgen(js_name = requestAppleDevice)]
pub async fn request_apple_device() -> Result<UsbDevice, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    // `Navigator.usb` is a getter that returns `undefined` on unsupported / non-secure contexts.
    // Crucially, web_sys still hands us back a `Usb` wrapper around `undefined` instead of
    // panicking — calling `.request_device()` on it then throws inside the JS binding. Inspect
    // the raw JsValue first so we can return a clear error.
    let nav = window.navigator();
    let usb_jsv: JsValue = js_sys::Reflect::get(nav.as_ref(), &JsValue::from_str("usb"))
        .map_err(|_| JsValue::from_str("WebUSB unavailable: failed to read navigator.usb"))?;
    if usb_jsv.is_undefined() || usb_jsv.is_null() {
        return Err(JsValue::from_str(diagnose_no_webusb()));
    }
    let usb: Usb = nav.usb();
    let filter = UsbDeviceFilter::new();
    filter.set_vendor_id(0x05ac);
    let opts = UsbDeviceRequestOptions::new(&[filter]);
    let p = usb.request_device(&opts);
    let dev = JsFuture::from(p).await?;
    dev.dyn_into::<UsbDevice>().map_err(JsValue::from)
}

/// Build a one-line explanation of *why* `navigator.usb` is missing — secure-context, browser
/// engine, or extension policy. Pure JS introspection so it works even without a WebUSB stack.
fn diagnose_no_webusb() -> &'static str {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return "WebUSB unavailable: no `window` (running outside a browser?).",
    };
    // `window.isSecureContext` — false for plain `http://` or `file://` (except `localhost`).
    let is_secure = js_sys::Reflect::get(window.as_ref(), &JsValue::from_str("isSecureContext"))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if !is_secure {
        return "WebUSB unavailable: this page must be served from a secure context — \
                use https:// or http://localhost (e.g. `bash scripts/serve.sh`). \
                file:// and plain http:// over LAN are blocked by the browser.";
    }
    let ua = js_sys::Reflect::get(window.navigator().as_ref(), &JsValue::from_str("userAgent"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
        .to_lowercase();
    if ua.contains("firefox") {
        return "WebUSB unavailable: Firefox does not implement the WebUSB API. \
                Use Chrome / Edge / Brave / Arc / Opera over HTTPS or localhost.";
    }
    if ua.contains("safari") && !ua.contains("chrome") && !ua.contains("chromium") {
        return "WebUSB unavailable: Safari does not implement the WebUSB API. \
                Use Chrome / Edge / Brave / Arc / Opera over HTTPS or localhost.";
    }
    "WebUSB unavailable: `navigator.usb` is missing. Most likely an enterprise USB policy or \
     a browser extension is blocking it; check `chrome://flags`, the Permissions Policy, and \
     try a fresh user profile."
}

fn scan_config_for_apple_mux(cfg: &UsbConfiguration) -> Option<(u8, u8, AppleEndpoints)> {
    let ifaces = cfg.interfaces();
    let n = ifaces.length();
    for i in 0..n {
        let Ok(iface) = ifaces.get(i).dyn_into::<UsbInterface>() else {
            continue;
        };
        let alts = iface.alternates();
        let na = alts.length();
        for j in 0..na {
            let Ok(alt) = alts.get(j).dyn_into::<UsbAlternateInterface>() else {
                continue;
            };
            if alt.interface_class() != APPLE_VENDOR_CLASS
                || alt.interface_subclass() != APPLE_VENDOR_SUBCLASS
            {
                continue;
            }
            let mut ep_out = None;
            let mut ep_in = None;
            let eps = alt.endpoints();
            let ne = eps.length();
            for k in 0..ne {
                let Ok(ep) = eps.get(k).dyn_into::<UsbEndpoint>() else {
                    continue;
                };
                if ep.type_() != UsbEndpointType::Bulk {
                    continue;
                }
                match ep.direction() {
                    UsbDirection::Out => ep_out = Some(ep.endpoint_number()),
                    UsbDirection::In => ep_in = Some(ep.endpoint_number()),
                    _ => {}
                }
            }
            if let (Some(o), Some(i)) = (ep_out, ep_in) {
                return Some((
                    iface.interface_number(),
                    alt.alternate_setting(),
                    AppleEndpoints {
                        ep_out: o,
                        ep_in: i,
                    },
                ));
            }
        }
    }
    None
}

fn js_err(v: &JsValue) -> String {
    v.as_string()
        .or_else(|| {
            js_sys::Reflect::get(v, &JsValue::from_str("message"))
                .ok()
                .and_then(|m| m.as_string())
        })
        .unwrap_or_else(|| format!("{v:#?}"))
}

fn linux_webusb_busy_help() -> String {
    format!(
        "{}{}",
        SELECT_CONFIGURATION_FAILED_LINUX_HINT, WEBUSB_CHROMIUM_USB_BUSY_EXPLAINER
    )
}

/// Enumerate `(bConfigurationValue, iface, alternate, endpoints)` for every configuration that exposes the Apple mux iface.
fn enumerate_apple_mux_candidates(device: &UsbDevice) -> Result<Vec<(u8, u8, u8, AppleEndpoints)>, JsValue> {
    let cfgs = device.configurations();
    let n = cfgs.length();
    let mut out = Vec::new();
    for i in 0..n {
        let cfg = cfgs
            .get(i)
            .dyn_into::<UsbConfiguration>()
            .map_err(|_| JsValue::from_str("USBConfiguration expected"))?;
        let cv = cfg.configuration_value();
        if let Some((iface_num, alt_setting, eps)) = scan_config_for_apple_mux(&cfg) {
            out.push((cv, iface_num, alt_setting, eps));
        }
    }
    if out.is_empty() {
        return Err(JsValue::from_str(
            "No Apple usbmux interface (class 255 / subclass 254 + bulk IN/OUT) found",
        ));
    }
    Ok(out)
}

/// If nothing is selected after `open()`, issue a best-effort USB reset (matches usbmuxd-rs / lab bring-up).
async fn try_reset_if_no_configuration(device: &UsbDevice) {
    if device.configuration().is_none() {
        wasm_log::info("USB: no active configuration after open — best-effort device.reset()");
        let _ = JsFuture::from(device.reset()).await;
    }
}

/// `open` → optional **reset** → **`selectConfiguration`** (preferred mux config first, then others) →
/// **`claimInterface`** → **`clearHalt`** on both bulk ends → **`selectAlternateInterface`**.
///
/// Ordering follows the WASM lab in `usbmux` + `lockdown` setup (preferred configuration first like
/// `select_usb_configuration_with_fallback`, then claim / clear-halt / alternate).
pub async fn prepare_apple_usb(device: &UsbDevice) -> Result<AppleEndpoints, JsValue> {
    wasm_log::info("USB: prepare_apple_usb — start");
    if !device.opened() {
        wasm_log::info("USB: calling device.open()…");
        JsFuture::from(device.open())
            .await
            .map_err(|e| JsValue::from_str(&format!("USB open: {}", js_err(&e))))?;
        wasm_log::info("USB: device.open() OK");
    } else {
        wasm_log::info("USB: device already opened");
    }

    try_reset_if_no_configuration(device).await;

    let mut candidates = enumerate_apple_mux_candidates(device)?;
    wasm_log::info(&format!(
        "USB: found {} configuration(s) with Apple mux (255/254)",
        candidates.len()
    ));
    let preferred_cv = candidates[0].0;
    candidates.sort_by_key(|(cv, _, _, _)| (*cv != preferred_cv, *cv));

    let help = linux_webusb_busy_help();
    let mut last_cfg_err = JsValue::UNDEFINED;

    for (cv, iface_num, alt_setting, eps) in candidates {
        wasm_log::info(&format!(
            "USB: trying configuration {cv}, iface {iface_num}, alt {alt_setting}, bulk out/in {}/{}",
            eps.ep_out, eps.ep_in
        ));
        if let Err(e) = JsFuture::from(device.select_configuration(cv)).await {
            last_cfg_err = JsValue::from_str(&format!(
                "selectConfiguration({cv}): {}{}",
                js_err(&e),
                help
            ));
            continue;
        }

        let _ = JsFuture::from(device.release_interface(iface_num)).await;
        if let Err(e) = JsFuture::from(device.claim_interface(iface_num)).await {
            last_cfg_err = JsValue::from_str(&format!(
                "claimInterface({iface_num}): {}{}",
                js_err(&e),
                help
            ));
            continue;
        }

        for (dir, epn) in [
            (UsbDirection::Out, eps.ep_out),
            (UsbDirection::In, eps.ep_in),
        ] {
            let _ = JsFuture::from(device.clear_halt(dir, epn)).await;
        }

        if let Err(e) =
            JsFuture::from(device.select_alternate_interface(iface_num, alt_setting)).await
        {
            last_cfg_err = JsValue::from_str(&format!(
                "selectAlternateInterface({iface_num}, {alt_setting}): {}{}",
                js_err(&e),
                help
            ));
            continue;
        }

        wasm_log::info("USB: Apple mux interface ready (configuration + claim + alternate + clearHalt)");
        return Ok(eps);
    }

    wasm_log::warn(&format!(
        "USB: failed to open mux interface — last error: {}",
        js_err(&last_cfg_err)
    ));
    Err(JsValue::from_str(&format!(
        "Could not open Apple usbmux interface: {}",
        js_err(&last_cfg_err)
    )))
}
