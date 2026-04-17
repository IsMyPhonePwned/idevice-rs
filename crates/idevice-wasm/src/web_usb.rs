use idevice_usb_core::{
    APPLE_VENDOR_CLASS, APPLE_VENDOR_SUBCLASS, SELECT_CONFIGURATION_FAILED_LINUX_HINT,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
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
pub async fn request_apple_device() -> Result<UsbDevice, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let usb: Usb = window.navigator().usb();
    let filter = UsbDeviceFilter::new();
    filter.set_vendor_id(0x05ac);
    let opts = UsbDeviceRequestOptions::new(&[filter]);
    let p = usb.request_device(&opts);
    let dev = JsFuture::from(p).await?;
    dev.dyn_into::<UsbDevice>().map_err(|e| JsValue::from(e))
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

/// `open` → **`selectConfiguration`** (try each descriptor that has the Apple mux interface) →
/// **`claimInterface`** → **`selectAlternateInterface`** → **`clearHalt`** on bulk endpoints.
pub async fn prepare_apple_usb(device: &UsbDevice) -> Result<AppleEndpoints, JsValue> {
    if !device.opened() {
        JsFuture::from(device.open())
            .await
            .map_err(|e| JsValue::from_str(&format!("USB open: {}", js_err(&e))))?;
    }

    let cfgs = device.configurations();
    let n = cfgs.length();
    let mut last_cfg_err = JsValue::UNDEFINED;

    for i in 0..n {
        let cfg = cfgs
            .get(i)
            .dyn_into::<UsbConfiguration>()
            .map_err(|_| JsValue::from_str("USBConfiguration expected"))?;
        let Some((iface_num, alt_setting, eps)) = scan_config_for_apple_mux(&cfg) else {
            continue;
        };
        let cv = cfg.configuration_value();
        if JsFuture::from(device.select_configuration(cv))
            .await
            .is_err()
        {
            last_cfg_err = JsValue::from_str(&format!(
                "selectConfiguration({cv}) failed — {}",
                SELECT_CONFIGURATION_FAILED_LINUX_HINT
            ));
            continue;
        }

        let _ = JsFuture::from(device.release_interface(iface_num)).await;
        if let Err(e) = JsFuture::from(device.claim_interface(iface_num)).await {
            last_cfg_err = e;
            continue;
        }
        if let Err(e) =
            JsFuture::from(device.select_alternate_interface(iface_num, alt_setting)).await
        {
            last_cfg_err = e;
            continue;
        }
        for (dir, epn) in [
            (UsbDirection::Out, eps.ep_out),
            (UsbDirection::In, eps.ep_in),
        ] {
            let _ = JsFuture::from(device.clear_halt(dir, epn)).await;
        }
        return Ok(eps);
    }

    Err(JsValue::from_str(&format!(
        "Could not open Apple usbmux interface: {}",
        js_err(&last_cfg_err)
    )))
}
