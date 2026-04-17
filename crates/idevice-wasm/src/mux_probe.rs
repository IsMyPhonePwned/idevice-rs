//! Async mux path mirroring **`idevice_usb_core::TcpConn::handshake_and_connect`** (no `BulkTransport` trait).

use idevice_usb_core::{
    build_mux_setup_packet_v2, build_mux_version_request, lockdown_proto::LOCKDOWND_PORT,
    parse_mux_version_response, TcpConn, READ_BUF,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{UsbDevice, UsbInTransferResult};

use crate::web_usb::{prepare_apple_usb, request_apple_device};

struct Wusb<'a> {
    dev: &'a UsbDevice,
    ep_out: u8,
    ep_in: u8,
}

impl<'a> Wusb<'a> {
    async fn bulk_out(&self, data: &[u8]) -> Result<(), JsValue> {
        let mut buf = data.to_vec();
        let p = self
            .dev
            .transfer_out_with_u8_slice(self.ep_out, &mut buf)
            .map_err(|e| e)?;
        JsFuture::from(p).await.map_err(|e| e)?;
        Ok(())
    }

    async fn bulk_in(&self, max: usize) -> Result<Vec<u8>, JsValue> {
        let p = self.dev.transfer_in(self.ep_in, max as u32);
        let res = JsFuture::from(p).await?;
        let u: UsbInTransferResult = res
            .dyn_into()
            .map_err(|_| JsValue::from_str("USBInTransferResult expected"))?;
        let Some(dv) = u.data() else {
            return Ok(Vec::new());
        };
        let len = dv.byte_length() as usize;
        let mut v = vec![0u8; len];
        if len > 0 {
            let arr = js_sys::Uint8Array::new_with_byte_offset_and_length(
                &dv.buffer(),
                dv.byte_offset() as u32,
                dv.byte_length() as u32,
            );
            arr.copy_to(&mut v);
        }
        Ok(v)
    }

    async fn handshake_to_lockdown(&self) -> Result<String, JsValue> {
        let ver = build_mux_version_request();
        self.bulk_out(ver.as_slice()).await?;
        let resp = self.bulk_in(READ_BUF).await?;
        let (major, minor) =
            parse_mux_version_response(&resp).map_err(|e| JsValue::from_str(&e))?;

        if major >= 2 {
            let setup = build_mux_setup_packet_v2();
            self.bulk_out(setup.as_slice()).await?;
        }

        let mut mux_tx_next: u16 = 1;
        let mut conn = TcpConn::new_ready_for_syn(major, LOCKDOWND_PORT);
        let syn = conn.build_mux_tcp_packet(&mut mux_tx_next, 0x02, &[]);
        self.bulk_out(&syn).await?;
        let raw = self.bulk_in(READ_BUF).await?;
        let ack = conn
            .finish_handshake_ack_packet(&raw, &mut mux_tx_next)
            .map_err(|e| JsValue::from_str(&e))?;
        self.bulk_out(&ack).await?;

        Ok(format!(
            "mux major={} minor={} — pseudo-TCP to lockdownd :{} OK (SYN/SYN-ACK/ACK). Pair/diagnostics use the `idevice` CLI or the dev server API.",
            major, minor, LOCKDOWND_PORT
        ))
    }
}

/// Request an Apple USB device (picker) and run mux **VERSION** (+ **SETUP**) + TCP handshake to **lockdownd**.
#[wasm_bindgen(js_name = muxLockdownHandshakePickDevice)]
pub async fn mux_lockdown_handshake_pick_device() -> Result<String, JsValue> {
    let dev = request_apple_device().await?;
    mux_lockdown_handshake(dev).await
}

/// After **`requestAppleDevice()`** in JS (or prior picker), run the mux + TCP handshake.
#[wasm_bindgen(js_name = muxLockdownHandshake)]
pub async fn mux_lockdown_handshake(device: UsbDevice) -> Result<String, JsValue> {
    let eps = prepare_apple_usb(&device).await?;
    let w = Wusb {
        dev: &device,
        ep_out: eps.ep_out,
        ep_in: eps.ep_in,
    };
    w.handshake_to_lockdown().await
}
