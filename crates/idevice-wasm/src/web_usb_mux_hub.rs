//! Shared USB mux demux for **multiple** pseudo-TCP streams (lockdownd + services), mirroring `idevice::mux_link::MuxHub`.

use std::collections::VecDeque;

use idevice_usb_core::{
    build_mux_setup_packet_v2, build_mux_version_request, parse_mux_version_response, TcpConn,
    MUX_PROTO_CONTROL, MUX_PROTO_TCP, READ_BUF,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{UsbDevice, UsbInTransferResult};

use crate::wasm_log;
use crate::web_usb::AppleEndpoints;

const TH_SYN: u8 = 0x02;
const TH_RST: u8 = 0x04;
const TH_ACK: u8 = 0x10;
const MAX_MUX_PACKET: usize = 1 << 20;

fn log_verbose(verbose: bool, msg: &str) {
    wasm_log::debug_verbose(verbose, msg);
}

pub struct WebUsbMuxHub<'a> {
    dev: &'a UsbDevice,
    pub(crate) ep_out: u8,
    pub(crate) ep_in: u8,
    pub(crate) mux_tx_seq: u16,
    pub(crate) mux_version: u8,
    usb_rx_buffer: Vec<u8>,
    /// Frames for pseudo-TCP tuples other than the connection currently receiving.
    stash: VecDeque<Vec<u8>>,
    verbose: bool,
}

impl<'a> WebUsbMuxHub<'a> {
    /// USB mux VERSION (+ SETUP v2); returns hub ready for first pseudo-TCP.
    pub async fn new_usb_mux(
        dev: &'a UsbDevice,
        eps: AppleEndpoints,
        verbose: bool,
    ) -> Result<Self, JsValue> {
        let ver = build_mux_version_request();
        wasm_log::info(&format!(
            "mux: VERSION → bulk OUT ep {} ({} bytes)",
            eps.ep_out,
            ver.len()
        ));
        bulk_out(dev, eps.ep_out, ver.as_slice()).await?;
        let resp = bulk_in(dev, eps.ep_in, READ_BUF).await?;
        let (major, minor) = parse_mux_version_response(&resp).map_err(|e| JsValue::from_str(&e))?;
        wasm_log::info(&format!(
            "mux: VERSION reply — major={major} minor={minor} ({} bytes IN)",
            resp.len()
        ));
        log_verbose(
            verbose,
            &format!("[wasm] mux VERSION major={}", major),
        );

        let mux_version = major;
        let mux_tx_seq: u16 = 1;
        if mux_version >= 2 {
            let setup = build_mux_setup_packet_v2();
            wasm_log::info(&format!(
                "mux: SETUP (v2) → bulk OUT {} bytes",
                setup.len()
            ));
            bulk_out(dev, eps.ep_out, setup.as_slice()).await?;
        }

        Ok(Self {
            dev,
            ep_out: eps.ep_out,
            ep_in: eps.ep_in,
            mux_tx_seq,
            mux_version,
            usb_rx_buffer: Vec::new(),
            stash: VecDeque::new(),
            verbose,
        })
    }

    /// First pseudo-TCP to `dport` (SYN → ACK from device → our ACK), same as previous single-stream connect.
    pub async fn connect_tcp_initial(
        &mut self,
        dport: u16,
    ) -> Result<TcpConn, JsValue> {
        let mut conn = TcpConn::new_ready_for_syn(self.mux_version, dport);
        wasm_log::info(&format!(
            "mux: pseudo-TCP SYN → :{} (sport {})",
            dport,
            conn.sport
        ));
        let syn = conn.build_mux_tcp_packet(&mut self.mux_tx_seq, TH_SYN, &[]);
        self.bulk_out(&syn).await?;
        let raw = self.bulk_in(READ_BUF).await?;
        let ack = conn
            .finish_handshake_ack_packet(&raw, &mut self.mux_tx_seq)
            .map_err(|e| JsValue::from_str(&e))?;
        self.bulk_out(&ack).await?;
        wasm_log::info("mux: pseudo-TCP handshake OK");
        Ok(conn)
    }

    /// Additional pseudo-TCP after mux is up (stashes frames for other connections).
    pub async fn connect_tcp_additional(&mut self, dport: u16) -> Result<TcpConn, JsValue> {
        let mut conn = TcpConn::new_ready_for_syn(self.mux_version, dport);
        let syn = conn.build_mux_tcp_packet(&mut self.mux_tx_seq, TH_SYN, &[]);
        self.bulk_out(&syn).await?;
        loop {
            let frame = self.next_full_mux_tcp_frame().await?;
            if !tcp_frame_matches_conn(&frame, conn.mux_header_len(), &conn) {
                self.stash.push_back(frame);
                continue;
            }
            let tcp_base = conn.mux_header_len();
            let th = frame.get(tcp_base + 13).copied().unwrap_or(0);
            if (th & TH_SYN) != 0 && (th & TH_ACK) != 0 {
                let ack = conn
                    .finish_handshake_ack_packet(&frame, &mut self.mux_tx_seq)
                    .map_err(|e| JsValue::from_str(&e))?;
                self.bulk_out(&ack).await?;
                wasm_log::info(&format!(
                    "mux: secondary TCP OK → :{} (sport {})",
                    dport,
                    conn.sport
                ));
                return Ok(conn);
            }
            if (th & TH_RST) != 0 {
                return Err(JsValue::from_str(
                    "mux TCP RST during secondary handshake",
                ));
            }
        }
    }

    pub(crate) async fn bulk_out(&mut self, data: &[u8]) -> Result<(), JsValue> {
        let mut buf = data.to_vec();
        let p = self
            .dev
            .transfer_out_with_u8_slice(self.ep_out, &mut buf)
            .map_err(|e| e)?;
        JsFuture::from(p).await.map_err(|e| e)?;
        Ok(())
    }

    pub(crate) async fn bulk_in(&mut self, max: usize) -> Result<Vec<u8>, JsValue> {
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

    async fn next_full_mux_tcp_frame(&mut self) -> Result<Vec<u8>, JsValue> {
        loop {
            while self.usb_rx_buffer.len() >= 8 {
                let protocol =
                    u32::from_be_bytes(self.usb_rx_buffer[0..4].try_into().map_err(|_| {
                        JsValue::from_str("mux buffer protocol parse")
                    })?);
                let packet_len = u32::from_be_bytes(self.usb_rx_buffer[4..8].try_into().unwrap())
                    as usize;
                if packet_len < 8 {
                    return Err(JsValue::from_str(&format!(
                        "invalid mux packet_len {}",
                        packet_len
                    )));
                }
                if packet_len > MAX_MUX_PACKET {
                    return Err(JsValue::from_str("mux packet too large"));
                }
                if self.usb_rx_buffer.len() < packet_len {
                    break;
                }
                let frame = self.usb_rx_buffer[..packet_len].to_vec();
                self.usb_rx_buffer.drain(..packet_len);
                if protocol == MUX_PROTO_CONTROL {
                    log_verbose(
                        self.verbose,
                        &format!("[wasm] mux CONTROL {} bytes", frame.len()),
                    );
                    continue;
                }
                if protocol != MUX_PROTO_TCP {
                    return Err(JsValue::from_str(&format!(
                        "unexpected mux protocol {}",
                        protocol
                    )));
                }
                return Ok(frame);
            }
            let chunk = self.bulk_in(READ_BUF).await?;
            self.usb_rx_buffer.extend_from_slice(&chunk);
        }
    }

    async fn deliver_tcp_payload_from_frame(
        &mut self,
        conn: &mut TcpConn,
        tcp_packet: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        let mux_len = conn.mux_header_len();
        if tcp_packet.len() < mux_len + 20 {
            return Err(JsValue::from_str("mux TCP frame too short"));
        }
        if conn.mux_version >= 2 && tcp_packet.len() >= 16 {
            conn.mux_rx_seq = u16::from_be_bytes([tcp_packet[14], tcp_packet[15]]);
        }
        let tcp_base = mux_len;
        let data_off = (tcp_packet[tcp_base + 12] >> 4) as usize * 4;
        let header_len = tcp_base + data_off;
        if tcp_packet.len() < header_len {
            return Err(JsValue::from_str("mux TCP header_len"));
        }
        let iph_seq =
            u32::from_be_bytes(tcp_packet[tcp_base + 4..tcp_base + 8].try_into().unwrap());
        let th_flags = tcp_packet.get(tcp_base + 13).copied().unwrap_or(0);
        let payload_len_u32 = (tcp_packet.len() - header_len) as u32;

        log_verbose(
            self.verbose,
            &format!(
                "[wasm] tcp IN flags=0x{:02X} payload_len={} seq={}",
                th_flags, payload_len_u32, iph_seq
            ),
        );

        if (th_flags & TH_RST) != 0 {
            let body = tcp_packet.get(header_len..).unwrap_or(&[]);
            let lossy = String::from_utf8_lossy(body);
            return Err(JsValue::from_str(&format!("mux TCP RST: {}", lossy)));
        }

        conn.ack = iph_seq.wrapping_add(payload_len_u32);
        let ack_pkt = conn.build_mux_tcp_packet(&mut self.mux_tx_seq, TH_ACK, &[]);
        self.bulk_out(&ack_pkt).await?;

        if tcp_packet.len() > header_len {
            return Ok(Some(tcp_packet[header_len..].to_vec()));
        }
        Ok(None)
    }

    /// Next TCP payload for `conn`, stashing frames for other pseudo-TCP connections.
    pub async fn recv_tcp_payload_for(&mut self, conn: &mut TcpConn) -> Result<Vec<u8>, JsValue> {
        loop {
            if let Some(idx) = self
                .stash
                .iter()
                .position(|f| tcp_frame_matches_conn(f, conn.mux_header_len(), conn))
            {
                let frame = self.stash.remove(idx).unwrap();
                if let Some(p) = self.deliver_tcp_payload_from_frame(conn, frame).await? {
                    return Ok(p);
                }
                continue;
            }

            let frame = self.next_full_mux_tcp_frame().await?;
            if !tcp_frame_matches_conn(&frame, conn.mux_header_len(), conn) {
                self.stash.push_back(frame);
                continue;
            }
            if let Some(p) = self.deliver_tcp_payload_from_frame(conn, frame).await? {
                return Ok(p);
            }
        }
    }

    pub async fn send_tcp_payload_for(
        &mut self,
        conn: &mut TcpConn,
        payload: &[u8],
    ) -> Result<(), JsValue> {
        let pkt = conn.build_mux_tcp_packet(&mut self.mux_tx_seq, TH_ACK, payload);
        self.bulk_out(&pkt).await?;
        conn.seq = conn.seq.wrapping_add(payload.len() as u32);
        log_verbose(
            self.verbose,
            &format!("[wasm] tcp OUT payload {} bytes", payload.len()),
        );
        Ok(())
    }
}

fn tcp_frame_matches_conn(frame: &[u8], mux_len: usize, conn: &TcpConn) -> bool {
    let tcp_base = mux_len;
    if frame.len() < tcp_base + 4 {
        return false;
    }
    let src = u16::from_be_bytes([frame[tcp_base], frame[tcp_base + 1]]);
    let dst = u16::from_be_bytes([frame[tcp_base + 2], frame[tcp_base + 3]]);
    src == conn.dport && dst == conn.sport
}

async fn bulk_out(dev: &UsbDevice, ep_out: u8, data: &[u8]) -> Result<(), JsValue> {
    let mut buf = data.to_vec();
    let p = dev
        .transfer_out_with_u8_slice(ep_out, &mut buf)
        .map_err(|e| e)?;
    JsFuture::from(p).await.map_err(|e| e)?;
    Ok(())
}

async fn bulk_in(dev: &UsbDevice, ep_in: u8, max: usize) -> Result<Vec<u8>, JsValue> {
    let p = dev.transfer_in(ep_in, max as u32);
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
