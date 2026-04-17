//! USB mux pseudo-TCP framing. **`MuxHub`** owns USB + a demux buffer so **multiple** pseudo-TCP
//! connections (e.g. lockdownd + another service) can share one bulk pair.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use idevice_usb_core::{
    BulkTransport, Endpoints, TcpConn, MUX_PROTO_CONTROL, MUX_PROTO_TCP, READ_BUF,
};

use crate::usb::AppleUsb;

const TH_SYN: u8 = 0x02;
const TH_RST: u8 = 0x04;
const TH_ACK: u8 = 0x10;

/// Shared USB mux state for one or more [`TcpConn`] pseudo-TCP flows.
pub struct MuxHub {
    pub usb: AppleUsb,
    pub eps: Endpoints,
    pub mux_version: u8,
    /// Mux v2 per-USB-session TX sequence; must not reset per pseudo-TCP (iOS rejects reused values with CONTROL *duplicate packet*).
    pub mux_tx_seq: u16,
    usb_rx_buffer: Vec<u8>,
    /// Full mux TCP frames for tuples other than the connection currently receiving.
    stash: VecDeque<Vec<u8>>,
    pub verbose_tcp: bool,
}

impl BulkTransport for MuxHub {
    fn bulk_out(&mut self, ep_num: u8, data: &[u8]) -> Result<(), String> {
        self.usb.bulk_out(ep_num, data)
    }

    fn bulk_in(&mut self, ep_num: u8, max_len: usize) -> Result<Vec<u8>, String> {
        self.usb.bulk_in(ep_num, max_len)
    }
}

impl MuxHub {
    pub fn new(usb: AppleUsb, eps: Endpoints, mux_version: u8, mux_tx_seq: u16) -> Self {
        Self {
            usb,
            eps,
            mux_version,
            mux_tx_seq,
            usb_rx_buffer: Vec::new(),
            stash: VecDeque::new(),
            verbose_tcp: false,
        }
    }

    pub fn clear_buffers(&mut self) {
        self.usb_rx_buffer.clear();
        self.stash.clear();
    }

    /// Complete a **new** pseudo-TCP to `dport` on an already-running mux (VERSION/SETUP already done).
    pub fn connect_additional_tcp(&mut self, dport: u16) -> Result<TcpConn, String> {
        let mut conn = TcpConn::new_ready_for_syn(self.mux_version, dport);
        let syn = conn.build_mux_tcp_packet(&mut self.mux_tx_seq, TH_SYN, &[]);
        self.bulk_out(self.eps.ep_out, &syn)?;
        loop {
            let frame = self.next_full_mux_tcp_frame()?;
            if !tcp_frame_matches_conn(&frame, conn.mux_header_len(), &conn) {
                self.stash.push_back(frame);
                continue;
            }
            let tcp_base = conn.mux_header_len();
            let th = frame.get(tcp_base + 13).copied().unwrap_or(0);
            if (th & TH_SYN) != 0 && (th & TH_ACK) != 0 {
                let ack = conn.finish_handshake_ack_packet(&frame, &mut self.mux_tx_seq)?;
                self.bulk_out(self.eps.ep_out, &ack)?;
                return Ok(conn);
            }
            if (th & TH_RST) != 0 {
                return Err("mux TCP RST during secondary handshake".into());
            }
        }
    }

    pub fn send_raw_for(&mut self, conn: &mut TcpConn, payload: &[u8]) -> Result<(), String> {
        let pkt = conn.build_mux_tcp_packet(&mut self.mux_tx_seq, 0x10, payload);
        self.bulk_out(self.eps.ep_out, &pkt)?;
        conn.seq = conn.seq.wrapping_add(payload.len() as u32);
        Ok(())
    }

    pub fn send_ack_for(&mut self, conn: &mut TcpConn) -> Result<(), String> {
        let pkt = conn.build_mux_tcp_packet(&mut self.mux_tx_seq, 0x10, &[]);
        self.bulk_out(self.eps.ep_out, &pkt)
    }

    /// Next TCP payload for `conn`, stashing frames for other connections.
    pub fn recv_tcp_payload_for(&mut self, conn: &mut TcpConn) -> Result<Vec<u8>, String> {
        loop {
            if let Some(idx) = self
                .stash
                .iter()
                .position(|f| tcp_frame_matches_conn(f, conn.mux_header_len(), conn))
            {
                let frame = self.stash.remove(idx).unwrap();
                if let Some(payload) = self.deliver_tcp_payload_from_frame(conn, frame)? {
                    return Ok(payload);
                }
                continue;
            }

            let frame = self.next_full_mux_tcp_frame()?;
            if !tcp_frame_matches_conn(&frame, conn.mux_header_len(), conn) {
                self.stash.push_back(frame);
                continue;
            }
            if let Some(payload) = self.deliver_tcp_payload_from_frame(conn, frame)? {
                return Ok(payload);
            }
        }
    }

    /// Returns next full mux packet (including mux + TCP headers) for **any** TCP connection.
    fn next_full_mux_tcp_frame(&mut self) -> Result<Vec<u8>, String> {
        const MAX_MUX_PACKET: usize = 1 << 20;
        loop {
            while self.usb_rx_buffer.len() >= 8 {
                let protocol = u32::from_be_bytes(self.usb_rx_buffer[0..4].try_into().unwrap());
                let packet_len =
                    u32::from_be_bytes(self.usb_rx_buffer[4..8].try_into().unwrap()) as usize;
                if packet_len < 8 {
                    return Err(format!("invalid mux packet_len {}", packet_len));
                }
                if packet_len > MAX_MUX_PACKET {
                    return Err(format!("mux packet_len {} exceeds cap", packet_len));
                }
                if self.usb_rx_buffer.len() < packet_len {
                    break;
                }
                let frame = self.usb_rx_buffer[..packet_len].to_vec();
                self.usb_rx_buffer.drain(..packet_len);
                if protocol == MUX_PROTO_CONTROL {
                    let mux_len = if self.mux_version >= 2 { 16 } else { 8 };
                    if frame.len() > mux_len {
                        let body = &frame[mux_len..];
                        crate::console_log!(
                            "[mux] device CONTROL {} bytes: {:02X?}",
                            body.len(),
                            &body[..std::cmp::min(32, body.len())]
                        );
                        let lossy = String::from_utf8_lossy(body);
                        if lossy.chars().any(|c| c.is_ascii_graphic()) {
                            crate::console_log!(
                                "[mux] device CONTROL (utf-8-ish): {}",
                                lossy.trim()
                            );
                        }
                    } else {
                        crate::console_log!("[mux] device CONTROL (empty body)");
                    }
                    continue;
                }
                if protocol != MUX_PROTO_TCP {
                    return Err(format!(
                        "USBMUX unexpected mux protocol {} (expected TCP {})",
                        protocol, MUX_PROTO_TCP
                    ));
                }
                return Ok(frame);
            }
            let chunk = self
                .usb
                .bulk_in(self.eps.ep_in, READ_BUF)
                .map_err(|e| format!("bulk IN: {}", e))?;
            self.usb_rx_buffer.extend_from_slice(&chunk);
        }
    }

    /// If the frame carries TCP payload for `conn`, update seq/ack, send ACK, return `Some(payload)`.
    /// If matching but zero payload (pure ACK), update state and return `None`.
    fn deliver_tcp_payload_from_frame(
        &mut self,
        conn: &mut TcpConn,
        tcp_packet: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        let mux_len = conn.mux_header_len();
        if tcp_packet.len() < mux_len + 20 {
            return Err(format!(
                "mux TCP frame too short: {} bytes",
                tcp_packet.len()
            ));
        }
        if conn.mux_version >= 2 && tcp_packet.len() >= 16 {
            conn.mux_rx_seq = u16::from_be_bytes([tcp_packet[14], tcp_packet[15]]);
        }
        let tcp_base = mux_len;
        let data_off = (tcp_packet[tcp_base + 12] >> 4) as usize * 4;
        let header_len = tcp_base + data_off;
        if tcp_packet.len() < header_len {
            return Err(format!(
                "mux TCP header_len {} exceeds frame {}",
                header_len,
                tcp_packet.len()
            ));
        }
        let iph_seq =
            u32::from_be_bytes(tcp_packet[tcp_base + 4..tcp_base + 8].try_into().unwrap());
        let th_flags = tcp_packet.get(tcp_base + 13).copied().unwrap_or(0);
        let payload_len_u32 = (tcp_packet.len() - header_len) as u32;

        if self.verbose_tcp {
            crate::console_log!(
                "[tcp] IN (demux) peer_seq={} flags=0x{:02X} payload_len={} (conn seq={} ack={})",
                iph_seq,
                th_flags,
                payload_len_u32,
                conn.seq,
                conn.ack
            );
        }

        if (th_flags & TH_RST) != 0 {
            let body = tcp_packet.get(header_len..).unwrap_or(&[]);
            let lossy = String::from_utf8_lossy(body);
            let mut msg = format!("mux TCP reset: {}", lossy);
            if lossy.contains("sessionUpcall") {
                msg.push_str(" (lockdownd closed the session — check pairing / TLS flags.)");
            }
            return Err(msg);
        }

        conn.ack = iph_seq.wrapping_add(payload_len_u32);
        self.send_ack_for(conn)?;

        if tcp_packet.len() > header_len {
            let raw_payload = tcp_packet[header_len..].to_vec();
            let hex_preview = &raw_payload[..std::cmp::min(4, raw_payload.len())];
            crate::console_log!(
                "[tcp] RCV: {} bytes (Hex: {:02X?})",
                payload_len_u32,
                hex_preview
            );
            return Ok(Some(raw_payload));
        }
        Ok(None)
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

/// Lockdownd pseudo-TCP + shared [`MuxHub`] for demuxed secondary services.
pub struct MuxLink {
    pub hub: Rc<RefCell<MuxHub>>,
    pub conn: TcpConn,
}

impl MuxLink {
    pub fn new(usb: AppleUsb, eps: Endpoints, conn: TcpConn, mux_tx_seq: u16) -> Self {
        let mux_version = conn.mux_version;
        let hub = MuxHub::new(usb, eps, mux_version, mux_tx_seq);
        Self {
            hub: Rc::new(RefCell::new(hub)),
            conn,
        }
    }

    pub fn clear_usb_rx_buffer(&mut self) {
        self.hub.borrow_mut().clear_buffers();
    }

    pub fn send_raw(&mut self, payload: &[u8]) -> Result<(), String> {
        let h = self.hub.clone();
        let mut hub = h.borrow_mut();
        hub.send_raw_for(&mut self.conn, payload)
    }

    pub fn recv_tcp_payload(&mut self) -> Result<Vec<u8>, String> {
        let h = self.hub.clone();
        let mut hub = h.borrow_mut();
        hub.recv_tcp_payload_for(&mut self.conn)
    }

    pub fn connect_service_tcp(&self, dport: u16) -> Result<TcpConn, String> {
        self.hub.borrow_mut().connect_additional_tcp(dport)
    }

    pub fn recv_tcp_payload_for(&self, conn: &mut TcpConn) -> Result<Vec<u8>, String> {
        let h = self.hub.clone();
        let mut hub = h.borrow_mut();
        hub.recv_tcp_payload_for(conn)
    }

    pub fn send_raw_for_conn(&self, conn: &mut TcpConn, payload: &[u8]) -> Result<(), String> {
        let h = self.hub.clone();
        let mut hub = h.borrow_mut();
        hub.send_raw_for(conn, payload)
    }

    pub fn eps(&self) -> Endpoints {
        self.hub.borrow().eps
    }

    pub fn mux_version(&self) -> u8 {
        self.hub.borrow().mux_version
    }
}
