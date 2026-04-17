//! Pseudo-TCP over USB mux (blocking `BulkTransport`).

use crate::wire::{
    build_mux_setup_packet_v2, build_mux_version_request, parse_mux_version_response, MUX_MAGIC,
    MUX_PROTO_TCP, MUX_TCP_WINDOW,
};

pub const READ_BUF: usize = 65536;

#[derive(Clone, Copy, Debug)]
pub struct Endpoints {
    pub ep_out: u8,
    pub ep_in: u8,
}

pub trait BulkTransport {
    fn bulk_out(&mut self, ep_num: u8, data: &[u8]) -> Result<(), String>;
    fn bulk_in(&mut self, ep_num: u8, max_len: usize) -> Result<Vec<u8>, String>;
}

pub struct TcpConn {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub mux_version: u8,
    pub mux_rx_seq: u16,
}

impl TcpConn {
    #[inline]
    pub fn mux_header_len(&self) -> usize {
        if self.mux_version >= 2 {
            16
        } else {
            8
        }
    }

    /// State after VERSION (+ optional SETUP) so the next frame is SYN.
    pub fn new_ready_for_syn(mux_version: u8, dport: u16) -> Self {
        // Pseudo-TCP source port: avoid a single fixed value so reconnects (e.g. post-`Pair` → TLS)
        // do not collide on-device while an old mux session is still winding down.
        let mut b = [0u8; 2];
        let sport = if getrandom::getrandom(&mut b).is_ok() {
            0xc000u16 | (u16::from_le_bytes(b) & 0x3fff)
        } else {
            27015
        };
        Self {
            sport,
            dport,
            seq: 0,
            ack: 0,
            mux_version,
            mux_rx_seq: 0xFFFF,
        }
    }

    /// After SYN was sent, parse SYN-ACK `raw`, update seq/ack/mux_rx_seq, build final ACK frame.
    pub fn finish_handshake_ack_packet(
        &mut self,
        raw: &[u8],
        mux_tx_next: &mut u16,
    ) -> Result<Vec<u8>, String> {
        let m = self.mux_header_len();
        if raw.len() < m + 20 {
            return Err("SYN-ACK too short".into());
        }
        if self.mux_version >= 2 && raw.len() >= 16 {
            self.mux_rx_seq = u16::from_be_bytes([raw[14], raw[15]]);
        }
        let tcp = m;
        let iph_seq = u32::from_be_bytes([raw[tcp + 4], raw[tcp + 5], raw[tcp + 6], raw[tcp + 7]]);
        let iph_ack =
            u32::from_be_bytes([raw[tcp + 8], raw[tcp + 9], raw[tcp + 10], raw[tcp + 11]]);
        self.seq = iph_ack;
        self.ack = iph_seq.wrapping_add(1);
        Ok(self.build_mux_tcp_packet(mux_tx_next, 0x10, &[]))
    }

    /// `mux_tx_next` must be shared across **all** pseudo-TCP streams on one USB mux session (mux v2);
    /// start at `1` for the first connection on a fresh USB link, then keep one counter for every further SYN/data on that link.
    pub fn handshake_and_connect(
        io: &mut impl BulkTransport,
        eps: &Endpoints,
        dport: u16,
        mux_tx_next: &mut u16,
    ) -> Result<Self, String> {
        let ver = build_mux_version_request();
        io.bulk_out(eps.ep_out, &ver)?;

        let resp = io.bulk_in(eps.ep_in, READ_BUF)?;
        let (major, _minor) = parse_mux_version_response(&resp)?;

        let mux_version = major;
        if mux_version >= 2 {
            let setup = build_mux_setup_packet_v2();
            io.bulk_out(eps.ep_out, &setup)?;
        }

        let mut conn = Self::new_ready_for_syn(mux_version, dport);
        let syn = conn.build_mux_tcp_packet(mux_tx_next, 0x02, &[]);
        io.bulk_out(eps.ep_out, &syn)?;
        let raw = io.bulk_in(eps.ep_in, READ_BUF)?;
        let ack_pkt = conn.finish_handshake_ack_packet(&raw, mux_tx_next)?;
        io.bulk_out(eps.ep_out, &ack_pkt)?;
        Ok(conn)
    }

    pub fn send(
        &mut self,
        io: &mut impl BulkTransport,
        eps: &Endpoints,
        mux_tx_next: &mut u16,
        payload: &[u8],
    ) -> Result<(), String> {
        let pkt = self.build_mux_tcp_packet(mux_tx_next, 0x10, payload);
        io.bulk_out(eps.ep_out, &pkt)?;
        self.seq = self.seq.wrapping_add(payload.len() as u32);
        Ok(())
    }

    pub fn send_ack(
        &mut self,
        io: &mut impl BulkTransport,
        eps: &Endpoints,
        mux_tx_next: &mut u16,
    ) -> Result<(), String> {
        let pkt = self.build_mux_tcp_packet(mux_tx_next, 0x10, &[]);
        io.bulk_out(eps.ep_out, &pkt)
    }

    pub fn build_mux_tcp_packet(
        &mut self,
        mux_tx_next: &mut u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_hdr_len = 20usize;
        let mux_len = self.mux_header_len();
        let total_len = (mux_len + tcp_hdr_len + payload.len()) as u32;

        let mut buf = Vec::with_capacity(total_len as usize);
        buf.extend_from_slice(&MUX_PROTO_TCP.to_be_bytes());
        buf.extend_from_slice(&total_len.to_be_bytes());
        if self.mux_version >= 2 {
            buf.extend_from_slice(&MUX_MAGIC.to_be_bytes());
            buf.extend_from_slice(&mux_tx_next.to_be_bytes());
            buf.extend_from_slice(&self.mux_rx_seq.to_be_bytes());
            *mux_tx_next = mux_tx_next.wrapping_add(1);
        }

        buf.extend_from_slice(&self.sport.to_be_bytes());
        buf.extend_from_slice(&self.dport.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.ack.to_be_bytes());
        buf.push(0x50);
        buf.push(flags);
        let win = (MUX_TCP_WINDOW >> 8) as u16;
        buf.extend_from_slice(&win.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }
}
