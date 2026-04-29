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
    /// **Ciphertext stash for the rustls feeder**. iOS lockdownd can deliver a single mux segment
    /// that contains multiple back-to-back TLS records (~16 KiB each) — `pcapd` does this when
    /// the device is busy. rustls's internal plaintext buffer caps at `MAX_PLAINTEXT_SIZE`
    /// (16 KiB), so feeding the whole segment via `read_tls` in one go and *then* trying to drain
    /// fails with `received plaintext buffer full`. The TLS feeder pushes any unfed bytes here
    /// after each `read_tls` round-trip and consumes them on the next call, which keeps
    /// **feed → process → drain → repeat** cycle balanced.
    pub pending_tls_in: Vec<u8>,
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
            pending_tls_in: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mux_header_len_v1_vs_v2() {
        let mut c = TcpConn::new_ready_for_syn(1, 62078);
        assert_eq!(c.mux_header_len(), 8);
        c.mux_version = 2;
        assert_eq!(c.mux_header_len(), 16);
    }

    #[test]
    fn new_ready_for_syn_initialises_state() {
        let c = TcpConn::new_ready_for_syn(2, 62078);
        assert_eq!(c.dport, 62078);
        assert_eq!(c.seq, 0);
        assert_eq!(c.ack, 0);
        assert_eq!(c.mux_version, 2);
        // After SETUP the device expects rx_seq == 0xFFFF + 1 → 0; we seed 0xFFFF so the first
        // outgoing TX appears as `rx_seq=0xFFFF`, which matches usbmuxd's `device_version_input`.
        assert_eq!(c.mux_rx_seq, 0xFFFF);
        // Source port stays inside the upper-half range usbmuxd uses (0xC000–0xFFFF).
        assert!(c.sport >= 0xc000 || c.sport == 27015);
    }

    #[test]
    fn build_mux_tcp_packet_v2_layout_and_advances_tx_seq() {
        let mut c = TcpConn::new_ready_for_syn(2, 62078);
        c.sport = 0xC123;
        c.seq = 0;
        c.ack = 0;
        let mut tx = 1u16;
        let pkt = c.build_mux_tcp_packet(&mut tx, 0x02 /* SYN */, &[]);
        assert_eq!(tx, 2, "tx seq must advance by 1");
        assert_eq!(pkt.len(), 16 + 20);

        // Mux header (16 bytes for v2)
        assert_eq!(u32::from_be_bytes(pkt[0..4].try_into().unwrap()), MUX_PROTO_TCP);
        assert_eq!(u32::from_be_bytes(pkt[4..8].try_into().unwrap()), 36);
        assert_eq!(u32::from_be_bytes(pkt[8..12].try_into().unwrap()), MUX_MAGIC);
        assert_eq!(u16::from_be_bytes([pkt[12], pkt[13]]), 1, "mux tx seq we just advanced");
        assert_eq!(u16::from_be_bytes([pkt[14], pkt[15]]), 0xFFFF, "mux rx seq from new_ready_for_syn");

        // TCP header (RFC 793 layout, big-endian)
        let tcp = &pkt[16..];
        assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]), 0xC123); // src
        assert_eq!(u16::from_be_bytes([tcp[2], tcp[3]]), 62078); // dst
        assert_eq!(u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]), 0); // seq
        assert_eq!(u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]), 0); // ack
        // data offset (high nibble) * 4 = 20 bytes
        assert_eq!(tcp[12] >> 4, 5);
        // flags
        assert_eq!(tcp[13], 0x02);
        // window scaled like usbmuxd (`MUX_TCP_WINDOW >> 8`)
        assert_eq!(
            u16::from_be_bytes([tcp[14], tcp[15]]),
            (MUX_TCP_WINDOW >> 8) as u16
        );
    }

    #[test]
    fn build_mux_tcp_packet_v1_omits_mux_magic_block() {
        let mut c = TcpConn::new_ready_for_syn(1, 62078);
        let mut tx = 0u16;
        let pkt = c.build_mux_tcp_packet(&mut tx, 0x10, b"abc");
        // v1 mux header is 8 bytes, no magic / tx / rx fields.
        assert_eq!(pkt.len(), 8 + 20 + 3);
        assert_eq!(u32::from_be_bytes(pkt[0..4].try_into().unwrap()), MUX_PROTO_TCP);
        assert_eq!(u32::from_be_bytes(pkt[4..8].try_into().unwrap()), 31);
        // tx seq must NOT advance for v1.
        assert_eq!(tx, 0);
        // payload trailing
        assert_eq!(&pkt[pkt.len() - 3..], b"abc");
    }

    fn fabricate_syn_ack_v2(mux_rx_seq: u16, peer_seq: u32, peer_ack: u32) -> Vec<u8> {
        // 16 bytes mux header + 20 bytes TCP header (no payload).
        let mut p = Vec::with_capacity(36);
        p.extend_from_slice(&MUX_PROTO_TCP.to_be_bytes());
        p.extend_from_slice(&36u32.to_be_bytes());
        p.extend_from_slice(&MUX_MAGIC.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&mux_rx_seq.to_be_bytes());

        // src/dst — finish_handshake_ack_packet doesn't validate them but the offsets matter.
        p.extend_from_slice(&62078u16.to_be_bytes());
        p.extend_from_slice(&0xC123u16.to_be_bytes());
        p.extend_from_slice(&peer_seq.to_be_bytes());
        p.extend_from_slice(&peer_ack.to_be_bytes());
        p.push(0x50);
        p.push(0x12); // SYN-ACK
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p
    }

    #[test]
    fn finish_handshake_ack_packet_advances_seq_ack_and_rx_seq() {
        let mut c = TcpConn::new_ready_for_syn(2, 62078);
        let raw = fabricate_syn_ack_v2(0x0001, 0xDEAD_BEEF, 0x0000_0001);
        let mut tx = 2u16;
        let ack_pkt = c.finish_handshake_ack_packet(&raw, &mut tx).unwrap();
        // After SYN-ACK we capture the device's mux_rx_seq.
        assert_eq!(c.mux_rx_seq, 0x0001);
        // seq ← peer ack, ack ← peer seq + 1 (SYN consumes one logical byte).
        assert_eq!(c.seq, 0x0000_0001);
        assert_eq!(c.ack, 0xDEAD_BEEF + 1);
        // build_mux_tcp_packet was called with flags=0x10 (ACK) so output is well-formed.
        assert_eq!(ack_pkt.len(), 16 + 20);
        assert_eq!(ack_pkt[16 + 13], 0x10);
        // tx must have been bumped exactly once (the ACK frame).
        assert_eq!(tx, 3);
    }

    #[test]
    fn finish_handshake_ack_packet_rejects_truncated_input() {
        let mut c = TcpConn::new_ready_for_syn(2, 62078);
        let mut tx = 0u16;
        assert!(c.finish_handshake_ack_packet(&[0u8; 4], &mut tx).is_err());
    }
}
