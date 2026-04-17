//! Cleartext I/O used by lockdownd (USB pseudo-TCP or **usbmuxd** byte stream).

use crate::mux_link::MuxLink;

/// Same cleartext contract as [`MuxLink`]: length-prefixed lockdownd plists over the transport.
pub trait CleartextMuxIo {
    fn send_raw(&mut self, payload: &[u8]) -> Result<(), String>;
    fn recv_tcp_payload(&mut self) -> Result<Vec<u8>, String>;
    fn set_verbose_tcp(&mut self, verbose: bool);
    fn transport_snapshot(&self) -> String;
}

impl CleartextMuxIo for MuxLink {
    fn send_raw(&mut self, payload: &[u8]) -> Result<(), String> {
        MuxLink::send_raw(self, payload)
    }

    fn recv_tcp_payload(&mut self) -> Result<Vec<u8>, String> {
        MuxLink::recv_tcp_payload(self)
    }

    fn set_verbose_tcp(&mut self, verbose: bool) {
        self.hub.borrow_mut().verbose_tcp = verbose;
    }

    fn transport_snapshot(&self) -> String {
        format!(
            "sport={} dport={} seq={} ack={} mux_v={}",
            self.conn.sport,
            self.conn.dport,
            self.conn.seq,
            self.conn.ack,
            self.conn.mux_version
        )
    }
}
