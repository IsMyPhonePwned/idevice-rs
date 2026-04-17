//! Lockdownd cleartext over a **usbmuxd** tunnel (`UnixStream`) — no USB pseudo-TCP framing.

use std::io::{Read, Write};
use std::path::PathBuf;

use idevice_usb_core::READ_BUF;
use std::os::unix::net::UnixStream;

use crate::mux_io::CleartextMuxIo;
use crate::usbmuxd;

/// Byte stream to lockdownd via usbmuxd (same 4-byte BE plist framing as mux TCP payload).
pub struct SocketMuxLink {
    stream: UnixStream,
    pub socket_path: PathBuf,
    pub device_id: u32,
}

impl SocketMuxLink {
    pub fn new(stream: UnixStream, socket_path: PathBuf, device_id: u32) -> Self {
        Self {
            stream,
            socket_path,
            device_id,
        }
    }

    /// New tunnel to lockdownd on the same device (after `Pair`, etc.).
    pub fn reopen_lockdown(&mut self) -> Result<(), String> {
        let port = idevice_usb_core::lockdown_proto::LOCKDOWND_PORT;
        self.stream = usbmuxd::connect_device_port(&self.socket_path, self.device_id, port)?;
        Ok(())
    }
}

impl CleartextMuxIo for SocketMuxLink {
    fn send_raw(&mut self, payload: &[u8]) -> Result<(), String> {
        self.stream
            .write_all(payload)
            .map_err(|e| format!("usbmuxd tunnel write: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("usbmuxd tunnel flush: {}", e))?;
        Ok(())
    }

    fn recv_tcp_payload(&mut self) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; READ_BUF];
        let n = self
            .stream
            .read(&mut buf)
            .map_err(|e| format!("usbmuxd tunnel read: {}", e))?;
        buf.truncate(n);
        Ok(buf)
    }

    fn set_verbose_tcp(&mut self, _verbose: bool) {}

    fn transport_snapshot(&self) -> String {
        format!(
            "usbmuxd device_id={} path={}",
            self.device_id,
            self.socket_path.display()
        )
    }
}
