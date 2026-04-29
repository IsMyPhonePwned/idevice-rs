//! AFC over mux pseudo-TCP + TLS — send/receive matches **libimobiledevice** `afc.c` (`AFCPacket`,
//! `afc_dispatch_packet`, `afc_receive_data`): one receive round-trip per high-level call (no extra
//! STATUS read after **`AFC_OP_DATA`**).

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use rustls::ClientConnection;

use crate::crypto::HostKeys;
use crate::lockdown_rustls::{
    handshake_service_tls, tls_read_plain_service, tls_write_plain_and_flush_service,
    LockdownTlsClientAuth, LockdownTlsSni,
};
use crate::mux_link::{MuxHub, MuxLink};
use idevice_usb_core::TcpConn;

const AFC_MAGIC: &[u8; 8] = b"CFA6LPAA";
/// `sizeof(AFCPacket)` in libimobiledevice `src/afc.h`.
const AFC_HDR: usize = 40;

const AFC_OP_STATUS: u64 = 0x01;
const AFC_OP_DATA: u64 = 0x02;
const AFC_OP_READ_DIR: u64 = 0x03;
const AFC_OP_GET_FILE_INFO: u64 = 0x0a;
const AFC_OP_REMOVE_PATH: u64 = 0x08;
const AFC_OP_FILE_OPEN: u64 = 0x0d;
const AFC_OP_FILE_OPEN_RES: u64 = 0x0e;
const AFC_OP_FILE_READ: u64 = 0x0f;
const AFC_OP_FILE_CLOSE: u64 = 0x14;

/// `AFC_FOPEN_RDONLY` — see libimobiledevice `afc.h`.
pub const AFC_FOPEN_RDONLY: u64 = 0x0000_0001;

pub const AFC_E_SUCCESS: u64 = 0;
pub const AFC_E_OBJECT_NOT_FOUND: u64 = 8;

fn build_afc_packet(packet_num: u64, operation: u64, body: &[u8]) -> Vec<u8> {
    let this_length = (AFC_HDR + body.len()) as u64;
    let entire_length = this_length;
    let mut p = Vec::with_capacity(AFC_HDR + body.len());
    p.extend_from_slice(AFC_MAGIC);
    p.extend_from_slice(&entire_length.to_le_bytes());
    p.extend_from_slice(&this_length.to_le_bytes());
    p.extend_from_slice(&packet_num.to_le_bytes());
    p.extend_from_slice(&operation.to_le_bytes());
    p.extend_from_slice(body);
    p
}

fn parse_afc_header(h: &[u8]) -> Result<(u64, u64, u64, u64), String> {
    if h.len() < AFC_HDR {
        return Err(format!("AFC header short: {} bytes", h.len()));
    }
    if &h[0..8] != AFC_MAGIC {
        return Err("AFC magic mismatch".into());
    }
    let entire = u64::from_le_bytes(h[8..16].try_into().unwrap());
    let this = u64::from_le_bytes(h[16..24].try_into().unwrap());
    let packet_num = u64::from_le_bytes(h[24..32].try_into().unwrap());
    let op = u64::from_le_bytes(h[32..40].try_into().unwrap());
    Ok((entire, this, packet_num, op))
}

pub struct AfcSession {
    hub: Rc<RefCell<MuxHub>>,
    tcp: Rc<RefCell<TcpConn>>,
    tls: ClientConnection,
    packet_num: u64,
    stream: Vec<u8>,
    tls_payload_trace: bool,
}

impl AfcSession {
    pub fn connect(
        hub: Rc<RefCell<MuxHub>>,
        mux: &Rc<RefCell<MuxLink>>,
        port: u16,
        keys: &HostKeys,
        client_auth: LockdownTlsClientAuth,
        tls_sni: LockdownTlsSni,
        tls_debug: bool,
    ) -> Result<Self, String> {
        let tcp = Rc::new(RefCell::new(mux.borrow().connect_service_tcp(port)?));
        let tls = handshake_service_tls(
            hub.clone(),
            tcp.clone(),
            keys,
            client_auth,
            tls_sni,
            tls_debug,
        )?;
        Ok(Self {
            hub,
            tcp,
            tls,
            packet_num: 0,
            stream: Vec::new(),
            tls_payload_trace: tls_debug,
        })
    }

    fn read_tls_more(&mut self, scratch: &mut [u8]) -> Result<usize, String> {
        tls_read_plain_service(
            &mut self.tls,
            &self.hub,
            &self.tcp,
            scratch,
            self.tls_payload_trace,
        )
    }

    /// Ensure at least `need` bytes in `self.stream` (TLS plaintext).
    fn fill_stream(&mut self, need: usize, scratch: &mut [u8]) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(120);
        while self.stream.len() < need {
            if Instant::now() > deadline {
                return Err("AFC: timed out waiting for TLS plaintext".into());
            }
            let n = self.read_tls_more(scratch)?;
            if n == 0 {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            self.stream.extend_from_slice(&scratch[..n]);
        }
        Ok(())
    }

    /// One **`afc_receive_data`** round-trip: full AFC logical frame (`entire_length` bytes after TLS decode).
    fn recv_afc(&mut self, scratch: &mut [u8]) -> Result<(u64, Vec<u8>), String> {
        self.fill_stream(AFC_HDR, scratch)?;
        let (entire, _this, _pn, operation) = parse_afc_header(&self.stream[..AFC_HDR])?;
        let entire = entire as usize;
        if entire < AFC_HDR {
            return Err(format!("AFC invalid entire_length {}", entire));
        }
        if entire > 32 * 1024 * 1024 {
            return Err(format!("AFC entire_length {} too large", entire));
        }
        self.fill_stream(entire, scratch)?;
        let frame: Vec<u8> = self.stream.drain(..entire).collect();
        let body = frame[AFC_HDR..].to_vec();
        Ok((operation, body))
    }

    fn afc_status_param1(body: &[u8]) -> Result<u64, String> {
        if body.len() < 8 {
            return Err("AFC STATUS body short".into());
        }
        Ok(u64::from_le_bytes(body[0..8].try_into().unwrap()))
    }

    /// Like **`afc_receive_data`** when the caller expects **`AFC_OP_DATA`** (e.g. `afc_read_directory`).
    fn recv_afc_expect_data(&mut self, ctx: &str, scratch: &mut [u8]) -> Result<Vec<u8>, String> {
        let (op, body) = self.recv_afc(scratch)?;
        if op == AFC_OP_STATUS {
            let code = Self::afc_status_param1(&body)?;
            return Err(format!("AFC {} STATUS error {}", ctx, code));
        }
        if op != AFC_OP_DATA {
            return Err(format!("AFC {}: expected DATA, op=0x{:x}", ctx, op));
        }
        Ok(body)
    }

    /// Like **`afc_receive_data`** for **`afc_file_open`** (`AFC_OP_FILE_OPEN_RES` or error STATUS).
    fn recv_afc_expect_open_res(&mut self, scratch: &mut [u8]) -> Result<u64, String> {
        let (op, body) = self.recv_afc(scratch)?;
        if op == AFC_OP_STATUS {
            let code = Self::afc_status_param1(&body)?;
            return Err(format!("AFC FILE_OPEN STATUS {}", code));
        }
        if op != AFC_OP_FILE_OPEN_RES {
            return Err(format!("AFC FILE_OPEN: expected OPEN_RES, op=0x{:x}", op));
        }
        if body.len() < 8 {
            return Err("AFC FILE_OPEN_RES body short".into());
        }
        Ok(u64::from_le_bytes(body[0..8].try_into().unwrap()))
    }

    fn dispatch(&mut self, operation: u64, body: &[u8]) -> Result<(), String> {
        self.packet_num = self.packet_num.wrapping_add(1);
        let pkt = build_afc_packet(self.packet_num, operation, body);
        tls_write_plain_and_flush_service(
            &mut self.tls,
            &self.hub,
            &self.tcp,
            &pkt,
            self.tls_payload_trace,
        )
    }

    /// `afc_read_directory` — returns entry names (no `.` / `..`).
    pub fn read_directory(
        &mut self,
        path: &str,
        scratch: &mut [u8],
    ) -> Result<Vec<String>, String> {
        let mut p = path.as_bytes().to_vec();
        p.push(0);
        self.dispatch(AFC_OP_READ_DIR, &p)?;
        let data = self.recv_afc_expect_data("READ_DIR", scratch)?;
        Ok(parse_string_list(&data))
    }

    pub fn get_file_info_dict(
        &mut self,
        path: &str,
        scratch: &mut [u8],
    ) -> Result<std::collections::HashMap<String, String>, String> {
        let mut p = path.as_bytes().to_vec();
        p.push(0);
        self.dispatch(AFC_OP_GET_FILE_INFO, &p)?;
        let data = self.recv_afc_expect_data("GET_FILE_INFO", scratch)?;
        Ok(parse_info_dictionary(&data))
    }

    pub fn file_open(&mut self, path: &str, mode: u64, scratch: &mut [u8]) -> Result<u64, String> {
        let mut body = Vec::with_capacity(8 + path.len() + 1);
        body.extend_from_slice(&mode.to_le_bytes());
        body.extend_from_slice(path.as_bytes());
        body.push(0);
        self.dispatch(AFC_OP_FILE_OPEN, &body)?;
        self.recv_afc_expect_open_res(scratch)
    }

    pub fn file_read(
        &mut self,
        handle: u64,
        len: u32,
        scratch: &mut [u8],
    ) -> Result<Vec<u8>, String> {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&handle.to_le_bytes());
        b[8..16].copy_from_slice(&(len as u64).to_le_bytes());
        self.dispatch(AFC_OP_FILE_READ, &b)?;
        let data = self.recv_afc_expect_data("FILE_READ", scratch)?;
        Ok(data)
    }

    pub fn file_close(&mut self, handle: u64, scratch: &mut [u8]) -> Result<(), String> {
        let b = handle.to_le_bytes();
        self.dispatch(AFC_OP_FILE_CLOSE, &b)?;
        let (op, body) = self.recv_afc(scratch)?;
        if op == AFC_OP_STATUS {
            let code = Self::afc_status_param1(&body)?;
            if code != AFC_E_SUCCESS {
                return Err(format!("AFC FILE_CLOSE STATUS {}", code));
            }
            return Ok(());
        }
        Err(format!("AFC FILE_CLOSE: unexpected op 0x{:x}", op))
    }

    pub fn remove_path(&mut self, path: &str, scratch: &mut [u8]) -> Result<(), String> {
        let mut p = path.as_bytes().to_vec();
        p.push(0);
        self.dispatch(AFC_OP_REMOVE_PATH, &p)?;
        let (op, body) = self.recv_afc(scratch)?;
        if op == AFC_OP_STATUS {
            let code = Self::afc_status_param1(&body)?;
            if code == AFC_E_SUCCESS {
                return Ok(());
            }
            // libimobiledevice maps unknown error after remove to DIR_NOT_EMPTY for dirs
            return Err(format!("AFC REMOVE_PATH STATUS {}", code));
        }
        Err(format!("AFC REMOVE_PATH: unexpected op 0x{:x}", op))
    }
}

fn parse_string_list(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let end = data[i..]
            .iter()
            .position(|&b| b == 0)
            .map(|j| i + j)
            .unwrap_or(data.len());
        if end > i {
            if let Ok(s) = std::str::from_utf8(&data[i..end]) {
                if !s.is_empty() && s != "." && s != ".." {
                    out.push(s.to_string());
                }
            }
        }
        if end >= data.len() {
            break;
        }
        i = end + 1;
    }
    out
}

/// Same key layout as libimobiledevice `make_dictionary` (pairs of null-terminated strings).
/// The last value may run to the end of the buffer without a trailing `\0` (lib uses `strnlen` per
/// field; our previous `j + val_len >= len` check dropped that pair and left `st_ifmt` missing).
fn parse_info_dictionary(data: &[u8]) -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;
    let mut m = HashMap::new();
    let mut j = 0usize;
    while j < data.len() {
        let key_end_rel = data[j..].iter().position(|&b| b == 0);
        let Some(kr) = key_end_rel else {
            break;
        };
        let key_end = j + kr;
        let key = std::str::from_utf8(&data[j..key_end]).unwrap_or("");
        j = key_end + 1;
        if j > data.len() {
            break;
        }
        let val_end_rel = data[j..].iter().position(|&b| b == 0);
        let (val, next_j) = match val_end_rel {
            Some(vr) => {
                let ve = j + vr;
                (std::str::from_utf8(&data[j..ve]).unwrap_or(""), ve + 1)
            }
            None => (std::str::from_utf8(&data[j..]).unwrap_or(""), data.len()),
        };
        m.insert(key.to_string(), val.to_string());
        j = next_j;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_afc_packet_layout_matches_libimobiledevice() {
        let body = b"hi";
        let pkt = build_afc_packet(0xdead_beef, AFC_OP_FILE_READ, body);

        assert_eq!(pkt.len(), AFC_HDR + body.len());
        assert_eq!(&pkt[0..8], AFC_MAGIC);
        let entire = u64::from_le_bytes(pkt[8..16].try_into().unwrap());
        let this = u64::from_le_bytes(pkt[16..24].try_into().unwrap());
        let pn = u64::from_le_bytes(pkt[24..32].try_into().unwrap());
        let op = u64::from_le_bytes(pkt[32..40].try_into().unwrap());
        assert_eq!(entire, (AFC_HDR + body.len()) as u64);
        assert_eq!(this, entire);
        assert_eq!(pn, 0xdead_beef);
        assert_eq!(op, AFC_OP_FILE_READ);
        assert_eq!(&pkt[AFC_HDR..], body);
    }

    #[test]
    fn parse_afc_header_round_trips_build() {
        let pkt = build_afc_packet(7, AFC_OP_DATA, b"abcdef");
        let (entire, this, pn, op) = parse_afc_header(&pkt[..AFC_HDR]).unwrap();
        assert_eq!(entire, (AFC_HDR + 6) as u64);
        assert_eq!(this, entire);
        assert_eq!(pn, 7);
        assert_eq!(op, AFC_OP_DATA);
    }

    #[test]
    fn parse_afc_header_rejects_short_input() {
        let err = parse_afc_header(&[0u8; 8]).unwrap_err();
        assert!(err.contains("short"));
    }

    #[test]
    fn parse_afc_header_rejects_bad_magic() {
        let mut h = [0u8; AFC_HDR];
        h[..8].copy_from_slice(b"NOTAFCMG");
        let err = parse_afc_header(&h).unwrap_err();
        assert!(err.contains("magic"));
    }

    #[test]
    fn parse_string_list_filters_dot_entries_and_empties() {
        // libimobiledevice returns `.\0..\0Photos\0Trash\0`
        let raw = b".\0..\0Photos\0Trash\0";
        let v = parse_string_list(raw);
        assert_eq!(v, vec!["Photos".to_string(), "Trash".to_string()]);
    }

    #[test]
    fn parse_string_list_handles_unterminated_tail() {
        // Last name "Last" missing its trailing NUL — should still be picked up.
        let raw = b"a\0b\0Last";
        let v = parse_string_list(raw);
        assert_eq!(v, vec!["a".to_string(), "b".to_string(), "Last".to_string()]);
    }

    #[test]
    fn parse_string_list_returns_empty_for_empty_input() {
        assert!(parse_string_list(b"").is_empty());
    }

    #[test]
    fn parse_info_dictionary_recovers_all_pairs() {
        // Mimics `afc_get_file_info` reply: pairs of NUL-terminated strings.
        let raw = b"st_size\0123\0st_blocks\08\0st_ifmt\0S_IFREG";
        let m = parse_info_dictionary(raw);
        assert_eq!(m.get("st_size").map(String::as_str), Some("123"));
        assert_eq!(m.get("st_blocks").map(String::as_str), Some("8"));
        assert_eq!(m.get("st_ifmt").map(String::as_str), Some("S_IFREG"));
    }

    #[test]
    fn parse_info_dictionary_handles_trailing_nul_value() {
        let raw = b"key1\0val1\0key2\0val2\0";
        let m = parse_info_dictionary(raw);
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("key1").map(String::as_str), Some("val1"));
        assert_eq!(m.get("key2").map(String::as_str), Some("val2"));
    }

    #[test]
    fn parse_info_dictionary_returns_empty_on_empty_or_no_separator() {
        assert!(parse_info_dictionary(b"").is_empty());
        // No NUL in input — parser cannot extract a key.
        assert!(parse_info_dictionary(b"only-key").is_empty());
    }
}
