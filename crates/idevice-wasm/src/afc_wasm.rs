//! AFC over mux pseudo-TCP + TLS (same wire format as `idevice::afc`).

use std::collections::HashMap;
use std::time::Duration;

use gloo_timers::future::sleep;
use idevice_usb_core::TcpConn;
use rustls::ClientConnection;

use crate::lockdown_tls_wasm::tls_read_plain_wasm;
use crate::lockdown_tls_wasm::tls_write_plain_and_flush_wasm;
use crate::web_usb_mux_hub::WebUsbMuxHub;

const AFC_MAGIC: &[u8; 8] = b"CFA6LPAA";
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

pub const AFC_FOPEN_RDONLY: u64 = 0x0000_0001;
pub const AFC_E_SUCCESS: u64 = 0;

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

pub struct AfcSessionWasm<'a> {
    hub: &'a mut WebUsbMuxHub<'a>,
    tcp: TcpConn,
    tls: ClientConnection,
    packet_num: u64,
    stream: Vec<u8>,
    verbose: bool,
}

impl<'a> AfcSessionWasm<'a> {
    pub fn new(
        hub: &'a mut WebUsbMuxHub<'a>,
        tcp: TcpConn,
        tls: ClientConnection,
        verbose: bool,
    ) -> Self {
        Self {
            hub,
            tcp,
            tls,
            packet_num: 0,
            stream: Vec::new(),
            verbose,
        }
    }

    async fn read_tls_more(&mut self, scratch: &mut [u8]) -> Result<usize, String> {
        tls_read_plain_wasm(
            &mut self.tls,
            self.hub,
            &mut self.tcp,
            scratch,
            self.verbose,
        )
        .await
    }

    async fn fill_stream(&mut self, need: usize, scratch: &mut [u8]) -> Result<(), String> {
        let deadline = js_sys::Date::now() + 120_000.0;
        while self.stream.len() < need {
            if js_sys::Date::now() > deadline {
                return Err("AFC: timed out waiting for TLS plaintext".into());
            }
            let n = self.read_tls_more(scratch).await?;
            if n == 0 {
                sleep(Duration::from_millis(2)).await;
                continue;
            }
            self.stream.extend_from_slice(&scratch[..n]);
        }
        Ok(())
    }

    async fn recv_afc(&mut self, scratch: &mut [u8]) -> Result<(u64, Vec<u8>), String> {
        self.fill_stream(AFC_HDR, scratch).await?;
        let (entire, _this, _pn, operation) = parse_afc_header(&self.stream[..AFC_HDR])?;
        let entire = entire as usize;
        if entire < AFC_HDR {
            return Err(format!("AFC invalid entire_length {}", entire));
        }
        if entire > 32 * 1024 * 1024 {
            return Err(format!("AFC entire_length {} too large", entire));
        }
        self.fill_stream(entire, scratch).await?;
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

    async fn recv_afc_expect_data(
        &mut self,
        ctx: &str,
        scratch: &mut [u8],
    ) -> Result<Vec<u8>, String> {
        let (op, body) = self.recv_afc(scratch).await?;
        if op == AFC_OP_STATUS {
            let code = Self::afc_status_param1(&body)?;
            return Err(format!("AFC {} STATUS error {}", ctx, code));
        }
        if op != AFC_OP_DATA {
            return Err(format!("AFC {}: expected DATA, op=0x{:x}", ctx, op));
        }
        Ok(body)
    }

    async fn recv_afc_expect_open_res(&mut self, scratch: &mut [u8]) -> Result<u64, String> {
        let (op, body) = self.recv_afc(scratch).await?;
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

    async fn dispatch(&mut self, operation: u64, body: &[u8]) -> Result<(), String> {
        self.packet_num = self.packet_num.wrapping_add(1);
        let pkt = build_afc_packet(self.packet_num, operation, body);
        tls_write_plain_and_flush_wasm(
            &mut self.tls,
            self.hub,
            &mut self.tcp,
            &pkt,
            self.verbose,
        )
        .await
    }

    pub async fn read_directory(
        &mut self,
        path: &str,
        scratch: &mut [u8],
    ) -> Result<Vec<String>, String> {
        let mut p = path.as_bytes().to_vec();
        p.push(0);
        self.dispatch(AFC_OP_READ_DIR, &p).await?;
        let data = self.recv_afc_expect_data("READ_DIR", scratch).await?;
        Ok(parse_string_list(&data))
    }

    pub async fn get_file_info_dict(
        &mut self,
        path: &str,
        scratch: &mut [u8],
    ) -> Result<HashMap<String, String>, String> {
        let mut p = path.as_bytes().to_vec();
        p.push(0);
        self.dispatch(AFC_OP_GET_FILE_INFO, &p).await?;
        let data = self.recv_afc_expect_data("GET_FILE_INFO", scratch).await?;
        Ok(parse_info_dictionary(&data))
    }

    pub async fn file_open(
        &mut self,
        path: &str,
        mode: u64,
        scratch: &mut [u8],
    ) -> Result<u64, String> {
        let mut body = Vec::with_capacity(8 + path.len() + 1);
        body.extend_from_slice(&mode.to_le_bytes());
        body.extend_from_slice(path.as_bytes());
        body.push(0);
        self.dispatch(AFC_OP_FILE_OPEN, &body).await?;
        self.recv_afc_expect_open_res(scratch).await
    }

    pub async fn file_read(
        &mut self,
        handle: u64,
        len: u32,
        scratch: &mut [u8],
    ) -> Result<Vec<u8>, String> {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&handle.to_le_bytes());
        b[8..16].copy_from_slice(&(len as u64).to_le_bytes());
        self.dispatch(AFC_OP_FILE_READ, &b).await?;
        self.recv_afc_expect_data("FILE_READ", scratch).await
    }

    pub async fn file_close(&mut self, handle: u64, scratch: &mut [u8]) -> Result<(), String> {
        let b = handle.to_le_bytes();
        self.dispatch(AFC_OP_FILE_CLOSE, &b).await?;
        let (op, body) = self.recv_afc(scratch).await?;
        if op == AFC_OP_STATUS {
            let code = Self::afc_status_param1(&body)?;
            if code != AFC_E_SUCCESS {
                return Err(format!("AFC FILE_CLOSE STATUS {}", code));
            }
            return Ok(());
        }
        Err(format!("AFC FILE_CLOSE: unexpected op 0x{:x}", op))
    }

    pub async fn remove_path(&mut self, path: &str, scratch: &mut [u8]) -> Result<(), String> {
        let mut p = path.as_bytes().to_vec();
        p.push(0);
        self.dispatch(AFC_OP_REMOVE_PATH, &p).await?;
        let (op, body) = self.recv_afc(scratch).await?;
        if op == AFC_OP_STATUS {
            let code = Self::afc_status_param1(&body)?;
            if code == AFC_E_SUCCESS {
                return Ok(());
            }
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

fn parse_info_dictionary(data: &[u8]) -> HashMap<String, String> {
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
