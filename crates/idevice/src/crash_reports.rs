//! **`com.apple.crashreportmover`** + **`com.apple.crashreportcopymobile`** (AFC) — same flow as **libimobiledevice** `idevicecrashreport`.

use std::cell::RefCell;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::afc::{AfcSession, AFC_FOPEN_RDONLY};
use crate::crypto::HostKeys;
use crate::lockdown::LockdownClient;
use crate::lockdown_rustls::tls_read_plain_service;
use crate::lockdown_rustls::{LockdownTlsClientAuth, LockdownTlsSni};
use crate::mux_link::MuxLink;

const MOVER: &str = "com.apple.crashreportmover";
const COPY_MOBILE: &str = "com.apple.crashreportcopymobile";

fn wait_mover_ping(
    tls: &mut rustls::ClientConnection,
    hub: &Rc<RefCell<crate::mux_link::MuxHub>>,
    tcp: &Rc<RefCell<idevice_usb_core::TcpConn>>,
    trace_plain: bool,
) -> Result<(), String> {
    let mut acc: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let n = tls_read_plain_service(tls, hub, tcp, &mut scratch, trace_plain)?;
        if n > 0 {
            acc.extend_from_slice(&scratch[..n]);
            if acc.windows(4).any(|w| w == b"ping") {
                crate::console_log!("[crash] crashreportmover → ping OK");
                return Ok(());
            }
            if acc.len() > 65_536 {
                break;
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    Err(
        "Timed out waiting for crashreportmover `ping` (unlock device; crash logs may be empty)."
            .into(),
    )
}

fn run_crashreport_mover(
    client: &mut LockdownClient,
    mux: &Rc<RefCell<MuxLink>>,
    keys: &HostKeys,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
    tls_debug: bool,
) -> Result<(), String> {
    let (port, ssl) = client.start_service(MOVER)?;
    if !ssl {
        return Err("crashreportmover: StartService did not request SSL".into());
    }
    let hub = client
        .mux_hub()
        .ok_or_else(|| "crash-reports requires USB mux hub".to_string())?;
    let tcp = Rc::new(RefCell::new(mux.borrow().connect_service_tcp(port)?));
    crate::console_log!(
        "[crash] crashreportmover: EnableServiceSSL → TLS (same client certs as lockdownd)"
    );
    let mut tls = crate::lockdown_rustls::handshake_service_tls(
        hub.clone(),
        tcp.clone(),
        keys,
        client_auth,
        tls_sni,
        tls_debug,
    )?;
    wait_mover_ping(&mut tls, &hub, &tcp, tls_debug)?;
    Ok(())
}

fn afc_copy_tree(
    afc: &mut AfcSession,
    dev_dir: &str,
    host_dir: &Path,
    keep: bool,
    filter: Option<&str>,
    remove_all: bool,
    target_root: &Path,
    scratch: &mut [u8],
) -> Result<(), String> {
    let list = afc.read_directory(dev_dir, scratch)?;
    crate::console_log!("[crash] READ_DIR `{}`: {} entries", dev_dir, list.len());
    let dev_prefix = if dev_dir.ends_with('/') {
        dev_dir.to_string()
    } else {
        format!("{}/", dev_dir)
    };
    let host_prefix = if host_dir.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        host_dir.to_path_buf()
    };

    for name in list {
        let source = format!("{dev_prefix}{name}");
        let target_name = if let Some(p) = name.rfind('.') {
            if name[p..].starts_with(".synced") {
                &name[..p]
            } else {
                name.as_str()
            }
        } else {
            name.as_str()
        };
        let target = host_prefix.join(target_name);

        let info = match afc.get_file_info_dict(&source, scratch) {
            Ok(d) => d,
            Err(e) => {
                crate::console_log!("[crash] skip `{}`: {}", source, e);
                continue;
            }
        };

        let st_ifmt = info
            .get("st_ifmt")
            .map(|s| s.trim())
            .unwrap_or("")
            .to_string();
        let st_size: u64 = info
            .get("st_size")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        if st_ifmt == "S_IFLNK" {
            if remove_all {
                let _ = afc.remove_path(&source, scratch);
                continue;
            }
            let link_target = info.get("LinkTarget").map(|s| s.as_str()).unwrap_or("");
            let rel = target.strip_prefix(target_root).unwrap_or(&target);
            crate::console_log!("[crash] Link: {}", rel.display());
            if target.exists() {
                let _ = fs::remove_file(&target);
            }
            #[cfg(unix)]
            {
                let base = std::path::Path::new(link_target)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(link_target);
                if let Err(e) = std::os::unix::fs::symlink(base, &target) {
                    crate::console_log!("[crash] (symlink skipped or failed): {:?} {}", target, e);
                }
            }
            if !keep {
                let _ = afc.remove_path(&source, scratch);
            }
            continue;
        }

        if st_ifmt == "S_IFDIR" {
            if !remove_all {
                let _ = fs::create_dir_all(&target);
            }
            afc_copy_tree(
                afc,
                &source,
                &target,
                keep,
                filter,
                remove_all,
                target_root,
                scratch,
            )?;
            if !remove_all && !keep {
                let _ = afc.remove_path(&source, scratch);
            }
            continue;
        }

        if st_ifmt == "S_IFREG" {
            if let Some(f) = filter {
                if !source.contains(f) {
                    continue;
                }
            }
            if remove_all {
                crate::console_log!("[crash] Remove: {}", source);
                let _ = afc.remove_path(&source, scratch);
                continue;
            }

            let h = afc.file_open(&source, AFC_FOPEN_RDONLY, scratch)?;
            let mut out =
                File::create(&target).map_err(|e| format!("create {:?}: {}", target, e))?;
            let mut total: u64 = 0;
            loop {
                let chunk = afc.file_read(h, 0x1000, scratch)?;
                if chunk.is_empty() {
                    break;
                }
                total += chunk.len() as u64;
                out.write_all(&chunk)
                    .map_err(|e| format!("write {:?}: {}", target, e))?;
                if chunk.len() < 0x1000 {
                    break;
                }
            }
            afc.file_close(h, scratch)?;
            out.sync_all()
                .map_err(|e| format!("sync {:?}: {}", target, e))?;
            drop(out);

            if total != st_size {
                crate::console_log!(
                    "[crash] WARN size mismatch {} vs {} for {}",
                    total,
                    st_size,
                    source
                );
            }

            let rel = target.strip_prefix(target_root).unwrap_or(&target);
            crate::console_log!(
                "[crash] {}: {}",
                if keep { "Copy" } else { "Move" },
                rel.display()
            );

            if !keep {
                let _ = afc.remove_path(&source, scratch);
            }
            continue;
        }

        crate::console_log!(
            "[crash] skip `{}`: unknown st_ifmt={:?} (keys: {:?})",
            source,
            st_ifmt,
            info.keys().collect::<Vec<_>>()
        );
    }
    Ok(())
}

/// Same sequence as **`idevicecrashreport`**: mover → wait for **`ping`**, then AFC on **`com.apple.crashreportcopymobile`** from device root **`.`**.
pub fn copy_crash_reports_mobile(
    client: &mut LockdownClient,
    out_dir: &Path,
    keep: bool,
    filter: Option<&str>,
    remove_all: bool,
    keys: &HostKeys,
    client_auth: LockdownTlsClientAuth,
    tls_sni: LockdownTlsSni,
    tls_debug: bool,
    _tls_settle_ms: u64,
) -> Result<(), String> {
    let mux = client.mux_link().ok_or(
        "crash-reports requires direct USB mux (secondary pseudo-TCP to mover/AFC). \
         With **usbmuxd** holding the device, use Apple’s `idevicecrashreport` / libimobiledevice, \
         or stop usbmuxd briefly for raw USB.",
    )?;
    run_crashreport_mover(client, &mux, keys, client_auth, tls_sni, tls_debug)?;

    let (port, ssl) = client.start_service(COPY_MOBILE)?;
    if !ssl {
        return Err("crashreportcopymobile: StartService did not request SSL".into());
    }
    crate::console_log!("[crash] crashreportcopymobile: EnableServiceSSL → TLS");
    let hub = client
        .mux_hub()
        .ok_or_else(|| "crash-reports: no mux hub (internal)".to_string())?;
    let mut afc = AfcSession::connect(hub, &mux, port, keys, client_auth, tls_sni, tls_debug)?;

    let host = if remove_all {
        PathBuf::from(".")
    } else {
        fs::create_dir_all(out_dir)
            .map_err(|e| format!("create output directory {:?}: {}", out_dir, e))?;
        out_dir.to_path_buf()
    };

    let mut scratch = vec![0u8; 65536];
    afc_copy_tree(
        &mut afc,
        ".",
        &host,
        keep,
        filter,
        remove_all,
        out_dir,
        &mut scratch,
    )?;
    println!("Done.");
    Ok(())
}
