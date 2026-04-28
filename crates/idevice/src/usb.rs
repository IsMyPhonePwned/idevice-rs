//! libusb (rusb) open + Apple mux interface discovery.

use rusb::{Context, Device, DeviceDescriptor, DeviceHandle, Direction, TransferType, UsbContext};
use std::time::Duration;

use idevice_usb_core::{BulkTransport, Endpoints, SELECT_CONFIGURATION_FAILED_LINUX_HINT};

const APPLE_VID: u16 = 0x05ac;
const APPLE_VENDOR_CLASS: u8 = 255;
const APPLE_VENDOR_SUBCLASS: u8 = 254;

pub struct AppleUsb {
    pub handle: DeviceHandle<Context>,
    pub eps: Endpoints,
    pub ep_out_addr: u8,
    pub ep_in_addr: u8,
    pub target_config: u8,
    pub target_iface: u8,
    pub target_alt: u8,
}

impl BulkTransport for AppleUsb {
    fn bulk_out(&mut self, ep_num: u8, data: &[u8]) -> Result<(), String> {
        let addr = if ep_num == self.eps.ep_out {
            self.ep_out_addr
        } else {
            ep_num
        };
        self.handle
            .write_bulk(addr, data, Duration::from_secs(5))
            .map_err(|e| format!("bulk OUT: {}", e))?;
        Ok(())
    }

    fn bulk_in(&mut self, ep_num: u8, max_len: usize) -> Result<Vec<u8>, String> {
        let addr = if ep_num == self.eps.ep_in {
            self.ep_in_addr
        } else {
            ep_num | 0x80
        };
        let mut buf = vec![0u8; max_len];
        let n = self
            .handle
            .read_bulk(addr, &mut buf, Duration::from_secs(5))
            .map_err(|e| format!("bulk IN: {}", e))?;
        buf.truncate(n);
        Ok(buf)
    }
}

pub fn list_apple_devices() -> Result<Vec<(u8, u8, u16, String)>, String> {
    let ctx = Context::new().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for dev in ctx.devices().map_err(|e| e.to_string())?.iter() {
        let desc = dev.device_descriptor().map_err(|e| e.to_string())?;
        if desc.vendor_id() != APPLE_VID {
            continue;
        }
        let bus = dev.bus_number();
        let addr = dev.address();
        let pid = desc.product_id();
        let serial = read_string_descriptor_simple(&dev, &desc, desc.serial_number_string_index())
            .unwrap_or_default();
        out.push((bus, addr, pid, serial));
    }
    Ok(out)
}

fn read_string_descriptor_simple(
    dev: &Device<Context>,
    _desc: &DeviceDescriptor,
    index: Option<u8>,
) -> Option<String> {
    let idx = index?;
    if idx == 0 {
        return None;
    }
    let h = dev.open().ok()?;
    h.read_string_descriptor_ascii(idx)
        .ok()
        .map(|s| sanitize_usb_descriptor_string(&s))
}

/// rusb's `read_string_descriptor_ascii` can return trailing or interior NUL bytes when the
/// device pads the UTF‑16 buffer (Apple devices have done this on iOS 17). Those bytes break
/// downstream `CString`/path APIs (`std::fs::write` returns `file name contained an unexpected
/// NUL byte`), so we strip controls and trim whitespace before any consumer (USB ID printer,
/// pair-record filename, …) sees the string.
pub(crate) fn sanitize_usb_descriptor_string(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

/// Find (config, iface, alt, bulk endpoints) by scanning all configurations.
fn find_apple_in_device(dev: &Device<Context>) -> Result<(u8, u8, u8, Endpoints, u8, u8), String> {
    let desc = dev.device_descriptor().map_err(|e| e.to_string())?;
    for cfg_idx in 0..desc.num_configurations() {
        let cfg = dev.config_descriptor(cfg_idx).map_err(|e| e.to_string())?;
        let cfg_val = cfg.number();
        for iface in cfg.interfaces() {
            for alt in iface.descriptors() {
                if alt.class_code() != APPLE_VENDOR_CLASS
                    || alt.sub_class_code() != APPLE_VENDOR_SUBCLASS
                {
                    continue;
                }
                let mut ep_out = None;
                let mut ep_in = None;
                let mut ep_out_addr = None;
                let mut ep_in_addr = None;
                for ep in alt.endpoint_descriptors() {
                    if ep.transfer_type() != TransferType::Bulk {
                        continue;
                    }
                    let addr = ep.address();
                    let num = addr & 0x0f;
                    match ep.direction() {
                        Direction::Out => {
                            ep_out = Some(num);
                            ep_out_addr = Some(addr);
                        }
                        Direction::In => {
                            ep_in = Some(num);
                            ep_in_addr = Some(addr);
                        }
                    }
                }
                if let (Some(outn), Some(inn), Some(outa), Some(ina)) =
                    (ep_out, ep_in, ep_out_addr, ep_in_addr)
                {
                    return Ok((
                        cfg_val,
                        alt.interface_number(),
                        alt.setting_number(),
                        Endpoints {
                            ep_out: outn,
                            ep_in: inn,
                        },
                        outa,
                        ina,
                    ));
                }
            }
        }
    }
    Err("No Apple usbmux interface (255/254 + bulk IN/OUT) found".into())
}

fn try_select_configuration(
    handle: &mut DeviceHandle<Context>,
    preferred: u8,
) -> Result<(), String> {
    let dev = handle.device();
    let desc = dev.device_descriptor().map_err(|e| e.to_string())?;
    let mut order = vec![preferred];
    for i in 0..desc.num_configurations() {
        let v = dev
            .config_descriptor(i)
            .map_err(|e| e.to_string())?
            .number();
        if v != preferred {
            order.push(v);
        }
    }
    let mut last = String::new();
    for v in order {
        match handle.set_active_configuration(v) {
            Ok(()) => {
                println!("[usb] active configuration = {}", v);
                return Ok(());
            }
            Err(e) => last = format!("cfg {}: {}", v, e),
        }
    }
    Err(format!(
        "set_active_configuration failed ({}).{}",
        last, SELECT_CONFIGURATION_FAILED_LINUX_HINT
    ))
}

/// Claim mux interface, clear halts, select alternate (matches WASM `LockdownClient::new` USB steps).
pub fn prepare_mux_interface(usb: &mut AppleUsb) -> Result<(), String> {
    let iface = usb.target_iface;
    let alt = usb.target_alt;
    let _ = usb.handle.release_interface(iface);
    let _ = usb.handle.detach_kernel_driver(iface);
    usb.handle
        .claim_interface(iface)
        .map_err(|e| format!("claim_interface: {}", e))?;
    usb.handle
        .clear_halt(usb.ep_out_addr)
        .map_err(|e| format!("clear_halt out: {}", e))?;
    usb.handle
        .clear_halt(usb.ep_in_addr)
        .map_err(|e| format!("clear_halt in: {}", e))?;
    usb.handle
        .set_alternate_setting(iface, alt)
        .map_err(|e| format!("set_alternate_setting: {}", e))?;
    Ok(())
}

pub fn open_apple(
    bus: Option<u8>,
    addr: Option<u8>,
    serial: Option<&str>,
) -> Result<AppleUsb, String> {
    let ctx = Context::new().map_err(|e| e.to_string())?;
    let mut chosen: Option<Device<Context>> = None;
    for dev in ctx.devices().map_err(|e| e.to_string())?.iter() {
        let d = dev.device_descriptor().map_err(|e| e.to_string())?;
        if d.vendor_id() != APPLE_VID {
            continue;
        }
        if let (Some(b), Some(a)) = (bus, addr) {
            if dev.bus_number() == b && dev.address() == a {
                chosen = Some(dev);
                break;
            }
        } else if let Some(s) = serial {
            if let Some(sn) =
                read_string_descriptor_simple(&dev, &d, d.serial_number_string_index())
            {
                if sn == s {
                    chosen = Some(dev);
                    break;
                }
            }
        } else {
            chosen = Some(dev);
            break;
        }
    }
    let dev = chosen.ok_or_else(|| {
        "No matching Apple USB device. Use `idevice list` and `--bus/--addr` or `--serial`."
            .to_string()
    })?;

    let (target_config, target_iface, target_alt, eps, ep_out_addr, ep_in_addr) =
        find_apple_in_device(&dev)?;

    let mut handle = dev.open().map_err(|e| format!("open: {}", e))?;

    let _ = handle.set_auto_detach_kernel_driver(true);

    try_select_configuration(&mut handle, target_config)?;

    Ok(AppleUsb {
        handle,
        eps,
        ep_out_addr,
        ep_in_addr,
        target_config,
        target_iface,
        target_alt,
    })
}

/// One-line summary for scripts: bus, addr, PID, serial (serial from device descriptor).
pub fn format_apple_device_identity(usb: &mut AppleUsb) -> Result<String, String> {
    let dev = usb.handle.device();
    let bus = dev.bus_number();
    let addr = dev.address();
    let desc = dev.device_descriptor().map_err(|e| e.to_string())?;
    let (mfr, prod, ser) = read_usb_strings(usb)?;
    let mfr = if mfr.is_empty() { "(n/a)".into() } else { mfr };
    let prod = if prod.is_empty() {
        "(n/a)".into()
    } else {
        prod
    };
    let ser = if ser.is_empty() { "(n/a)".into() } else { ser };
    Ok(format!(
        "USB bus {:>3}  addr {:>3}  VID {:04X}  PID {:04X}\n\
  Manufacturer: {}\n\
  Product:      {}\n\
  Serial:       {}",
        bus,
        addr,
        desc.vendor_id(),
        desc.product_id(),
        mfr,
        prod,
        ser
    ))
}

/// Product / manufacturer / serial from string descriptors (after device is opened).
pub fn read_usb_strings(usb: &mut AppleUsb) -> Result<(String, String, String), String> {
    let desc = usb
        .handle
        .device()
        .device_descriptor()
        .map_err(|e| e.to_string())?;
    let prod = desc
        .product_string_index()
        .and_then(|i| usb.handle.read_string_descriptor_ascii(i).ok())
        .map(|s| sanitize_usb_descriptor_string(&s))
        .unwrap_or_default();
    let mfr = desc
        .manufacturer_string_index()
        .and_then(|i| usb.handle.read_string_descriptor_ascii(i).ok())
        .map(|s| sanitize_usb_descriptor_string(&s))
        .unwrap_or_default();
    let ser = desc
        .serial_number_string_index()
        .and_then(|i| usb.handle.read_string_descriptor_ascii(i).ok())
        .map(|s| sanitize_usb_descriptor_string(&s))
        .unwrap_or_default();
    Ok((mfr, prod, ser))
}

/// USB **serial number** string (matches typical `/var/lib/lockdown/<serial>.plist` names).
pub fn usb_serial_for_pair_record(usb: &mut AppleUsb) -> Result<String, String> {
    let (_, _, ser) = read_usb_strings(usb)?;
    if ser.is_empty() {
        return Err(
            "USB serial string is empty; pass an explicit `--pair-record /path/to.plist`.".into(),
        );
    }
    Ok(ser)
}
