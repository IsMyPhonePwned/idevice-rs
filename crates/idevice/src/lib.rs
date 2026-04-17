//! Apple USB mux, lockdownd (pairing, TLS), AFC helpers — **blocking**. Uses **libusb** by default; on Unix, [`connect::open_lockdown`] can fall back to **usbmuxd** when the device is busy.
//!
//! Used by the `idevice` CLI and suitable as a dependency for other Rust tools. Low-level framing lives in the `idevice-usb-core` crate.

use std::sync::atomic::{AtomicBool, Ordering};

static DIAGNOSTIC_TRACE: AtomicBool = AtomicBool::new(false);

/// Enable extra **`[crypto]`** logs (pairing / key material sizes and previews) for this process.
/// The `idevice` CLI sets this from **`--lockdown-tls-debug`** together with TLS tracing.
pub fn set_diagnostic_trace(enabled: bool) {
    DIAGNOSTIC_TRACE.store(enabled, Ordering::Relaxed);
}

pub(crate) fn diagnostic_trace_enabled() -> bool {
    DIAGNOSTIC_TRACE.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! console_log {
    ($($t:tt)*) => {
        println!($($t)*)
    };
}

#[macro_export]
macro_rules! console_error {
    ($($t:tt)*) => {
        eprintln!($($t)*)
    };
}

pub mod afc;
pub mod connect;
pub mod crash_reports;
pub mod lockdown;
pub mod lockdown_rustls;
pub mod mux_link;
pub mod pair_record;
pub mod usb;

pub mod crypto;

mod mux_io;
#[cfg(unix)]
mod socket_mux;
#[cfg(unix)]
mod usbmuxd;

mod pair_record_parse;
