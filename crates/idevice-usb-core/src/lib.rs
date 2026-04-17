//! Shared Apple USB mux framing and lockdownd plist snippets for **`iphone-cli`** and **`iphone-wasm`** (WebUSB).
//!
//! Platform-specific I/O (WebUSB vs libusb) stays in each crate; this library holds wire constants,
//! `TcpConn` for blocking transports, and lockdownd XML templates.

mod tcp;
mod wire;

pub mod lockdown_proto;

pub use lockdown_proto::{parse_get_value_string, PairingIds, LOCKDOWN_TLS_SETTLE_MS};
pub use tcp::{BulkTransport, Endpoints, TcpConn, READ_BUF};
pub use wire::{
    build_mux_setup_packet_v2, build_mux_version_request, parse_mux_version_response,
    APPLE_VENDOR_CLASS, APPLE_VENDOR_SUBCLASS, MUX_MAGIC, MUX_PROTO_CONTROL, MUX_PROTO_SETUP,
    MUX_PROTO_TCP, MUX_PROTO_VERSION, MUX_TCP_WINDOW, SELECT_CONFIGURATION_FAILED_LINUX_HINT,
};
