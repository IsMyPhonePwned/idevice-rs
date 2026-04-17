# idevice-rs

Rust workspace for **Apple USB mux**, **lockdownd** (pairing, TLS), **device info**, and **crash report copy** — similar in spirit to libimobiledevice tools (`ideviceinfo`, `idevicepair`, `idevicecrashreport`).

## Prerequisites

- **Rust** (stable), **Cargo**
- **libusb** (for `rusb` on Linux: e.g. `libusb-1.0-0-dev`)
- On **Linux**, if **system `usbmuxd`** already owns the phone, `pair`, `battery` / `run`, and `diagnostics` fall back to the usbmuxd socket (default `/var/run/usbmuxd`, override with `USBMUXD_SOCKET_PATH`) when direct USB open fails with “Resource busy”. **`connect`**, **`mux`**, and **`crash-reports`** still require exclusive raw USB access (or stop `usbmuxd` briefly for those).
- For the **browser demo**: Chromium (WebUSB), **HTTPS or localhost**, and a user gesture for `navigator.usb.requestDevice`. On Linux you may need to stop **`usbmuxd`** so the browser can claim the Apple USB interface.

## Build

From the repository root:

```bash
cargo build
```

This builds `idevice-usb-core`, `idevice`, and the `idevice` CLI (package `idevice-cli`). The WebAssembly crate is **not** built by default; see [WebAssembly & browser demo](#webassembly--browser-demo).

---

## CLI

Run the binary **through Cargo** from the repo root (`--` separates Cargo args from the program):

```bash
cargo run -p idevice-cli -- --help
```

### Subcommands

| Command | Purpose |
|--------|---------|
| `list` | List Apple USB devices (VID `05ac`): bus, addr, PID, serial |
| `connect` | Open device and print USB string descriptors |
| `mux` | USB mux VERSION (+ SETUP on v2) + pseudo-TCP handshake to lockdownd (port 62078) |
| `pair` | Pair with lockdownd (generates RSA host keys each run unless a pair plist is loaded) |
| `battery` | Identify device, pair (or use pair record), `StartSession` + TLS, print `com.apple.mobile.battery` |
| `run` | Same flow as `battery` |
| `diagnostics` | Pair (or pair record), TLS, then many lockdown `GetValue` queries (snapshot; not Apple sysdiagnose) |
| `crash-reports` | Pair, TLS, `crashreportmover` + AFC `crashreportcopymobile` (like `idevicecrashreport`) |

#### Examples — discovery & USB

```bash
cargo run -p idevice-cli -- list
cargo run -p idevice-cli -- connect
cargo run -p idevice-cli -- connect --serial "00008110-001A548E0A8A401E"
cargo run -p idevice-cli -- connect --bus 1 --addr 42
cargo run -p idevice-cli -- mux
```

#### Examples — pairing

```bash
# Fresh pair (unlock iPhone; approve Trust when prompted)
cargo run -p idevice-cli -- pair

# Pair using HostID / keys from a libimobiledevice-style plist (skip interactive Pair if valid)
cargo run -p idevice-cli -- pair --pair-record /var/lib/lockdown/XXXXXXXX.plist

# Auto-pick plist as <dir>/<USB serial>.plist (common on Linux with usbmuxd)
cargo run -p idevice-cli -- pair --pair-record-dir /var/lib/lockdown
```

#### Examples — battery & diagnostics

```bash
cargo run -p idevice-cli -- battery
cargo run -p idevice-cli -- run
cargo run -p idevice-cli -- battery --pair-record-dir /var/lib/lockdown

cargo run -p idevice-cli -- diagnostics
cargo run -p idevice-cli -- diagnostics --pair-record /path/to/UDID.plist
```

#### Examples — crash reports

`crash-reports` takes a host **output directory** as the first argument.

```bash
# Copy crash logs to ./crashes; **keep** copies on the device (omit --no-keep)
mkdir -p ./crashes
cargo run -p idevice-cli -- crash-reports ./crashes

# Copy then **remove** each log from the device after successful copy (“move”)
cargo run -p idevice-cli -- crash-reports ./crashes --no-keep

# Only paths containing a substring (like idevicecrashreport -f)
cargo run -p idevice-cli -- crash-reports ./crashes --filter SpringBoard

# Delete crash logs on device only (no copy); out_dir is ignored for output placement
cargo run -p idevice-cli -- crash-reports . --remove-all
```

### Global flags (all subcommands)

These apply to any subcommand that opens a device (see `--help` for defaults and full text):

```bash
# Device selection (default: first Apple device)
cargo run -p idevice-cli -- battery --serial "YOUR_USB_SERIAL"
cargo run -p idevice-cli -- battery --bus 1 --addr 42

# Pair record (skip Pair when load succeeds, for battery/diagnostics/crash-reports/run)
cargo run -p idevice-cli -- battery --pair-record /path/to/record.plist
cargo run -p idevice-cli -- battery --pair-record-dir /var/lib/lockdown

# TLS quirks (if StartSession/TLS fails with a plist from idevicepair / OpenSSL)
cargo run -p idevice-cli -- battery --pair-record /path/to.plist --lockdown-tls-client-auth root
cargo run -p idevice-cli -- battery --lockdown-tls-sni none
cargo run -p idevice-cli -- battery --lockdown-tls-debug
# `--lockdown-tls-debug`: TLS handshake records, cleartext lockdown AFC/service payloads, `[crypto]` pairing traces
cargo run -p idevice-cli -- battery --lockdown-tls-settle-ms 50

# Pairing trust / passcode polling
cargo run -p idevice-cli -- pair --pair-trust-timeout-secs 300 --pair-trust-poll-secs 5

# New RSA keys: HostID mode (default is random; legacy = fixed WASM-style id)
cargo run -p idevice-cli -- pair --pair-ids random
cargo run -p idevice-cli -- pair --pair-ids legacy

# Rarely needed (see --help): reopen TCP after pair, ValidatePair after pair
cargo run -p idevice-cli -- battery --reopen-lockdown-after-pair
cargo run -p idevice-cli -- battery --validate-pair-after-pair
```

---

## Workspace crates

| Crate | Description |
|-------|-------------|
| **`idevice-usb-core`** | Mux framing, `TcpConn`, lockdownd plist snippets — shared by native CLI and WASM. |
| **`idevice`** | Library: USB, lockdownd + rustls, pair-record parsing, AFC, crash copy. Optional feature **`with-clap`** adds `clap::ValueEnum` on TLS enums for the CLI. |
| **`idevice-cli`** | Binary **`idevice`**: this README’s examples. |
| **`idevice-wasm`** | WebUSB + mux handshake in the browser (Chromium). Built only for **`wasm32-unknown-unknown`**. |

Depend on the library in another project:

```toml
[dependencies]
idevice = { path = "path/to/idevice-rs/crates/idevice" }
idevice-usb-core = { path = "path/to/idevice-rs/crates/idevice-usb-core" }
```

---

## WebAssembly & browser demo

Build the WASM bundle (requires [**wasm-pack**](https://rustwasm.github.io/wasm-pack/installer/)):

```bash
./scripts/build-wasm.sh
```

Output is written to **`web/pkg/`** (listed in `.gitignore`; rebuild after clone).

Serve **`web/`** (including **`index.html`**) with **`python3`** embedded in **`scripts/serve.sh`**, plus a small **`POST /api/cli`** bridge to the host **`idevice`** binary:

```bash
./scripts/serve.sh 8080
# or: BUILD_WASM=1 ./scripts/serve.sh 8080   # build WASM first
```

Open **`http://127.0.0.1:8080/index.html`**.

- **WebUSB** in the page: request device + mux pseudo-TCP to lockdownd (no full TLS/pairing in WASM).
- **Host CLI**: the script runs `target/release/idevice` or `target/debug/idevice` if present; otherwise build with `cargo build -p idevice-cli` or run once `cargo run -p idevice-cli -- --help`.

Environment variables for the embedded server:

| Variable | Meaning |
|----------|---------|
| `PORT` | Listen port (default **8080**; `serve.sh` sets this from its first argument). |
| `IDEVICE_BIN` | Absolute path to the `idevice` executable if it is not under `target/debug` or `target/release`. |

---

## License

See the `LICENSE` file in this repository.
