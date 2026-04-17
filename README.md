# idevice-rs

Rust workspace for **Apple USB mux**, **lockdownd** (pairing, TLS), **device info**, **syslog relay**, and **crash report copy** — similar in spirit to libimobiledevice tools (`ideviceinfo`, `idevicepair`, `idevicesyslog`, `idevicecrashreport`).

## Prerequisites

- **Rust** (stable), **Cargo**
- **libusb** (for `rusb` on Linux: e.g. `libusb-1.0-0-dev`)
- On **Linux**, if **system `usbmuxd`** already owns the phone, `pair`, `battery` / `run`, and `diagnostics` fall back to the usbmuxd socket (default `/var/run/usbmuxd`, override with `USBMUXD_SOCKET_PATH`) when direct USB open fails with “Resource busy”. **`connect`**, **`mux`**, **`syslog`**, and **`crash-reports`** still require exclusive raw USB access (or stop `usbmuxd` briefly for those) — they need a **second** mux pseudo-TCP after lockdown, which the usbmuxd-only path does not expose yet.
- For the **browser demo**: Chromium (WebUSB), **HTTPS or localhost**, and a user gesture for `navigator.usb.requestDevice`. **Linux:** WebUSB and the CLI are not equivalent — **`idevice-cli`** can use the **usbmuxd** socket when USB is busy; **Chromium cannot**, so you often must stop **`usbmuxd`** (and related services) so the tab can `selectConfiguration` / claim the interface, **or** keep using the native CLI with usbmuxd running.

## Build

From the repository root:

```bash
cargo build
```

This builds `idevice-usb-core`, `idevice`, and the `idevice` CLI (package `idevice-cli`). The WebAssembly crate is **not** built by default; see [WebAssembly & browser demo](#webassembly--browser-demo).

---

## How it works (technical)

Apple exposes a **USB multiplexing (mux)** protocol on a vendor interface: the host wraps **IPv4-style TCP** (SYN, ACK, payload segments) inside USB bulk transfers. **lockdownd** listens on **port 62078** (`LOCKDOWND_PORT`). The Rust stack implements that framing in **`idevice-usb-core`**, then **`idevice`** speaks lockdown **XML plists** (length-prefixed) over the resulting byte stream.

### Stack on the host

```
  +-----------+  USB cable   +-----------------------------+
  |  iPhone   |<============>|  Host OS + libusb (rusb)    |
  | lockdownd |              |  OR usbmuxd socket (Unix)   |
  +-----+-----+              +--------------+--------------+
        |                                    |
        |   Apple USB mux interface          |
        |   (bulk IN/OUT, mux packets)       |
        v                                    v
  +-------------------+              +-------------------+
  | libusb path       |              | usbmuxd path      |
  | MuxLink (USB)     |              | SocketMuxLink    |
  +---------+---------+              +---------+---------+
            |                                    |
            +----------------+-------------------+
                             v
                    +----------------+
                    |  pseudo-TCP    |
                    |  dport 62078   |  <-- single "connection" to lockdownd
                    +--------+-------+
                             |
                             v
                    +----------------+
                    |  lockdownd     |  plist requests / responses
                    +----------------+
```

**Cleartext first:** `QueryType`, `Pair`, `GetValue` (some), `StartSession`, … **Then TLS:** after a successful `StartSession` with `EnableSessionSSL`, the same TCP connection carries **TLS 1.2/1.3** (implemented with **rustls** in **`idevice`**) for `GetValue`, `StartService`, and so on. Pairing uses host-generated or plist-loaded **RSA keys** and certificates shaped like **pymobiledevice3** / **libimobiledevice** records.

### Linux: direct USB vs usbmuxd

When **usbmuxd** holds the device, **libusb** cannot switch configuration or claim the interface (`Resource busy`). For **pair**, **battery** / **run**, and **diagnostics**, **`idevice`** tries libusb first, then opens the **usbmuxd** plist protocol on a Unix socket, asks for a tunnel to port **62078**, and reuses the same lockdown + TLS code over that byte stream.

```
  try open_apple (libusb)
           |
           v
     +-----+-----+
     | success?  |
     +-----+-----+
       |         |
      yes        no (busy on Linux)
       |         |
       v         v
  MuxLink    SocketMuxLink  ---->  usbmuxd  ---->  iPhone
  (USB)      (Unix socket)         daemon          USB (owned by daemon)
```

**Not** on the usbmuxd-only path today: opening a **second** mux TCP from the same tunnel after lockdown (needed for **`syslog`** and **`crash-reports`** the same way as on raw USB). Use **`idevicesyslog`** / **`idevicecrashreport`**, stop usbmuxd briefly, or extend the library with an extra usbmuxd `Connect`.

### Syslog relay (USB mux hub)

**`syslog`** calls **`StartService("com.apple.syslog_relay")`**, then opens a **second** pseudo-TCP to the brokered port. With **`EnableServiceSSL`**, the relay speaks **TLS** (same client certs as lockdownd); decrypted application data is **raw syslog text** streamed to stdout or **`--output`**. Legacy cleartext relays may use **u32 big-endian length + payload** framing (as in older **libimobiledevice** `idevicesyslog`).

### Crash reports (USB mux hub)

After lockdown negotiates a service, **StartService** returns a **port** and whether **SSL** is required. **crash-reports** opens **another** pseudo-TCP through the mux hub to **crashreportmover**, upgrades with the **same** client certs, then **AFC** to **`com.apple.crashreportcopymobile`** — same idea as **libimobiledevice**.

```
  LockdownClient (TLS)                    secondary TCP + TLS
        |                                        |
        |   StartService("com.apple.crashreportcopymobile")
        v                                        v
  +-----------+                         +----------------+
  | lockdownd |                         | mover + AFC    |
  +-----------+                         +----------------+
        ^
        | one mux "TCP" connection
        |
  +-----+-----+
  |  MuxHub   |  <-- routes multiple sport/dport streams on one USB iface
  +-----------+
```

### Browser demo (WASM only)

**WebUSB** + **WASM** open the Apple mux interface, complete pseudo-TCP to **lockdownd**, then run **cleartext** lockdown (`QueryType`, `StartSession`, `GetValue` for battery / diagnostics). **TLS** after `StartSession` is **not** implemented in the browser build; **syslog** and **crash reports** (second mux TCP + TLS, AFC for crash copy) stay on the native **`idevice`** CLI.

```
  +------------------+   WebUSB    +---------------------------+
  | Chromium tab     | ---------->| iPhone (stop usbmuxd on   |
  | index.html WASM  |            | Linux if claim fails)    |
  +------------------+            +----------------------------+
```

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
| `syslog` | Pair, TLS, **`StartService` → `com.apple.syslog_relay`**, stream logs to stdout or **`--output`** (like `idevicesyslog`; **direct USB mux** only) |
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

#### Examples — syslog

Requires **exclusive USB** (see [Prerequisites](#prerequisites)). Stream to **stdout**, or **`-o` / `--output`** to write to a file (**created or truncated** at start).

```bash
cargo run -p idevice-cli -- syslog
cargo run -p idevice-cli -- syslog --pair-record /var/lib/lockdown/XXXXXXXX.plist
cargo run -p idevice-cli -- syslog -o ./iphone.syslog
cargo run -p idevice-cli -- syslog --output /tmp/ios.log --pair-record-dir /var/lib/lockdown
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

# Pair record (skip Pair when load succeeds, for battery/diagnostics/syslog/crash-reports/run)
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
| **`idevice`** | Library: USB, lockdownd + rustls, pair-record parsing, syslog relay, AFC, crash copy. Optional feature **`with-clap`** adds `clap::ValueEnum` on TLS enums for the CLI. |
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

Serve **`web/`** over **HTTP** (WASM loads **`./pkg/*.wasm`** from the same origin). Any static server works, for example:

```bash
cd web && python3 -m http.server 8080
```

Or **`./scripts/serve.sh [PORT]`** — runs **`./scripts/build-wasm.sh`** every time (so **`web/pkg/`** matches the tree), then **`python3 -m http.server`** for **`web/`** (**127.0.0.1** only). To serve without rebuilding: **`SKIP_WASM_BUILD=1 ./scripts/serve.sh`**.

Open **`http://127.0.0.1:8080/index.html`** (or your chosen port).

See [How it works (technical)](#how-it-works-technical) for ASCII diagrams of mux, lockdown, and usbmuxd fallback on the **native** CLI.

- **`web/index.html`**: **cleartext** lockdown only (`QueryType`, `StartSession`, `GetValue` when the phone does not require TLS). Pairing mode sets **HostID** / **SystemBUID** for `StartSession` (random, legacy, or XML plist / typed values) — it does **not** load RSA keys from the plist or run TLS. **Verbose** logs mux/TCP to the browser console (not TLS record hex). If `StartSession` returns **`EnableSessionSSL`** (common for battery/diagnostics on current iOS), the page explains the gap; use the CLI for the same flow as **`idevice`** with **`--pair-record`** and TLS.
- **WebUSB bring-up** (`idevice-wasm` `prepare_apple_usb`): best-effort **`reset()`** when no configuration is active after **`open()`**; **`selectConfiguration`** prefers the configuration that contains the Apple mux interface, then tries other configurations (usbmuxd-rs-style fallback); then **claim** → **clearHalt** on both bulk endpoints → **selectAlternateInterface**, matching the ordering used in the reference WASM lab (same pattern as **`select_usb_configuration_with_fallback`** + **`LockdownClient::new`** in the **`iphone-wasm`** / **`usbmux`** stack).
- **Console**: WASM logs lines prefixed **`[idevice-wasm]`** to the browser **console** (USB steps, mux VERSION/TCP, **`plist-fetch:`** lockdown phases). **`verbose`** in JS enables additional **`console.debug`** detail.
- **Pair-record plist in the page**: **`pairingIdsFromPlistXml`** (XML → HostID/SystemBUID) and **`lockdownFetchWithPlistXml`** (QueryType → StartSession with those IDs → cleartext GetValue for common keys + battery when **`EnableSessionSSL`** is false). **`web/index.html`** exposes **Fetch with pair-record plist** after loading an XML plist file.
- **Native `idevice`**: e.g. **`cargo run -p idevice-cli -- battery --pair-record /var/lib/lockdown/<UDID>.plist`** (optional **`--lockdown-tls-debug`**, **`--lockdown-tls-client-auth`** as needed) performs **StartSession → TLS → GetValue**; also **usbmuxd** fallback for pairing/battery/diagnostics, **`syslog`** / **`crash-reports`** on raw USB, etc.

**Why the CLI works but the browser demo may not:** the CLI upgrades the lockdown connection with **TLS** after `StartSession` using keys from the pair-record plist. The WASM build intentionally omits that step, so behavior matches the CLI only for requests that succeed **without** lockdown TLS.

| Variable | Meaning |
|----------|---------|
| `SKIP_WASM_BUILD` | Set to **`1`** when running **`serve.sh`** to skip **`./scripts/build-wasm.sh`** (only static files changed). |

---

## License

See the `LICENSE` file in this repository.
