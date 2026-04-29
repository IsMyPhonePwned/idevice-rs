# idevice-rs

Rust workspace for **Apple USB mux**, **lockdownd** (pairing, TLS), **device info**, **syslog relay**, and **crash report copy** — similar in spirit to libimobiledevice tools (`ideviceinfo`, `idevicepair`, `idevicesyslog`, `idevicecrashreport`).

## Prerequisites

- **Rust** (stable), **Cargo**
- **libusb** (for `rusb` on Linux: e.g. `libusb-1.0-0-dev`)
- On **Linux**, if **system `usbmuxd`** already owns the phone, `pair`, `battery` / `run`, and `diagnostics` fall back to the usbmuxd socket (default `/var/run/usbmuxd`, override with `USBMUXD_SOCKET_PATH`) when direct USB open fails with “Resource busy”. **`connect`**, **`mux`**, **`syslog`**, **`screenshot`**, and **`crash-reports`** still require exclusive raw USB access (or stop `usbmuxd` briefly for those) — they need a **second** mux pseudo-TCP after lockdown, which the usbmuxd-only path does not expose yet.
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

**Not** on the usbmuxd-only path today: opening a **second** mux TCP from the same tunnel after lockdown (needed for **`syslog`**, **`screenshot`**, and **`crash-reports`** the same way as on raw USB). Use **`idevicesyslog`** / **`idevicescreenshot`** / **`idevicecrashreport`**, stop usbmuxd briefly, or extend the library with an extra usbmuxd `Connect`.

### Syslog relay (USB mux hub)

**`syslog`** calls **`StartService("com.apple.syslog_relay")`**, then opens a **second** pseudo-TCP to the brokered port. With **`EnableServiceSSL`**, the relay speaks **TLS** (same client certs as lockdownd); decrypted application data is **raw syslog text** streamed to stdout / **`--output`** in the CLI, or to an `onChunk(text, totalBytes)` callback in the WASM build (`lockdownSyslog`). Legacy cleartext relays may use **u32 big-endian length + payload** framing (as in older **libimobiledevice** `idevicesyslog`); both transports are handled identically by the CLI and the browser tab.

### Screenshot (`com.apple.mobile.screenshotr`, DeviceLink)

**`screenshot`** captures one frame from the device, like libimobiledevice `idevicescreenshot`.
The transport is the usual **secondary mux TCP + TLS**, but the application protocol is
**DeviceLink**: short binary plists wrapped in `u32 BE length` frames, carrying control
arrays that begin with a `DL*` command string.

```
HOST                                                        DEVICE
  |   StartService(com.apple.mobile.screenshotr) → (port, ssl=true)
  |   secondary mux TCP + TLS handshake
  |
  |                              ←  [ "DLMessageVersionExchange", uint(major), uint(minor) ]
  |   [ "DLMessageVersionExchange", "DLVersionsOk", uint(400) ]      →
  |                              ←  [ "DLMessageDeviceReady", "___EmptyParameterString___" ]
  |
  |   [ "DLMessageProcessMessage", { "MessageType":"ScreenShotRequest" } ]   →
  |                              ←  [ "DLMessageProcessMessage",
  |                                     { "MessageType":"ScreenShotReply",
  |                                       "ScreenShotData": <PNG / TIFF bytes> } ]
  |   [ "DLMessageDisconnect", "___EmptyParameterString___" ]              →
```

We advertise DeviceLink **400.0** (same constant libimobiledevice uses for screenshotr) and
refuse if the device announces a higher version. The image bytes are detected by magic:
`\x89PNG` → `.png`, `MM\x00*` / `II*\x00` → `.tiff`, anything else falls back to `.dat` so
you can still inspect the payload.

**Important**: lockdownd only publishes `screenshotr` when a **Developer Disk Image** is
mounted on the device. Otherwise `StartService` returns `InvalidService` — both the CLI and
the WASM build translate that into a friendly hint pointing at Xcode / `pymobiledevice3
mounter auto-mount`. The protocol helpers (binary-plist build/parse, version check, image
detection) live in `idevice-usb-core::screenshotr_proto` and are shared verbatim between
`idevice::screenshotr` (native) and `idevice-wasm::screenshotr_wasm`.

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

### USB mux v2 framing (the bytes on the wire)

Every USB bulk transfer in either direction is one **mux packet**. `idevice-usb-core` speaks **mux v2** — the version negotiated during `VERSION` / `SETUP` against current iOS:

```
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  protocol (u8)  |   reserved (u8)   |  tx_seq (u16, big-endian)  | <-- 4-byte v2 header
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |              followed by a TCP-style header (sport,             |
  |              dport, seq, ack, flags, window, …) and payload     |
  +-----------------------------------------------------------------+
```

`tx_seq` is a per-direction `u16` counter that **must increment by one for every packet sent** — lockdownd silently drops out-of-order frames. `MuxHub::connect_tcp_initial` runs the `VERSION` / `SETUP` exchange once per session; subsequent `connect_tcp_additional` calls reuse the same hub so a single USB interface can carry **lockdownd**, **crashreportmover**, **syslog_relay**, and **AFC** simultaneously.

### Pairing flow (`InvalidPairRecord`-proof)

```
     Host (idevice / idevice-wasm)                  Device (lockdownd:62078)
     ───────────────────────────────                ────────────────────────
                       │   QueryType                              │
                       │ ───────────────────────────────────────► │
                       │   ServiceVersion                         │
                       │ ◄─────────────────────────────────────── │
                       │                                          │
                       │   GetValue("DevicePublicKey")            │
                       │ ───────────────────────────────────────► │
                       │   <data> (PKCS#1 RSA pubkey)             │
                       │ ◄─────────────────────────────────────── │
                       │                                          │
   build cert chain    │                                          │
   (root, host, device)│   Pair { PairRecord, PairingOptions:     │
   sign DevicePub      │          { ExtendedPairingErrors=true } }│
                       │ ───────────────────────────────────────► │
                       │   Error: PairingDialogResponsePending    │
                       │ ◄─────────────────────────────────────── │
                       │       (Trust prompt shown on device)     │
                       │  ⏳ poll on the SAME mux TCP (≥ 15 s     │
                       │      after the first Pending so the      │
                       │      user can type the passcode)         │
                       │   Pair { PairRecord, … }                 │
                       │ ───────────────────────────────────────► │
                       │   { EscrowBag, WiFiMACAddress, HostID }  │
                       │ ◄─────────────────────────────────────── │
                       │                                          │
                       │   StartSession { HostID, SystemBUID }    │
                       │ ───────────────────────────────────────► │
                       │   { SessionID, EnableSessionSSL: true }  │
                       │ ◄─────────────────────────────────────── │
                       │                                          │
                  ╔════╧═════════════════════════════════════════╤╗
                  ║  TLS handshake (rustls)                       ║
                  ║   ClientHello (SNI=device, no resumption)     ║
                  ║   ServerHello, Cert (DeviceCertificate)       ║
                  ║   Cert (HostCertificate) + ClientKeyExchange  ║
                  ║   Finished, Finished                          ║
                  ╚════╤═════════════════════════════════════════╧╝
                       │                                          │
                       │   GetValue / StartService / AFC … (TLS)  │
                       │ ◄────────────────────────────────────► … │
```

The whole loop runs on the **same** lockdown pseudo-TCP — re-opening it between `Pair` retries makes lockdownd drop the in-flight pair state and reply `InvalidPairRecord`, which is why **`--reopen-lockdown-between-pair-retries`** is **off** by default.

### `Pair` plist wire format (libimobiledevice canonical shape)

The XML below is what `lockdown_proto::pair_plist` puts on the wire for a fresh `Pair`. Five subtle invariants matter — getting any of them wrong yields `InvalidPairRecord` after the user accepts Trust, instead of a clean `EscrowBag` reply:

```xml
<plist version="1.0">
  <dict>
    <key>Label</key>            <string>idevice-rs</string>
    <key>Request</key>          <string>Pair</string>
    <key>ProtocolVersion</key>  <string>2</string>
    <key>PairingOptions</key>
    <dict>
      <key>ExtendedPairingErrors</key><true/>
    </dict>
    <key>PairRecord</key>
    <dict>
      <key>DeviceCertificate</key><data>…base64(PEM)…</data>   <!-- (1) CFData -->
      <key>HostCertificate</key>  <data>…base64(PEM)…</data>   <!-- (1) CFData -->
      <key>RootCertificate</key>  <data>…base64(PEM)…</data>   <!-- (1) CFData -->
      <key>HostID</key>           <string>4F8E…UPPERCASE…</string><!-- (2) UPPER UUIDv4 -->
      <key>SystemBUID</key>       <string>3A2B…UPPERCASE…</string>
      <!-- (3) NO RootPrivateKey  — host secret, must never leave the host -->
      <!-- (4) NO HostName at the OUTER dict level (libimobiledevice-style) -->
      <!-- (5) NO WiFiMACAddress  — the device echoes it in the reply -->
    </dict>
  </dict>
</plist>
```

| # | Rule | Why it matters |
|---|------|----------------|
| 1 | Certs and keys go in `<data>` (**CFData**), never `<string>` | lockdownd type-checks the values in the `Pair` request *after* the Trust dialog; a `<string>` parses fine but trips `InvalidPairRecord` on iOS ≥ 14. |
| 2 | `HostID` / `SystemBUID` are **UPPERCASE UUIDv4** | Matches libimobiledevice `generate_uuid()` and `usbmuxd`'s on-disk format (`/var/lib/lockdown/<UDID>.plist`). Lowercase works on some builds, fails silently on others. |
| 3 | `RootPrivateKey` is **stripped** before send | The root private key is a host secret. libimobiledevice removes it from the wire `PairRecord` (it is kept locally, see persistence below); sending it triggers a deferred `InvalidPairRecord` after Trust. |
| 4 | No top-level `HostName` | libimobiledevice keeps `HostName` only inside the locally-saved record. The wire request omits it. |
| 5 | No `WiFiMACAddress` in the request | The *device* echoes its WiFi MAC in the reply. Sending it pre-emptively is what `pymobiledevice3` does on Linux + usbmuxd, but with raw mux it confuses lockdownd on some builds — match libimobiledevice and let the device fill it. |

The certificate chain is generated with `rcgen` + `rsa` (or replayed from a loaded plist) and looks like:

```
  Root  (CN=Root Certification Authority,    serial=0, NotBefore=now-60s,
   │                                        NotAfter=now+10y,
   │                                        BasicConstraints CA:TRUE,
   │                                        KeyUsage keyCertSign,
   │                                        SubjectKeyIdentifier set)
   │
   ├── Host    (CN=<HostID>, signed by Root, serial=0, KeyUsage digitalSignature)
   │
   └── Device  (signed by Root over the device's public RSAPublicKey from
                GetDevicePublicKey, serial=0, BasicConstraints CA:FALSE)
```

All three certs use **`serial = 0`** to match libimobiledevice's `ASN1_INTEGER_set(sn, 0)` — non-zero serials work on macOS/usbmuxd but fail on a non-trivial fraction of phones on direct USB. The `NotBefore` is back-dated by ~1 minute to absorb host/device clock skew; `NotAfter` is `now + 10 years`.

### `EscrowBag` & pair record on disk

A successful `Pair` reply contains an `EscrowBag` (CFData) — the cryptographic material that lets the host pop StartSession + TLS without showing Trust again. `lockdown_proto::parse_escrow_bag` decodes it; the CLI / WASM then write the libimobiledevice-shape XML plist to disk:

```
  $XDG_CONFIG_HOME/idevice-rs/pair-records/<UDID>.plist
                                       │
                                       │       <plist><dict>
                                       │         <key>DeviceCertificate</key><data>…</data>
                                       │         <key>HostCertificate</key>  <data>…</data>
                                       │         <key>HostPrivateKey</key>   <data>…</data>   ← kept locally,
                                       │         <key>RootCertificate</key>  <data>…</data>      not sent
                                       │         <key>RootPrivateKey</key>   <data>…</data>
                                       │         <key>HostID</key>           <string>…</string>
                                       │         <key>SystemBUID</key>       <string>…</string>
                                       │         <key>WiFiMACAddress</key>   <string>…</string>  ← from device
                                       │         <key>EscrowBag</key>        <data>…</data>      ← from device
                                       │       </dict></plist>
                                       │
                                       └── Same shape as `idevicepair` / `pymobiledevice3 pair`,
                                           interchangeable with `/var/lib/lockdown/<UDID>.plist`.
```

The flow shared between native CLI and the browser tab:

```
  ┌──────────────────────┐                  ┌──────────────────────┐
  │   First Pair (CLI)   │  →  saves XML →  │  ~/.config/idevice-  │
  │   accept Trust ⏳    │                  │  rs/pair-records/    │
  └──────────┬───────────┘                  │  <UDID>.plist        │
             │                              └──────────┬───────────┘
             │                                         │ auto-loaded by
             │                                         ▼
  ┌──────────▼──────────┐  ←  same plist  ←  ┌──────────────────────┐
  │  Browser tab        │                    │  CLI battery /       │
  │  Pair record loaded │                    │  diagnostics /       │
  │  → StartSession+TLS │                    │  syslog / crashes    │
  │  → GetValue / AFC   │                    │  → no Trust prompt   │
  └─────────────────────┘                    └──────────────────────┘
```

Use **`--no-auto-pair-record-cache`** to force a fresh `Pair`, **`--save-pair-record PATH`** to override the location, or **`--no-save-pair-record`** to keep memory-only.

### Browser demo (WASM)

**WebUSB** + **WASM** open the Apple mux interface, complete pseudo-TCP to **lockdownd**, run **`QueryType`** / **`StartSession`**, and — when the device sets **`EnableSessionSSL`** — upgrade the same connection to **TLS 1.2/1.3 with `rustls`**, the same way the native CLI does. **`Pair`** (random / legacy host keys, with on-device Trust polling), **`GetValue`** batches (battery + diagnostics), **`crashreportmover` + AFC** crash copy, and pair-record load/save all run **inside the browser tab**.

```
  +------------------+   WebUSB    +-----------------------------+
  |  Chromium tab    | ----------> | iPhone (stop usbmuxd on    |
  |  index.html WASM |             | Linux if claim fails)      |
  |                  |             +-----------------------------+
  |  Rust → wasm32   |
  |  + rustls (TLS)  |    Same wire format as the CLI:
  |  + rcgen (certs) |    mux v2 → pseudo-TCP:62078 → lockdown
  |  + rsa (host RSA)|    → cleartext Pair → TLS StartSession
  +------------------+    → GetValue / StartService → AFC
```

The page exposes pair-record plists that are **byte-compatible** with `idevicepair` / `pymobiledevice3` — generate one in the browser and use it from the CLI (or vice-versa) without re-pairing. Verbose mode logs every mux frame, pseudo-TCP segment, and TLS phase in the browser DevTools console under the **`[idevice-wasm]`** prefix.

---

## CLI

The binary is named **`idevice`** (package `idevice-cli`). All examples below run it through Cargo from the repo root — `--` separates Cargo's args from the program's args:

```bash
cargo run -p idevice-cli -- --help
```

### Quick start (30 seconds)

```bash
# 1. Discover the device on USB (Apple VID 0x05ac)
cargo run -p idevice-cli -- list

# 2. Verify the mux + pseudo-TCP path to lockdownd (no pairing yet)
cargo run -p idevice-cli -- mux

# 3. First pair: unlock the iPhone, approve the “Trust this computer?” prompt, type passcode.
#    On success we save a libimobiledevice-shape pair record (with EscrowBag) under
#    $XDG_CONFIG_HOME/idevice-rs/pair-records/<UDID>.plist (~/.config/idevice-rs/... by default).
cargo run -p idevice-cli -- pair

# 4. Anything afterwards (battery / diagnostics / syslog / crash-reports) auto-loads the saved
#    record from the cache, skips Pair entirely (no more Trust prompt), and goes straight to
#    StartSession → TLS → GetValue.
cargo run -p idevice-cli -- battery
```

The cache layout matches `idevicepair pair` / `pymobiledevice3 pair`, so the same plist works
with **`--pair-record`** here, with `pymobiledevice3 --pair-record`, and (after copying it to
`/var/lib/lockdown/<UDID>.plist`) with `idevicepair`. Delete the file under
`~/.config/idevice-rs/pair-records/` to force a fresh `Pair` on the next run, or pass
**`--no-auto-pair-record-cache`** for a one-shot bypass.

If `usbmuxd` already owns the USB device on Linux, point at its on-disk pair records once and the CLI will reuse them instead of re-pairing:

```bash
cargo run -p idevice-cli -- battery --pair-record-dir /var/lib/lockdown
```

### Subcommand summary

| Command | Purpose |
|--------|---------|
| `list` | List Apple USB devices (VID `05ac`): bus, addr, PID, serial. |
| `connect` | Open the device and print USB string descriptors (manufacturer / product / serial). |
| `mux` | USB mux **VERSION** (+ **SETUP** on v2) + pseudo-TCP handshake to lockdownd on port **62078**. |
| `pair` | Run **`Pair`** against lockdownd. With **`--pair-record[-dir]`**, signs the pairing with keys from the plist instead of generating new RSA material. |
| `battery` | Identify device → pair (or load record) → **`StartSession`** + optional **TLS** → **`GetValue com.apple.mobile.battery`**. |
| `run` | Alias of `battery` (kept for muscle memory; same flow). |
| `diagnostics` | Same as `battery`, then ~40 lockdown **`GetValue`** queries grouped into Identity, Network/cellular, Locale, Activation, Storage (with human-readable byte counts), iTunes, and Battery — **not** Apple sysdiagnose. |
| `syslog` | After TLS, **`StartService` → `com.apple.syslog_relay`**, stream to stdout or `-o FILE` (like `idevicesyslog`; direct USB mux only). |
| `screenshot [PATH]` | After TLS, **`StartService` → `com.apple.mobile.screenshotr`**, run the DeviceLink handshake and save one PNG/TIFF (like `idevicescreenshot`). Requires a mounted Developer Disk Image. |
| `pcap -o FILE` | After TLS, **`StartService` → `com.apple.pcapd`**, decode each `device_packet_struct`, write a libpcap (`LINKTYPE_ETHERNET`) file Wireshark can open (like `pymobiledevice3 pcap`). Optional `--filter-process` / `--filter-interface` / `--max-packets` / `--max-bytes`. |
| `crash-reports OUT_DIR` | After TLS, open **`com.apple.crashreportmover`** + **AFC** to **`com.apple.crashreportcopymobile`**, copy logs into `OUT_DIR` (like `idevicecrashreport`). |

`cargo run -p idevice-cli -- <CMD> --help` prints the full clap help with defaults.

### Subcommand reference

Each block below lists the **positional args** and **subcommand-specific flags**. See [Global flags](#global-flags) for the device / pairing / TLS options shared by every command.

#### `list`

No arguments. Prints `bus`, `addr`, `PID`, and USB serial for every Apple device (VID `0x05ac`).

```bash
cargo run -p idevice-cli -- list
```

#### `connect`

Opens the USB device (selected via global `--serial` / `--bus`+`--addr`) and prints its USB string descriptors. Useful to confirm Chromium / a native client is **not** holding the interface.

```bash
cargo run -p idevice-cli -- connect
cargo run -p idevice-cli -- connect --serial 00008110-001A548E0A8A401E
cargo run -p idevice-cli -- connect --bus 1 --addr 42
```

#### `mux`

Runs only the USB-side handshake: `prepare_mux_interface` → mux **VERSION** (and **SETUP** on mux v2) → pseudo-TCP **SYN/ACK** to lockdownd on port `62078`. Does **not** send a lockdown plist. Use as a smoke test when claim / TCP fails.

```bash
cargo run -p idevice-cli -- mux
```

#### `pair`

Generates host RSA keys (or loads them from `--pair-record[-dir]`) and runs lockdown **`Pair`**. If the device replies **`PairingDialogResponsePending`** or **`PasswordProtected`**, the command keeps polling (`--pair-trust-poll-secs`) and re-opening the lockdown TCP between attempts until it succeeds or **`--pair-trust-timeout-secs`** elapses.

```bash
# Fresh pair — unlock the phone and tap Trust when prompted
cargo run -p idevice-cli -- pair

# Re-pair using existing libimobiledevice / usbmuxd record
cargo run -p idevice-cli -- pair --pair-record /var/lib/lockdown/00008110-001A548E0A8A401E.plist

# Auto-pick `<dir>/<USB-serial>.plist`
cargo run -p idevice-cli -- pair --pair-record-dir /var/lib/lockdown

# Customise polling: wait 5 minutes, poll every 5 s
cargo run -p idevice-cli -- pair --pair-trust-timeout-secs 300 --pair-trust-poll-secs 5

# Force fixed (legacy / WASM-style) HostID
cargo run -p idevice-cli -- pair --pair-ids legacy
```

#### `battery` / `run`

Full happy-path flow. Identifies the phone over USB (or over usbmuxd as fallback), runs **`Pair`** (skipped if a pair record is loaded), then **`StartSession`**, optionally upgrades to TLS when the response sets `EnableSessionSSL`, and finally prints `com.apple.mobile.battery` as plist XML.

```bash
cargo run -p idevice-cli -- battery
cargo run -p idevice-cli -- battery --pair-record-dir /var/lib/lockdown
cargo run -p idevice-cli -- run
```

#### `diagnostics`

Same flow as `battery`, then iterates every entry in `LOCKDOWN_DIAGNOSTIC_GET_VALUES` (device class, MAC addresses, IMEI / MEID / ICCID, region, locale, developer-mode + passcode flags, disk capacity, battery dict, …) and prints them as labelled plist sections. The same constant feeds the WASM **Diagnostics** action, which renders the result as a sectioned report and a **Device snapshot** card. **Not** equivalent to Apple’s `sysdiagnose`.

```bash
cargo run -p idevice-cli -- diagnostics
cargo run -p idevice-cli -- diagnostics --pair-record /path/to/UDID.plist
```

#### `syslog`

After `StartSession` + TLS, calls **`StartService("com.apple.syslog_relay")`**, opens a **second** mux pseudo-TCP to the brokered port, and streams the relay’s decrypted application data. Only works on **direct USB mux** (the usbmuxd-only path does not yet open a second tunnel).

| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output PATH` | stdout | Write the syslog stream to `PATH` (truncates the file at start). |

```bash
cargo run -p idevice-cli -- syslog
cargo run -p idevice-cli -- syslog -o ./iphone.syslog
cargo run -p idevice-cli -- syslog --output /tmp/ios.log --pair-record-dir /var/lib/lockdown
```

#### `screenshot [PATH]`

After `StartSession` + TLS, calls **`StartService("com.apple.mobile.screenshotr")`**, opens a **second** mux pseudo-TCP, runs the **DeviceLink** version exchange (announcing version `400.0`, same as libimobiledevice), then sends `ScreenShotRequest`. The reply’s `ScreenShotData` is decoded as **PNG** (iOS 9+) or **TIFF** by magic and saved to disk.

Requires a mounted **Developer Disk Image** — without it lockdownd answers `InvalidService` and the CLI prints a hint pointing at Xcode / `pymobiledevice3 mounter auto-mount`.

| Arg | Default | Description |
|-----|---------|-------------|
| `PATH` *(positional)* | `screenshot-<UTC>.<png|tiff>` (auto-bumped on collision, like `idevicescreenshot`) | Output path or basename. If `PATH` already has an extension it is used verbatim; otherwise the detected extension is appended. |

```bash
cargo run -p idevice-cli -- screenshot                       # writes screenshot-2026-04-28-09-30-12.png
cargo run -p idevice-cli -- screenshot ./shots/home          # writes ./shots/home.png (created on demand)
cargo run -p idevice-cli -- screenshot lockscreen.png        # writes lockscreen.png exactly
cargo run -p idevice-cli -- screenshot --pair-record-dir /var/lib/lockdown
```

#### `pcap -o FILE`

After `StartSession` + TLS, calls **`StartService("com.apple.pcapd")`**, opens a **second** mux pseudo-TCP, upgrades it to TLS, then loops decoding `<u32 BE length><bplist00 of CFData(device_packet_struct)>` frames. Each accepted frame becomes one **libpcap** record (`LINKTYPE_ETHERNET`, snaplen `65535`) — Wireshark / `tcpdump -r FILE` open it directly. Cellular packets (`pdp_ip*`, `frame_pre_length == 0`) get a synthetic Ethernet II header so IPv4/IPv6 dissectors stay happy, exactly like `pymobiledevice3 pcap`.

```text
                +-------------------+         +---------------------+
TLS plaintext   | u32 BE length     |  bplist | Value::Data(...)    |
read loop  ---> |  of plist payload | -----> | parse device_packet  |
                +-------------------+         +---------------------+
                                                       |
                                                       v
              [16-byte rec hdr][14-byte fake Ethernet][raw IP packet]   --> .pcap
```

| Arg / Flag | Default | Description |
|------------|---------|-------------|
| `-o, --output FILE` | — | Output libpcap path. Use `-` to write to stdout (e.g. `… pcap -o - --quiet | wireshark -k -i -`). |
| `--max-packets N` | `0` (∞) | Stop after writing `N` accepted records to the file. |
| `--max-bytes N` | `0` (∞) | Stop once the libpcap file exceeds `N` bytes (header + records). |
| `--filter-process VAL` | none | Drop packets whose pid/comm/ecomm doesn't match `VAL` (numeric pid or process name). Same semantics as `pymobiledevice3 pcap --process`. |
| `--filter-interface IF` | none | Drop packets whose `interface_name` isn't `IF` (`en0`, `pdp_ip0`, `awdl0`, …). |
| `--quiet` | off | Suppress the per-packet status line (handy when streaming to stdout). |

```bash
# Capture 200 packets to capture.pcap, then open it
cargo run -p idevice-cli -- pcap -o capture.pcap --max-packets 200
wireshark capture.pcap

# Live tail through tcpdump (every banner / status line is routed to stderr in `-o -` mode so
# stdout stays a pure libpcap byte stream; otherwise tcpdump rejects it as "unknown file format")
cargo run -p idevice-cli -- pcap -o - --quiet | tcpdump -r - -nn
cargo run -p idevice-cli -- pcap -o - --quiet | wireshark -k -i -

# Only Safari traffic on cellular
cargo run -p idevice-cli -- pcap -o safari-cell.pcap \
  --filter-process mobilesafari --filter-interface pdp_ip0
```

> When `-o -` is selected the CLI swaps process **fd 1 → fd 2** before any of the pair / TLS
> helpers run, so every `println!` from the existing flow lands on stderr while the libpcap
> bytes flow on the original stdout FD. Downstream pipes that close early (`tcpdump | head`,
> Wireshark window closed, …) are detected and exit cleanly instead of panicking with
> `failed printing to stdout: Broken pipe`.

> The TLS feeder used by `pcap` / `syslog` / `screenshot` / `crash-reports` interleaves
> **feed → process → drain → repeat** on each ciphertext segment instead of consuming it whole.
> iOS bursts can pack multiple ~16 KiB TLS records back-to-back inside one mux segment; rustls
> caps its decrypted-plaintext buffer at `MAX_PLAINTEXT_SIZE = 16 KiB` and otherwise rejects
> further `read_tls` with `received plaintext buffer full`. Any unfed ciphertext is parked on
> `TcpConn::pending_tls_in` and consumed on the next call so record order is preserved across
> reads.

#### `crash-reports OUT_DIR`

After `StartSession` + TLS, opens **`crashreportmover`** + **AFC** (`crashreportcopymobile`) and walks the device’s `CrashReporter` tree. Files are written under `OUT_DIR` mirroring their on-device paths.

| Arg / Flag | Default | Description |
|------------|---------|-------------|
| `OUT_DIR` *(positional)* | — | Host output directory. Created if missing. Ignored when `--remove-all` is set. |
| `--no-keep` *(alias `--move-from-device`)* | off (keep) | After a successful copy, delete the file on the device (`idevicecrashreport` *without* `-k`). |
| `--filter SUBSTR` | none | Only copy paths whose name contains `SUBSTR` (like `idevicecrashreport -f`). |
| `--remove-all` | off | **Delete** every crash log on the device, do not copy anything (`idevicecrashreport --remove-all`). |

```bash
mkdir -p ./crashes

# Copy and keep originals on the device (default since v0.x)
cargo run -p idevice-cli -- crash-reports ./crashes

# Copy then delete each report on the device after a successful copy
cargo run -p idevice-cli -- crash-reports ./crashes --no-keep

# Filter by substring (e.g. only SpringBoard panics)
cargo run -p idevice-cli -- crash-reports ./crashes --filter SpringBoard

# Delete-only mode (host dir is unused)
cargo run -p idevice-cli -- crash-reports . --remove-all
```

### Global flags

Available on every subcommand that opens a device. Set with `--flag VALUE` (or `--flag` for boolean switches) **before** the subcommand name on the command line — clap accepts either order, but putting them up front is unambiguous.

#### Device selection

| Flag | Default | Description |
|------|---------|-------------|
| `--serial STR` | — | Match the USB serial string (UDID with hyphens, as printed by `list`). |
| `--bus N` | — | USB bus number (decimal). Must be combined with `--addr`. |
| `--addr N` | — | USB device address (decimal). Must be combined with `--bus`. |

If none are given, the **first** Apple USB device is used. `--serial` takes precedence over `--bus`/`--addr`.

#### Pair record loading and saving (skip `Pair` for `run`/`battery`/`diagnostics`/`syslog`/`crash-reports`)

| Flag | Default | Description |
|------|---------|-------------|
| `--pair-record PATH` | — | Load `HostID`, `SystemBUID`, and PEM keys/certs from a libimobiledevice-style XML plist. |
| `--pair-record-dir DIR` | — | If `--pair-record` is unset, load `DIR/<USB-serial>.plist` (typical `--pair-record-dir /var/lib/lockdown`). |
| `--save-pair-record PATH` | — | After a successful `Pair`, write the libimobiledevice-shape pair record (host RSA keys, certs, `HostID`, `SystemBUID`, `EscrowBag`, `WiFiMACAddress`) to `PATH` instead of the default cache. Compatible with `idevicepair` / `pymobiledevice3 --pair-record`. Contains private keys; **`chmod 600`** if the host is shared. |
| `--no-save-pair-record` | off | Skip the auto-save after a successful `Pair`. By default the CLI persists the record under `$XDG_CONFIG_HOME/idevice-rs/pair-records/<UDID>.plist` so the next `battery`/`diagnostics`/`syslog`/`crash-reports` run skips `Pair` and the iPhone Trust prompt. |
| `--no-auto-pair-record-cache` | off | Skip auto-loading from `$XDG_CONFIG_HOME/idevice-rs/pair-records/<UDID>.plist` when no `--pair-record[-dir]` is given. Use this to force a fresh `Pair` (e.g. while debugging). |

**Auto-save & auto-load.** Without any pair-record flag, the CLI looks for
`$XDG_CONFIG_HOME/idevice-rs/pair-records/<USB-serial>.plist` (falls back to
`$HOME/.config/idevice-rs/pair-records/...`) and uses it if present. After a successful `Pair`,
it writes the same path so subsequent runs reuse it. With `--pair-record-dir DIR` set, the save
path becomes `DIR/<USB-serial>.plist`. With `--save-pair-record PATH`, that exact path is used.

#### Pairing behaviour

| Flag | Default | Description |
|------|---------|-------------|
| `--pair-ids {random,legacy}` | `random` | How to mint `HostID`/`SystemBUID` when generating new keys. `random` ≈ pymobiledevice3 / libimobiledevice. `legacy` is the fixed WASM-style id (can yield `InvalidPairRecord` if the phone has stale state). Ignored when a pair record is loaded. |
| `--pair-trust-timeout-secs SECS` | `120` | Total time to keep retrying `Pair` while lockdownd returns `PairingDialogResponsePending` / `PasswordProtected`. |
| `--pair-trust-poll-secs SECS` | `4` | Base interval between `Pair` retries. After `PairingDialogResponsePending` the CLI extends each wait to **≥ 15 s** so you have time to enter the passcode. |
| `--reopen-lockdown-between-pair-retries` | off | Reopen the lockdown mux TCP between `Pair` retries (legacy behaviour, mirrors the WASM build). Off by default — libimobiledevice / pymobiledevice3 retry on the **same** TCP, and reopening makes lockdownd drop the in-flight pair state and reply `InvalidPairRecord` on most current iOS builds. |
| `--reopen-lockdown-after-pair` | off | Open a **new** mux TCP to lockdownd after a successful `Pair` before `StartSession`. Workaround for some builds; libimobiledevice does **not** do this. |
| `--validate-pair-after-pair` | off | Send a `ValidatePair` after `Pair`. Modern iOS often **resets** the session if you do — leave off unless you know you need it (older iOS / supervised flows). |

#### TLS knobs (after `EnableSessionSSL`)

| Flag | Default | Description |
|------|---------|-------------|
| `--lockdown-tls-client-auth {host,root,chain}` | `host` | Client cert presented by rustls. `host` matches pymobiledevice3 / WASM. `root` matches libimobiledevice / OpenSSL records. `chain` sends `host` + `root` together. |
| `--lockdown-tls-sni {device,none}` | `device` | SNI in `ClientHello`. `device` is the jkcoxson/idevice default; `none` ≈ libimobiledevice (no SNI). |
| `--lockdown-tls-settle-ms MS` | `LOCKDOWN_TLS_SETTLE_MS` (small) | Pause between `StartSession` and TLS `ClientHello`. **0** matches libimobiledevice. **Avoid multi-second values** — lockdownd will close the mux TCP first (surfaces as `sessionUpcall` / TLS `wrong version number`). |
| `--lockdown-tls-debug` | off | Verbose log for TLS handshake records, cleartext lockdown / AFC / service payloads, and `[crypto]` pairing / key-load traces. |

```bash
# Common combos
cargo run -p idevice-cli -- battery --pair-record /path/to.plist --lockdown-tls-client-auth root
cargo run -p idevice-cli -- battery --lockdown-tls-sni none
cargo run -p idevice-cli -- battery --lockdown-tls-debug
cargo run -p idevice-cli -- battery --pair-record-dir /var/lib/lockdown --lockdown-tls-settle-ms 50
```

### Environment variables

| Variable | Used by | Effect |
|----------|---------|--------|
| `USBMUXD_SOCKET_PATH` | usbmuxd fallback in **`idevice`** | Override the default `/var/run/usbmuxd` when libusb returns *Resource busy* on Linux. |
| `RUST_LOG` | `tracing-subscriber` (when enabled in callers) | Standard env-logger / tracing filter. The CLI itself uses `println!`, but library traces (e.g. `[crypto]`, `[mux]`) honour this when logging is wired up. |
| `RUST_BACKTRACE` | Rust runtime | `1` or `full` to print backtraces on a panic. |

### Exit behaviour

The CLI exits **`0`** on success and **`1`** on any error (`Err(String)` returned by a subcommand is printed to **stderr** before exiting). `Pair` failures inside `run` / `battery` / `diagnostics` / `syslog` / `crash-reports` print a hint and exit **`0`** without running TLS / telemetry — re-run after fixing the Trust prompt.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `Resource busy` while opening USB | `usbmuxd` (Linux) or another client owns the interface. | Stop `usbmuxd` briefly (`sudo systemctl stop usbmuxd`), or pass `--pair-record-dir /var/lib/lockdown` so `pair`/`battery`/`diagnostics`/`run` can fall back to the usbmuxd socket. `syslog` and `crash-reports` still need raw USB. |
| `Timed out … waiting for unlock and Trust` | Phone locked / Trust prompt missed. | Unlock the phone, tap **Trust**, type the passcode, increase `--pair-trust-timeout-secs`, and try again. |
| `InvalidPairRecord` after `PairingDialogResponsePending` | Trust dismissed (Don’t Trust), stale pairing on the device, or `--pair-ids legacy` clashing with new RSA keys. The retry loop runs on the same lockdown TCP as `Pair` (libimobiledevice / pymobiledevice3 style); reopening the TCP between attempts is what made lockdownd reply `InvalidPairRecord` on current iOS, so leave `--reopen-lockdown-between-pair-retries` **off**. | Run `cargo run -p idevice-cli -- pair --pair-ids random`, or **Settings → General → Transfer or Reset → Reset Location & Privacy**, then retry. You can also pair externally with `idevicepair` / `pymobiledevice3` and load the record with `--pair-record`. As a last resort try `--reopen-lockdown-between-pair-retries` (only helps on a small subset of devices). |
| `StartSession` rejected with `InvalidHostID` | Pair did not actually complete on the device. | Re-run `cargo run -p idevice-cli -- pair`, accept Trust, then re-run the action. |
| TLS `wrong version number` / `sessionUpcall` right after `ClientHello` | `--lockdown-tls-settle-ms` too high, or wrong client cert. | Lower the settle (e.g. `0` or `50`). Try `--lockdown-tls-client-auth root` and/or `--lockdown-tls-sni none` for libimobiledevice-shaped pair records. Re-run with `--lockdown-tls-debug` to see exactly where the handshake breaks. |
| `syslog` / `crash-reports` fail on Linux while `pair`/`battery` works | The usbmuxd socket fallback only exposes a single mux TCP — these commands need a **second** tunnel. | Stop `usbmuxd` to get raw USB access, or use `idevicesyslog` / `idevicecrashreport` until the library exposes a second `Connect` over usbmuxd. |
| Battery / diagnostics print empty plist | `EnableSessionSSL` was not set and the request fell back to cleartext on a TLS-required iOS. | Make sure pairing succeeded; if you load a libimobiledevice record, try `--lockdown-tls-client-auth root --lockdown-tls-sni none`. |

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

See [How it works (technical)](#how-it-works-technical) for ASCII diagrams of mux, lockdown, the pair handshake, the canonical `Pair` plist, and the pair-record persistence flow shared with the native CLI.

#### What the page can actually do

| Step | Tab (WebUSB + WASM) | Native CLI (`idevice`) |
|------|---------------------|------------------------|
| USB claim + mux v2 handshake | ✅ (Chromium WebUSB) | ✅ (libusb / `rusb`) |
| pseudo-TCP to `lockdownd:62078` | ✅ | ✅ |
| `Pair` (random / legacy host RSA), Trust polling | ✅ — with **`rcgen`** + **`rsa`** in `idevice-wasm` | ✅ |
| Pair-record plist load (libimobiledevice / usbmuxd shape) | ✅ — drag-and-drop XML in step 2 | ✅ — `--pair-record` / `--pair-record-dir` |
| Pair-record plist save | ✅ — auto-cached in `localStorage` + downloaded | ✅ — `~/.config/idevice-rs/pair-records/<UDID>.plist` |
| `StartSession` + TLS upgrade (rustls) | ✅ — same client-auth / SNI knobs as the CLI | ✅ |
| `GetValue` snapshot (Identity, Cellular, Locale, Activation, Storage, Battery) | ✅ — sectioned report rendered as a Device snapshot card | ✅ — CLI prints raw plists |
| `crashreportmover` + AFC crash copy | ✅ — second mux TCP + TLS, files streamed to browser | ✅ |
| `syslog_relay` (live stream + Save) | ✅ — second mux TCP + TLS, chunks pushed via `onChunk` callback | ✅ |
| `mobile.screenshotr` (PNG / TIFF) | ✅ — second mux TCP + TLS, DeviceLink handshake, image bytes returned | ✅ — `screenshot [PATH]` subcommand |
| `pcapd` (RVI → libpcap) | ✅ — second mux TCP + TLS, framed CFData decoded into libpcap records, full `.pcap` returned to JS for download | ✅ — `pcap -o FILE` subcommand (filters, max packets/bytes/duration; `-o -` streams to stdout for `tcpdump -r -`) |
| usbmuxd Unix-socket fallback (Linux) | ❌ (Chromium can't talk to `/var/run/usbmuxd`) | ✅ |

#### Index.html action map

| Section | What it does | Underlying WASM export |
|---------|--------------|------------------------|
| **Step 1 → Mux test** | mux `VERSION` (+ `SETUP` on v2), pseudo-TCP SYN/ACK to lockdownd. | `muxLockdownHandshake` |
| **Step 1 → QueryType** | mux + lockdownd `QueryType` (cleartext). | `lockdownQueryType` |
| **Step 2 → Pair (random / legacy)** | Generate RSA host chain → `Pair` → poll Trust → cache + download XML pair record. | `lockdownPair` |
| **Step 2 → Load plist** | Parse a libimobiledevice / usbmuxd / CLI-saved pair record XML; reuse it without Trust. | `pairingIdsFromPlistXml` |
| **Step 3 → Battery** | `QueryType` → `StartSession` → optional TLS → `GetValue com.apple.mobile.battery`. | `lockdownBattery` |
| **Step 3 → Diagnostics** | Same prefix, then ~40 `GetValue` queries grouped into Identity / Cellular / Locale / Activation / Storage / Battery. Mirrors headline values into the **Device snapshot** card. | `lockdownDiagnostics` |
| **Step 3 → Fetch with plist** | Pair-record-only path: `StartSession` + TLS + the same sectioned report (no `Pair`). | `lockdownFetchWithPlistXml` |
| **Step 3 → Take screenshot** | After TLS, opens `com.apple.mobile.screenshotr` on a secondary mux TCP, performs the DeviceLink version exchange, then sends `ScreenShotRequest`. The reply (PNG on iOS 9+, TIFF on older releases) is shown inline as `<img>` and can be saved as `screenshot-<UTC>.<ext>`. Requires a mounted Developer Disk Image. | `lockdownScreenshot` |
| **Step 3 → Stream syslog** | After TLS, opens `com.apple.syslog_relay` on a secondary mux TCP. Decoded text is rendered live in a pane (with optional substring filter, highlight, mirror-to-log, and auto-scroll). **Stop** ends the stream cooperatively; **Save…** downloads the captured bytes as `syslog-<UTC>.log`. | `lockdownSyslog` |
| **Step 3 → Capture network** | After TLS, opens `com.apple.pcapd` on a secondary mux TCP, decodes each `device_packet_struct` and grows a libpcap (`LINKTYPE_ETHERNET`) buffer in memory. The live pane is a **dissector view**: each row shows direction, interface, process, src→dst flow, protocol tag (TCP/UDP/DNS/TLS/HTTP/ICMP/…), length and a one-line info field. Click any row to expand the layered breakdown (Ethernet → IPv4/IPv6 → TCP/UDP → DNS / TLS-SNI / HTTP) plus a hex dump. Decoding runs entirely in the browser — `dns-packet` (loaded lazily from `esm.sh`) handles DNS, the rest is inline JS. **Save .pcap** downloads `idevice-<UTC>.pcap` for Wireshark / `tcpdump -r`. Filters mirror the CLI (`process` / `interface`, `max-packets` / `max-bytes` / `max-duration`). | `lockdownPcap` |
| **Step 3 → Crash reports** | After TLS, opens `crashreportmover` + AFC and streams files into a per-file table with **Save** / **Save all** buttons. | `lockdownCrashReports` |

#### TLS knobs (advanced toggle in step 3)

- **Client cert** — `host` (default; pymobiledevice3-style `host` leaf + key), `root` (libimobiledevice-style root cert + key), or `chain` (host + root). Same enum as the CLI's `--lockdown-tls-client-auth`.
- **SNI** — `device` (default; jkcoxson/idevice-style) or `none` (libimobiledevice-style empty SNI). Same enum as `--lockdown-tls-sni`.

If TLS fails on a particular pair record, switching client-auth to `root` and SNI to `none` typically resolves it for libimobiledevice-shaped records — exactly like the CLI.

#### WebUSB bring-up

`idevice-wasm::prepare_apple_usb` mirrors `select_usb_configuration_with_fallback` from the reference `iphone-wasm` / `usbmux` stack:

1. `open()` (best-effort `reset()` when no configuration is active afterwards).
2. `selectConfiguration` — prefer the configuration that contains the Apple mux interface, fall back to the next available one if claim later fails.
3. `claimInterface` → `clearHalt` on both bulk endpoints → `selectAlternateInterface`.
4. Mux `VERSION` (and `SETUP` on v2) on the resulting bulk pipe.

All the steps are logged to the DevTools console with the **`[idevice-wasm]`** prefix; `verbose` in the page also routes additional `console.debug` lines (mux frames, pseudo-TCP segments, TLS handshake phases, `plist-fetch:` lockdown phases).

#### Sharing pair records with the CLI

The XML plist downloaded by **Pair + save record** in the tab is the same shape as `~/.config/idevice-rs/pair-records/<UDID>.plist` written by `cargo run -p idevice-cli -- pair`. You can:

1. Pair once in the tab → drop the file under `~/.config/idevice-rs/pair-records/<UDID>.plist` (or anywhere and pass `--pair-record PATH`) → CLI runs without Trust.
2. Pair once with the CLI → drag the resulting plist into step 2 of the page → tab runs without Trust.
3. Drop the same plist into `/var/lib/lockdown/<UDID>.plist` → `idevicepair` / `pymobiledevice3` accept it too.

| Variable | Meaning |
|----------|---------|
| `SKIP_WASM_BUILD` | Set to **`1`** when running **`serve.sh`** to skip **`./scripts/build-wasm.sh`** (only static files changed). |

---

## License

See the `LICENSE` file in this repository.
