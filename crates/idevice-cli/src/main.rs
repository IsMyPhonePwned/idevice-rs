//! CLI entry: list devices, mux smoke test, pair, battery, diagnostics, and crash report copy.

use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use idevice::connect::{open_lockdown_for_cli, LockdownConnectArgs};
use idevice::crypto::{generate_host_keys, HostKeys};
use idevice::lockdown::{LockdownClient, LockdownTlsClientAuth, LockdownTlsSni};
use idevice::pair_record::{load_pair_record, resolve_pair_record_path};
use idevice::usb::{
    format_apple_device_identity, list_apple_devices, open_apple, prepare_mux_interface,
};
use idevice_usb_core::{lockdown_proto, PairingIds, TcpConn};

#[derive(Parser, Debug)]
#[command(name = "idevice")]
#[command(
    about = "Apple USB mux + lockdownd: pair, battery, diagnostics, crash reports (Rust / idevice-rs)."
)]
struct Cli {
    #[command(flatten)]
    device: DeviceArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PairIdsMode {
    /// Fixed HostID + SystemBUID (WASM-style); can clash if you regenerate keys each run while the phone keeps an older record for the same id.
    Legacy,
    /// Random UUID HostID and SystemBUID per process (libimobiledevice / pymobiledevice3 style); try if TLS resets right after `ClientHello`.
    Random,
}

fn pairing_ids(mode: PairIdsMode) -> PairingIds {
    match mode {
        PairIdsMode::Legacy => PairingIds::legacy_host_and_system(),
        PairIdsMode::Random => PairingIds::new_v4(),
    }
}

fn load_or_generate_keys_and_ids(
    device: &DeviceArgs,
    usb_serial: &str,
) -> Result<(HostKeys, PairingIds, bool), String> {
    let path = resolve_pair_record_path(&device.pair_record, &device.pair_record_dir, usb_serial)?;
    if let Some(p) = path {
        let (keys, ids) = load_pair_record(&p)?;
        println!(
            "[pair-record] Loaded {} — HostID / SystemBUID from plist (`--pair-ids` ignored). \
             If `StartSession` + TLS fails, try `--lockdown-tls-client-auth root`.",
            p.display()
        );
        Ok((keys, ids, true))
    } else {
        let keys = generate_host_keys()?;
        let ids = pairing_ids(device.pair_ids);
        Ok((keys, ids, false))
    }
}

#[derive(clap::Args, Debug)]
struct DeviceArgs {
    /// USB bus number (from `list`)
    #[arg(long, global = true)]
    bus: Option<u8>,
    /// USB device address (from `list`)
    #[arg(long, global = true)]
    addr: Option<u8>,
    /// Match device serial string
    #[arg(long, global = true)]
    serial: Option<String>,
    /// TLS client certificate for lockdownd after StartSession (`host` = pymobiledevice3 / WASM; `root` = libimobiledevice OpenSSL).
    #[arg(long, global = true, value_enum, default_value_t = LockdownTlsClientAuth::Host)]
    lockdown_tls_client_auth: LockdownTlsClientAuth,
    /// TLS SNI for lockdownd ClientHello (`device` = jkcoxson/idevice default; `none` ≈ libimobiledevice no SNI).
    #[arg(long, global = true, value_enum, default_value_t = LockdownTlsSni::Device)]
    lockdown_tls_sni: LockdownTlsSni,
    /// Verbose lockdownd TLS: handshake record hex, mux snapshots, **TLS application** cleartext
    /// (lockdown plist frames), service TLS (AFC / mover), and **`[crypto]`** pairing / key-load logs.
    #[arg(long, global = true)]
    lockdown_tls_debug: bool,
    /// Milliseconds to wait after StartSession before TLS ClientHello. libimobiledevice uses **0**;
    /// a **short** pause (tens of ms) can help some hosts. **Avoid multi‑second values** — lockdownd
    /// often closes the mux TCP session first, which surfaces as `sessionUpcall` / TLS
    /// `wrong version number`.
    #[arg(long, global = true, default_value_t = idevice_usb_core::LOCKDOWN_TLS_SETTLE_MS)]
    lockdown_tls_settle_ms: u64,
    /// Seconds to keep retrying `Pair` while lockdownd returns `PairingDialogResponsePending` or
    /// `PasswordProtected` (unlock + Trust / passcode), instead of exiting immediately.
    #[arg(long, global = true, default_value_t = 120)]
    pair_trust_timeout_secs: u64,
    /// Seconds between **`Pair`** retries while waiting for Trust / passcode (allow time to enter the device passcode).
    #[arg(long, global = true, default_value_t = 4)]
    pair_trust_poll_secs: u64,
    /// After a successful `Pair`, open a **new** mux pseudo-TCP to lockdownd before `StartSession` + TLS.
    /// Default is **off** (same connection as `Pair`, like **libimobiledevice**); reopen was a workaround that can prevent `StartSession` + TLS from lining up on some builds.
    #[arg(long, global = true)]
    reopen_lockdown_after_pair: bool,
    /// Send **`ValidatePair`** after a successful **`Pair`** (same mux TCP). **libimobiledevice** / **pymobiledevice3** only use this on **older iOS**; on current releases it can make lockdownd **RST** the session—leave this **off** unless you know you need it.
    #[arg(long, global = true)]
    validate_pair_after_pair: bool,
    /// How **`HostID`** / **`SystemBUID`** are chosen for `Pair` / `StartSession`. **Default `random`** matches
    /// pymobiledevice3 when generating new RSA keys each run; **`legacy`** is the fixed WASM-style id (can yield
    /// **`InvalidPairRecord`** if the phone still has an older pair blob for that id). **Ignored** when a pair plist is loaded.
    #[arg(long, global = true, value_enum, default_value_t = PairIdsMode::Random)]
    pair_ids: PairIdsMode,
    /// Load **`HostID`**, **`SystemBUID`**, and PEM keys/certs from a **libimobiledevice**-style plist (same keys as
    /// **`idevicepair`** / **`/var/lib/lockdown/<UDID>.plist`**). **`run`/`battery`/`diagnostics`/`crash-reports`**: skip **`Pair`** if load succeeds.
    #[arg(long, global = true)]
    pair_record: Option<PathBuf>,
    /// With **`--pair-record-dir DIR`** and no **`--pair-record`**, load **`DIR/<USB_serial>.plist`** (typical:
    /// **`--pair-record-dir /var/lib/lockdown`** on Linux systems using **usbmuxd**).
    #[arg(long, global = true)]
    pair_record_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List Apple USB devices (05ac)
    List,
    /// Open device and print USB string descriptors (like “Connect Device”)
    Connect,
    /// USB mux VERSION + SETUP + TCP SYN to lockdownd (port 62078)
    Mux,
    /// Pair with lockdownd (RSA host keys generated each run)
    Pair,
    /// Identify the phone on USB, pair, then print `com.apple.mobile.battery` (TLS). Recommended example.
    Battery,
    /// Same as `battery` (pair, optional reopen/validate flags, then StartSession + TLS).
    Run,
    /// Pair (or pair-record), then **`StartSession` → TLS** and many **`GetValue`** queries (lockdown snapshot; not full sysdiagnose).
    Diagnostics,
    /// Pair, **`StartSession` → TLS**, then **`com.apple.crashreportmover`** + **`com.apple.crashreportcopymobile`** (AFC), like **`idevicecrashreport`**.
    CrashReports {
        /// Output directory on the host (ignored with **`--remove-all`**; that mode uses `.` on host).
        out_dir: PathBuf,
        /// Remove each log from the device after it is copied (previous default). Omit this flag to **keep** crash data on the device (like **`idevicecrashreport -k`**).
        #[arg(long = "no-keep", visible_alias = "move-from-device", default_value_t = false)]
        no_keep: bool,
        /// Only copy paths containing this substring (like **`idevicecrashreport -f`**).
        #[arg(long)]
        filter: Option<String>,
        /// Delete crash logs on the device only (like **`idevicecrashreport --remove-all`**).
        #[arg(long, default_value_t = false)]
        remove_all: bool,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    idevice::set_diagnostic_trace(cli.device.lockdown_tls_debug);
    match cli.command {
        Commands::List => cmd_list(),
        Commands::Connect => cmd_connect(&cli.device),
        Commands::Mux => cmd_mux(&cli.device),
        Commands::Pair => cmd_pair(&cli.device),
        Commands::Battery | Commands::Run => cmd_run(&cli.device),
        Commands::Diagnostics => cmd_diagnostics(&cli.device),
        Commands::CrashReports {
            out_dir,
            no_keep,
            filter,
            remove_all,
        } => cmd_crash_reports(&cli.device, &out_dir, !no_keep, filter.as_deref(), remove_all),
    }
}

fn cmd_list() -> Result<(), String> {
    let devs = list_apple_devices()?;
    if devs.is_empty() {
        println!("No Apple USB devices found.");
        return Ok(());
    }
    println!("{:>4} {:>4}  {:>6}  {}", "bus", "addr", "pid", "serial");
    for (bus, addr, pid, serial) in devs {
        println!("{:4} {:4}  0x{:04X}  {}", bus, addr, pid, serial);
    }
    Ok(())
}

fn connect_args(d: &DeviceArgs) -> LockdownConnectArgs<'_> {
    LockdownConnectArgs {
        bus: d.bus,
        addr: d.addr,
        serial: d.serial.as_deref(),
        pair_record: d.pair_record.as_deref(),
    }
}

fn resolve_device_args(d: &DeviceArgs) -> Result<(Option<u8>, Option<u8>, Option<&str>), String> {
    let serial = d.serial.as_deref();
    if d.bus.is_some() ^ d.addr.is_some() {
        return Err(
            "Specify both --bus and --addr, or neither (first Apple device), or --serial.".into(),
        );
    }
    Ok((d.bus, d.addr, serial))
}

fn cmd_connect(device: &DeviceArgs) -> Result<(), String> {
    let (bus, addr, serial) = resolve_device_args(device)?;
    let mut usb = open_apple(bus, addr, serial)?;
    println!("{}", format_apple_device_identity(&mut usb)?);
    Ok(())
}

fn cmd_mux(device: &DeviceArgs) -> Result<(), String> {
    let (bus, addr, serial) = resolve_device_args(device)?;
    let mut usb = open_apple(bus, addr, serial)?;
    prepare_mux_interface(&mut usb)?;
    let eps = usb.eps.clone();
    let mut mux_tx_next = 1u16;
    let conn = TcpConn::handshake_and_connect(
        &mut usb,
        &eps,
        idevice_usb_core::lockdown_proto::LOCKDOWND_PORT,
        &mut mux_tx_next,
    )?;
    println!(
        "[mux] pseudo-TCP to lockdownd OK (mux v{}, sport {})",
        conn.mux_version, conn.sport
    );
    let _ = usb.handle.release_interface(usb.target_iface);
    Ok(())
}

/// Call `Pair`; if the phone needs unlock / Trust / passcode, poll like libimobiledevice until success or timeout.
fn pair_with_trust_wait(
    client: &mut LockdownClient,
    keys: &idevice::crypto::HostKeys,
    ids: &PairingIds,
    timeout_secs: u64,
    poll_secs: u64,
) -> Result<String, String> {
    let poll = Duration::from_secs(poll_secs.max(1));
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    // One plist for the whole trust flow — rebuilding `Pair` after `PairingDialogResponsePending` can
    // change the device certificate bytes and produce `InvalidPairRecord` on the next attempt.
    let pair_xml = client.build_pair_request_xml(keys, ids)?;
    println!(
        "[pair] HostID={}  SystemBUID={}  (new RSA keys each run → use `--pair-ids random` unless you reuse the same HostID)",
        ids.host_id, ids.system_buid
    );
    let mut pair_out = client.pair_exchange(&pair_xml)?;
    println!("{}", pair_out);
    let mut printed_wait_hint = false;
    loop {
        let needs_wait = pair_out.contains("PairingDialogResponsePending")
            || pair_out.contains("PasswordProtected");
        if !needs_wait {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Timed out after {} s waiting for unlock and Trust (or passcode). \
                 Complete the prompt on the iPhone; increase `--pair-trust-timeout-secs` if you need more time.",
                timeout_secs
            ));
        }
        if !printed_wait_hint {
            println!(
                "[pair] Waiting for unlock / Trust / passcode (polling with `--pair-trust-poll-secs`; longer pause after `PairingDialogResponsePending`; timeout {} s)…",
                timeout_secs
            );
            printed_wait_hint = true;
        }
        // A second `Pair` while the Trust sheet is still up can flip some builds to `InvalidPairRecord`;
        // give the user time after `PairingDialogResponsePending` before re-validating.
        let wait = if pair_out.contains("PasswordProtected") {
            poll
        } else if pair_out.contains("PairingDialogResponsePending") {
            poll.max(Duration::from_secs(15))
        } else {
            poll
        };
        thread::sleep(wait);
        // After `PairingDialogResponsePending`, a second `Pair` on the **same** mux pseudo-TCP often
        // returns `InvalidPairRecord` on current iOS; pymobiledevice3 keeps one TCP session, but USB mux
        // stacks differ — reopen lockdownd before each retry with the **same** `Pair` plist.
        println!("[pair] Re-opening mux TCP to lockdownd, then retrying `Pair`…");
        client.reopen_lockdown_tcp()?;
        pair_out = client.pair_exchange(&pair_xml)?;
        if pair_out.contains("<key>Error</key>") {
            println!(
                "[pair] {}",
                pair_out
                    .replace('\n', " ")
                    .chars()
                    .take(260)
                    .collect::<String>()
            );
        }
        if !pair_out.contains("PairingDialogResponsePending")
            && !pair_out.contains("PasswordProtected")
        {
            println!("{}", pair_out);
        }
    }
    Ok(pair_out)
}

fn cmd_pair(device: &DeviceArgs) -> Result<(), String> {
    let _ = resolve_device_args(device)?;
    let (usb_serial, mut client) = open_lockdown_for_cli(connect_args(device))?;
    let (keys, ids, loaded) = load_or_generate_keys_and_ids(device, &usb_serial)?;
    if loaded {
        println!("[pair-record] Performing `Pair` using keys from the plist.");
    }
    pair_with_trust_wait(
        &mut client,
        &keys,
        &ids,
        device.pair_trust_timeout_secs,
        device.pair_trust_poll_secs,
    )?;
    Ok(())
}

fn establish_lockdown_tls_session(
    client: &mut LockdownClient,
    keys: &idevice::crypto::HostKeys,
    ids: &PairingIds,
    device: &DeviceArgs,
    log_tag: &str,
) -> Result<(), String> {
    println!("{} StartSession…", log_tag);
    let res = client.start_session(ids)?;
    println!("{} Session plist:\n{}", log_tag, res);
    if res.contains("<key>Error</key>") {
        return Err(
            "StartSession was rejected by lockdownd (often InvalidHostID if pairing did not complete). \
             Fix the Pair step first (unlock iPhone, passcode / Trust, then retry)."
                .into(),
        );
    }
    let ssl = lockdown_proto::start_session_enable_ssl(&res);
    if ssl {
        println!("{} Upgrading to TLS…", log_tag);
        client.enable_ssl(
            keys,
            device.lockdown_tls_client_auth,
            device.lockdown_tls_sni,
            device.lockdown_tls_settle_ms,
            device.lockdown_tls_debug,
        )?;
    } else {
        println!(
            "{} StartSession did not enable SSL (no `EnableSessionSSL` true); continuing cleartext (may fail on modern iOS).",
            log_tag
        );
    }
    Ok(())
}

fn cmd_battery_inner(
    client: &mut LockdownClient,
    keys: &idevice::crypto::HostKeys,
    ids: &PairingIds,
    device: &DeviceArgs,
) -> Result<(), String> {
    establish_lockdown_tls_session(client, keys, ids, device, "[battery]")?;
    let battery = client.get_value("com.apple.mobile.battery", "")?;
    println!("{}", battery);
    Ok(())
}

fn cmd_diagnostics_inner(
    client: &mut LockdownClient,
    keys: &idevice::crypto::HostKeys,
    ids: &PairingIds,
    device: &DeviceArgs,
) -> Result<(), String> {
    establish_lockdown_tls_session(client, keys, ids, device, "[diagnostics]")?;
    println!(
        "\n--- Lockdown GetValue snapshot ({} queries; not Apple sysdiagnose) ---",
        lockdown_proto::LOCKDOWN_DIAGNOSTIC_GET_VALUES.len()
    );
    for (label, domain, key) in lockdown_proto::LOCKDOWN_DIAGNOSTIC_GET_VALUES {
        match client.get_value(domain, key) {
            Ok(xml) => println!("\n## {}\n{}", label, xml),
            Err(e) => println!("\n## {} → ERROR: {}", label, e),
        }
    }
    Ok(())
}

/// Shared path: optional **`Pair`**, **`ValidatePair`**, **`reopen_lockdown_tcp`**.
/// Returns **`Ok(false)`** when **`Pair`** failed (caller should skip TLS / telemetry).
fn lockdown_pair_validate_reopen(
    client: &mut LockdownClient,
    keys: &HostKeys,
    ids: &PairingIds,
    device: &DeviceArgs,
    from_saved_record: bool,
    next_step: &str,
) -> Result<bool, String> {
    if from_saved_record {
        println!("\n=== Skip `Pair` (saved pair record) → {} ===", next_step);
    } else {
        println!(
            "\n=== Pair + {} (USB mux; same lockdownd TCP as `Pair` unless you pass reopen flags) ===",
            next_step
        );
        let pair_out = pair_with_trust_wait(
            client,
            keys,
            ids,
            device.pair_trust_timeout_secs,
            device.pair_trust_poll_secs,
        )?;
        if pair_out.contains("<key>Error</key>") {
            println!(
                "\n⚠ Pair did not succeed (see Error in the plist above). Encrypted lockdownd requires a successful pair."
            );
            if pair_out.contains("InvalidPairRecord") {
                println!(
                    "Hint: after `PairingDialogResponsePending`, `InvalidPairRecord` often means Trust was not completed (Don’t Trust), a stale prompt, **`--pair-ids legacy`** with new keys vs an old phone pairing, or a supervised/challenge flow — unlock, tap Trust, try `--pair-ids random` if you use **`legacy`**, or Settings → General → Transfer or Reset → Reset Location & Privacy, then run again. \
                     You can also pair with **idevicepair** / **pymobiledevice3** and use **`--pair-record`** / **`--pair-record-dir /var/lib/lockdown`** here."
                );
            }
            return Ok(false);
        }
    }
    if device.validate_pair_after_pair {
        println!("\n=== ValidatePair (opt-in; `--validate-pair-after-pair`) ===");
        let validate_out = client.validate_pair(keys, ids)?;
        println!("{}", validate_out);
        if validate_out.contains("<key>Error</key>") {
            return Err(
                "ValidatePair failed. Unlock the device, ensure Trust / pairing is complete, then try again."
                    .into(),
            );
        }
    }
    if device.reopen_lockdown_after_pair {
        println!(
            "\n=== New lockdownd TCP (`--reopen-lockdown-after-pair`; optional workaround) ==="
        );
        client.reopen_lockdown_tcp()?;
    }
    Ok(true)
}

fn cmd_run(device: &DeviceArgs) -> Result<(), String> {
    let (bus, addr, serial) = resolve_device_args(device)?;
    let (usb_serial, mut client) = open_lockdown_for_cli(connect_args(device))?;
    if let Ok(mut usb) = open_apple(bus, addr, serial) {
        println!(
            "=== Phone (identified on USB) ===\n{}",
            format_apple_device_identity(&mut usb)?
        );
    } else {
        println!(
            "=== Phone (via usbmuxd) ===\nIdentifier (pair-record name): {}",
            usb_serial
        );
    }
    let (keys, ids, from_saved_record) = load_or_generate_keys_and_ids(device, &usb_serial)?;
    if !lockdown_pair_validate_reopen(
        &mut client,
        &keys,
        &ids,
        device,
        from_saved_record,
        "battery",
    )? {
        return Ok(());
    }
    println!("\n=== Battery (StartSession → TLS → GetValue) ===");
    cmd_battery_inner(&mut client, &keys, &ids, device)?;
    Ok(())
}

fn cmd_diagnostics(device: &DeviceArgs) -> Result<(), String> {
    let (bus, addr, serial) = resolve_device_args(device)?;
    let (usb_serial, mut client) = open_lockdown_for_cli(connect_args(device))?;
    if let Ok(mut usb) = open_apple(bus, addr, serial) {
        println!(
            "=== Phone (identified on USB) ===\n{}",
            format_apple_device_identity(&mut usb)?
        );
    } else {
        println!(
            "=== Phone (via usbmuxd) ===\nIdentifier (pair-record name): {}",
            usb_serial
        );
    }
    let (keys, ids, from_saved_record) = load_or_generate_keys_and_ids(device, &usb_serial)?;
    if !lockdown_pair_validate_reopen(
        &mut client,
        &keys,
        &ids,
        device,
        from_saved_record,
        "diagnostics",
    )? {
        return Ok(());
    }
    println!("\n=== Diagnostics (StartSession → TLS → many GetValue) ===");
    cmd_diagnostics_inner(&mut client, &keys, &ids, device)?;
    Ok(())
}

fn cmd_crash_reports(
    device: &DeviceArgs,
    out_dir: &Path,
    keep: bool,
    filter: Option<&str>,
    remove_all: bool,
) -> Result<(), String> {
    let (bus, addr, serial) = resolve_device_args(device)?;
    let (usb_serial, mut client) = open_lockdown_for_cli(connect_args(device))?;
    if let Ok(mut usb) = open_apple(bus, addr, serial) {
        println!(
            "=== Phone (identified on USB) ===\n{}",
            format_apple_device_identity(&mut usb)?
        );
    } else {
        println!(
            "=== Phone (via usbmuxd) ===\nIdentifier (pair-record name): {}",
            usb_serial
        );
    }
    let (keys, ids, from_saved_record) = load_or_generate_keys_and_ids(device, &usb_serial)?;
    if !lockdown_pair_validate_reopen(
        &mut client,
        &keys,
        &ids,
        device,
        from_saved_record,
        "crash-reports",
    )? {
        return Ok(());
    }
    println!(
        "\n=== Crash reports (StartSession → TLS → crashreportmover + crashreportcopymobile) ==="
    );
    establish_lockdown_tls_session(&mut client, &keys, &ids, device, "[crash-reports]")?;
    idevice::crash_reports::copy_crash_reports_mobile(
        &mut client,
        out_dir,
        keep,
        filter,
        remove_all,
        &keys,
        device.lockdown_tls_client_auth,
        device.lockdown_tls_sni,
        device.lockdown_tls_debug,
        device.lockdown_tls_settle_ms,
    )
}
