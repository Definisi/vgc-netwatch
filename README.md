# vgc-netwatch

A small Windows tool that watches network activity from Riot Vanguard (`vgc.exe`) in real time. It tracks every TCP and UDP connection the process opens, records how long each one lasted, and writes structured logs you can grep or query later.

## Why this exists

Vanguard is a kernel-mode anti-cheat. Most users have no clear view of what it talks to over the network. vgc-netwatch gives you that view. It runs in user space, polls the Windows network tables, and matches connections by process ID. You get:

- A live console feed with colors for OPEN, CLOSE, and FAILED events
- Service name hints for common ports (HTTPS, STUN, Riot launcher, and others)
- Reverse DNS lookups for remote IPs, cached per session
- TCP byte counters per connection via Windows eStats
- Two log files: a plain text monitor log and a JSON detail log

This is a passive observer. It does not block, modify, or inject into `vgc.exe`. It only reads what the kernel already exposes.

## Install

You need **Rust 1.70+** and the **Windows MSVC toolchain** installed.

```bash
git clone https://github.com/Definisi/vgc-netwatch.git
cd vgc-netwatch
cargo build --release
```

The binary lands at `target/release/vgc_netwatch.exe`.

## Run

Start it from any terminal that supports ANSI colors (Windows Terminal, PowerShell 7, or any modern shell):

```bash
target\release\vgc_netwatch.exe
```

The tool waits until `vgc.exe` is running, then starts logging. When the process exits, it closes any open connection records and goes back to waiting. Press `Ctrl+C` to stop.

> [!NOTE]
> You do not need administrator rights for read-only network table access. Running as admin gives no extra information here.

## Output

Three streams get written at the same time:

| Target | Format | Purpose |
|---|---|---|
| Console | Pretty, colored | Live view while the tool runs |
| `vgc_monitor.log` | Plain text | Human-readable history with no ANSI codes |
| `vgc_detailed.log` | JSON, one event per line | Machine-readable record for analysis |

### Sample console output

```
14:32:01.123  INFO vgc-netwatch started
14:32:03.456  INFO vgc.exe started  pid=12480  session=1
14:32:03.789  INFO OPEN    [TCP] 192.168.1.5:53412 -> 104.18.32.1:443 (HTTPS) [SYN_SENT]
14:32:04.012  INFO CLOSE   [TCP] 192.168.1.5:53412 -> 104.18.32.1:443 (HTTPS) [TIME_WAIT]  (1820ms)
```

### Sample JSON record

Each line in `vgc_detailed.log` is a self-contained JSON object:

```json
{
  "timestamp": "2026-05-06T14:32:04.012",
  "level": "INFO",
  "event": "CLOSE",
  "proto": "TCP",
  "local": "192.168.1.5:53412",
  "remote": "104.18.32.1:443",
  "host": "riotgames.com",
  "service": "HTTPS",
  "duration_ms": 1820,
  "bytes_sent": 4321,
  "bytes_recv": 18204,
  "message": "CLOSE   [TCP] 192.168.1.5:53412 -> 104.18.32.1:443  (1820ms)"
}
```

You can query it with `jq`:

```bash
jq 'select(.event=="CLOSE" and .duration_ms > 5000)' vgc_detailed.log
```

## Configure

vgc-netwatch reads one environment variable.

### `RUST_LOG`

Sets the log level. The default is `info`. Set it to `debug` if you want to see TCP state changes too:

```powershell
$env:RUST_LOG = "debug"; .\target\release\vgc_netwatch.exe
```

```bash
RUST_LOG=debug target/release/vgc_netwatch.exe
```

### Polling rate

The poll interval is fixed at 100 ms inside the source. If you need a different rate, edit the `sleep` call at the bottom of `main.rs` and rebuild. A faster rate catches shorter connections but uses more CPU. A slower rate is the opposite.

### Target process

The tool watches `vgc.exe` by default. To watch a different process, change the string passed to `find_pids_by_name` in `main.rs` and rebuild.

## How it works

The main loop runs every 100 ms and does five things:

1. **Find PIDs.** It walks the process list with `CreateToolhelp32Snapshot` and matches on the executable name.
2. **List connections.** For each PID, it calls `GetExtendedTcpTable` and `GetExtendedUdpTable` for both IPv4 and IPv6.
3. **Diff against last tick.** New keys become OPEN events. Missing keys become CLOSE or FAILED events.
4. **Resolve and label.** Remote IPs get a cached reverse DNS lookup. Common ports get a service name.
5. **Query byte counts.** For closed TCP connections, it pulls eStats data with `GetPerTcpConnectionEStats`.

A connection that disappears in the `SYN_SENT` state counts as FAILED. Anything else counts as a normal CLOSE.

## Project layout

```
vgc-netwatch/
├── Cargo.toml          dependencies and build profile
├── src/
│   └── main.rs         all logic in one file
├── vgc_monitor.log     plain log, created at runtime
├── vgc_detailed.log    JSON log, created at runtime
└── README.md
```

The Rust port is a single file because the program is small and the Windows API code does not break apart cleanly.

## Limits

- **Windows only.** It uses Win32 APIs that have no cross-platform equivalent.
- **Polling, not streaming.** Connections that open and close inside one 100 ms tick get missed.
- **No packet capture.** It sees connection metadata, not packet contents. For payload inspection, use Wireshark.
- **Reverse DNS is best effort.** Some IPs return no PTR record. Those show as empty `host` fields.

## Contributing

Pull requests are welcome. Please:

1. Run `cargo fmt` before you commit.
2. Run `cargo clippy --release` and fix any new warnings.
3. Test on a real Windows host, not just under WSL or a VM without network adapters.

If you want to add a new output sink (for example, an HTTP push or a SQLite store), put it behind a feature flag in `Cargo.toml` so the default build stays small.

## License

MIT. See `LICENSE` if present, otherwise treat the code as MIT-licensed.
