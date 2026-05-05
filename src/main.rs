#![cfg(windows)]
#![allow(non_snake_case)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::thread::sleep;
use std::time::{Duration, Instant};

use time::macros::format_description;
use tracing::{info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::time::LocalTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::*;
use windows::Win32::System::Console::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::SystemInformation::GetLocalTime;

fn port_service(p: u16) -> &'static str {
    match p {
        80 => "HTTP",
        443 => "HTTPS",
        8443 => "HTTPS-alt",
        8080 => "HTTP-proxy",
        3478 => "STUN/TURN",
        3479 => "STUN/TURN-alt",
        5222 => "XMPP",
        5223 => "XMPP-TLS",
        2099 => "Riot-login",
        8393 => "Riot-launcher",
        9339 => "Riot-patch",
        123 => "NTP",
        53 => "DNS",
        _ if p >= 49152 => "ephemeral",
        _ => "",
    }
}

fn tcp_state_name(s: u32) -> &'static str {
    match MIB_TCP_STATE(s as i32) {
        MIB_TCP_STATE_CLOSED => "CLOSED",
        MIB_TCP_STATE_LISTEN => "LISTEN",
        MIB_TCP_STATE_SYN_SENT => "SYN_SENT",
        MIB_TCP_STATE_SYN_RCVD => "SYN_RCVD",
        MIB_TCP_STATE_ESTAB => "ESTABLISHED",
        MIB_TCP_STATE_FIN_WAIT1 => "FIN_WAIT1",
        MIB_TCP_STATE_FIN_WAIT2 => "FIN_WAIT2",
        MIB_TCP_STATE_CLOSE_WAIT => "CLOSE_WAIT",
        MIB_TCP_STATE_CLOSING => "CLOSING",
        MIB_TCP_STATE_LAST_ACK => "LAST_ACK",
        MIB_TCP_STATE_TIME_WAIT => "TIME_WAIT",
        _ => "?",
    }
}

fn ipv4_to_string(ip_be: u32) -> String {
    let b = ip_be.to_le_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn ipv6_to_string(addr: &[u8; 16]) -> String {
    let mut sa = unsafe { zeroed::<SOCKADDR_IN6>() };
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.u.Byte = *addr;
    let mut host = [0u8; 64];
    let mut serv = [0u8; 8];
    unsafe {
        let _ = getnameinfo(
            &sa as *const _ as *const SOCKADDR,
            socklen_t(size_of::<SOCKADDR_IN6>() as i32),
            Some(&mut host),
            Some(&mut serv),
            (NI_NUMERICHOST | NI_NUMERICSERV) as i32,
        );
    }
    let len = host.iter().position(|&c| c == 0).unwrap_or(host.len());
    String::from_utf8_lossy(&host[..len]).into_owned()
}

fn resolve_dns(cache: &mut HashMap<String, String>, ip: &str) -> String {
    if ip == "*" || ip == "0.0.0.0" {
        return String::new();
    }
    if let Some(v) = cache.get(ip) {
        return v.clone();
    }
    let wide: Vec<u16> = ip.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sa = unsafe { zeroed::<SOCKADDR_IN>() };
    sa.sin_family = AF_INET;
    let r = unsafe {
        InetPtonW(
            AF_INET.0 as i32,
            windows::core::PCWSTR(wide.as_ptr()),
            &mut sa.sin_addr as *mut _ as *mut _,
        )
    };
    if r != 1 {
        cache.insert(ip.to_string(), String::new());
        return String::new();
    }
    let mut host = [0u8; 1025];
    let res = unsafe {
        getnameinfo(
            &sa as *const _ as *const SOCKADDR,
            socklen_t(size_of::<SOCKADDR_IN>() as i32),
            Some(&mut host),
            None,
            NI_NAMEREQD as i32,
        )
    };
    let name = if res == 0 {
        let len = host.iter().position(|&c| c == 0).unwrap_or(host.len());
        String::from_utf8_lossy(&host[..len]).into_owned()
    } else {
        String::new()
    };
    cache.insert(ip.to_string(), name.clone());
    name
}

fn find_pids_by_name(name: &str) -> HashSet<u32> {
    let mut pids = HashSet::new();
    let target = name.to_lowercase();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return pids,
        };
        let mut pe = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..zeroed()
        };
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let len = pe
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(pe.szExeFile.len());
                let cur = String::from_utf16_lossy(&pe.szExeFile[..len]).to_lowercase();
                if cur == target {
                    pids.insert(pe.th32ProcessID);
                }
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    pids
}

#[derive(Default, Clone, Copy)]
struct TcpDataTotals {
    tx: u64,
    rx: u64,
}

fn query_tcp_data_totals(
    local_ip: u32,
    local_port: u16,
    remote_ip: u32,
    remote_port: u16,
) -> TcpDataTotals {
    let row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE_ESTAB },
        dwLocalAddr: local_ip,
        dwLocalPort: (local_port.to_be() as u32) & 0xFFFF,
        dwRemoteAddr: remote_ip,
        dwRemotePort: (remote_port.to_be() as u32) & 0xFFFF,
    };
    let mut rw = unsafe { zeroed::<TCP_ESTATS_DATA_RW_v0>() };
    rw.EnableCollection = BOOLEAN(1);
    let rw_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            &rw as *const _ as *const u8,
            size_of::<TCP_ESTATS_DATA_RW_v0>(),
        )
    };
    unsafe {
        SetPerTcpConnectionEStats(&row, TcpConnectionEstatsData, rw_bytes, 0, 0);
    }
    let mut rod = unsafe { zeroed::<TCP_ESTATS_DATA_ROD_v0>() };
    let rod_bytes: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(
            &mut rod as *mut _ as *mut u8,
            size_of::<TCP_ESTATS_DATA_ROD_v0>(),
        )
    };
    let res = unsafe {
        GetPerTcpConnectionEStats(
            &row,
            TcpConnectionEstatsData,
            None,
            0,
            None,
            0,
            Some(rod_bytes),
            0,
        )
    };
    if res == NO_ERROR.0 {
        TcpDataTotals { tx: rod.DataBytesOut, rx: rod.DataBytesIn }
    } else {
        TcpDataTotals::default()
    }
}

#[derive(Clone)]
struct ConnectionInfo {
    proto: String,
    lip: String,
    lport: u16,
    rip: String,
    rport: u16,
    state: u32,
    lip_raw: u32,
    rip_raw: u32,
}

impl ConnectionInfo {
    fn key(&self) -> String {
        format!(
            "{}|{}:{}|{}:{}",
            self.proto, self.lip, self.lport, self.rip, self.rport
        )
    }
}

struct ConnectionRecord {
    conn: ConnectionInfo,
    t0: Instant,
    t0_wall: String,
}

fn enumerate_connections(pids: &HashSet<u32>) -> Vec<ConnectionInfo> {
    let mut out = Vec::new();

    unsafe {
        let mut sz: u32 = 0;
        GetExtendedTcpTable(None, &mut sz, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if sz > 0 {
            let mut buf = vec![0u8; sz as usize];
            if GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut sz,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == NO_ERROR.0
            {
                let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let n = (*table).dwNumEntries;
                let rows = (*table).table.as_ptr();
                for i in 0..n {
                    let r = &*rows.add(i as usize);
                    if !pids.contains(&r.dwOwningPid) {
                        continue;
                    }
                    out.push(ConnectionInfo {
                        proto: "TCP".into(),
                        state: r.dwState,
                        lip_raw: r.dwLocalAddr,
                        rip_raw: r.dwRemoteAddr,
                        lip: ipv4_to_string(r.dwLocalAddr),
                        lport: u16::from_be((r.dwLocalPort & 0xFFFF) as u16),
                        rip: ipv4_to_string(r.dwRemoteAddr),
                        rport: u16::from_be((r.dwRemotePort & 0xFFFF) as u16),
                    });
                }
            }
        }

        let mut sz: u32 = 0;
        GetExtendedUdpTable(None, &mut sz, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0);
        if sz > 0 {
            let mut buf = vec![0u8; sz as usize];
            if GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut sz,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            ) == NO_ERROR.0
            {
                let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                let n = (*table).dwNumEntries;
                let rows = (*table).table.as_ptr();
                for i in 0..n {
                    let r = &*rows.add(i as usize);
                    if !pids.contains(&r.dwOwningPid) {
                        continue;
                    }
                    out.push(ConnectionInfo {
                        proto: "UDP".into(),
                        state: 0,
                        lip_raw: r.dwLocalAddr,
                        rip_raw: 0,
                        lip: ipv4_to_string(r.dwLocalAddr),
                        lport: u16::from_be((r.dwLocalPort & 0xFFFF) as u16),
                        rip: "*".into(),
                        rport: 0,
                    });
                }
            }
        }

        let mut sz: u32 = 0;
        GetExtendedTcpTable(None, &mut sz, false, AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if sz > 0 {
            let mut buf = vec![0u8; sz as usize];
            if GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut sz,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == NO_ERROR.0
            {
                let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
                let n = (*table).dwNumEntries;
                let rows = (*table).table.as_ptr();
                for i in 0..n {
                    let r = &*rows.add(i as usize);
                    if !pids.contains(&r.dwOwningPid) {
                        continue;
                    }
                    out.push(ConnectionInfo {
                        proto: "TCP6".into(),
                        state: r.dwState,
                        lip_raw: 0,
                        rip_raw: 0,
                        lip: ipv6_to_string(&r.ucLocalAddr),
                        lport: u16::from_be((r.dwLocalPort & 0xFFFF) as u16),
                        rip: ipv6_to_string(&r.ucRemoteAddr),
                        rport: u16::from_be((r.dwRemotePort & 0xFFFF) as u16),
                    });
                }
            }
        }

        let mut sz: u32 = 0;
        GetExtendedUdpTable(None, &mut sz, false, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0);
        if sz > 0 {
            let mut buf = vec![0u8; sz as usize];
            if GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut sz,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            ) == NO_ERROR.0
            {
                let table = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
                let n = (*table).dwNumEntries;
                let rows = (*table).table.as_ptr();
                for i in 0..n {
                    let r = &*rows.add(i as usize);
                    if !pids.contains(&r.dwOwningPid) {
                        continue;
                    }
                    out.push(ConnectionInfo {
                        proto: "UDP6".into(),
                        state: 0,
                        lip_raw: 0,
                        rip_raw: 0,
                        lip: ipv6_to_string(&r.ucLocalAddr),
                        lport: u16::from_be((r.dwLocalPort & 0xFFFF) as u16),
                        rip: "*".into(),
                        rport: 0,
                    });
                }
            }
        }
    }

    out
}

fn timestamp_iso() -> String {
    let s = unsafe { GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute, s.wSecond, s.wMilliseconds
    )
}

fn enable_vt_mode() {
    unsafe {
        if let Ok(h) = GetStdHandle(STD_OUTPUT_HANDLE) {
            let mut m = CONSOLE_MODE(0);
            if GetConsoleMode(h, &mut m).is_ok() {
                let _ = SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

fn wsa_startup() {
    let mut wsa = unsafe { zeroed::<WSADATA>() };
    unsafe { WSAStartup(0x0202, &mut wsa) };
}

fn init_logging() -> (WorkerGuard, WorkerGuard) {
    let monitor_appender = tracing_appender::rolling::never(".", "vgc_monitor.log");
    let (monitor_writer, monitor_guard) = tracing_appender::non_blocking(monitor_appender);

    let detail_appender = tracing_appender::rolling::never(".", "vgc_detailed.log");
    let (detail_writer, detail_guard) = tracing_appender::non_blocking(detail_appender);

    let timer = LocalTime::new(format_description!(
        "[hour]:[minute]:[second].[subsecond digits:3]"
    ));

    let console_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .with_target(false)
        .with_timer(timer.clone())
        .compact()
        .with_filter(EnvFilter::new("info"));

    let monitor_layer = fmt::layer()
        .with_writer(monitor_writer)
        .with_ansi(false)
        .with_target(false)
        .with_timer(timer)
        .compact()
        .with_filter(EnvFilter::new("info"));

    let detail_layer = fmt::layer()
        .with_writer(detail_writer)
        .with_ansi(false)
        .with_target(false)
        .json()
        .flatten_event(true)
        .with_filter(EnvFilter::new("debug"));

    tracing_subscriber::registry()
        .with(console_layer)
        .with(monitor_layer)
        .with(detail_layer)
        .init();

    (monitor_guard, detail_guard)
}

fn fmt_endpoint(c: &ConnectionInfo) -> String {
    let mut s = format!(
        "[{}] {}:{} -> {}:{}",
        c.proto, c.lip, c.lport, c.rip, c.rport
    );
    let pd = port_service(c.rport);
    if !pd.is_empty() {
        s.push_str(&format!(" ({})", pd));
    }
    if c.proto == "TCP" || c.proto == "TCP6" {
        s.push_str(&format!(" [{}]", tcp_state_name(c.state)));
    }
    s
}

fn log_connection_close(
    dns_cache: &mut HashMap<String, String>,
    rec: &ConnectionRecord,
) {
    let dur = rec.t0.elapsed().as_millis() as u64;
    let host = resolve_dns(dns_cache, &rec.conn.rip);
    let svc = port_service(rec.conn.rport);
    let failed = MIB_TCP_STATE(rec.conn.state as i32) == MIB_TCP_STATE_SYN_SENT;

    let mut es = TcpDataTotals::default();
    let mut has_es = false;
    if rec.conn.proto == "TCP" && rec.conn.rip != "127.0.0.1" && rec.conn.rip_raw != 0 {
        es = query_tcp_data_totals(
            rec.conn.lip_raw,
            rec.conn.lport,
            rec.conn.rip_raw,
            rec.conn.rport,
        );
        has_es = es.tx > 0 || es.rx > 0;
    }

    let endpoint = fmt_endpoint(&rec.conn);
    let bytes_sent = if has_es { es.tx } else { 0 };
    let bytes_recv = if has_es { es.rx } else { 0 };

    if failed {
        warn!(
            event = "FAILED",
            proto = %rec.conn.proto,
            local = %format!("{}:{}", rec.conn.lip, rec.conn.lport),
            remote = %format!("{}:{}", rec.conn.rip, rec.conn.rport),
            host = %host,
            service = %svc,
            duration_ms = dur,
            opened = %rec.t0_wall,
            bytes_sent,
            bytes_recv,
            "FAILED  {}  ({}ms)", endpoint, dur
        );
    } else {
        info!(
            event = "CLOSE",
            proto = %rec.conn.proto,
            local = %format!("{}:{}", rec.conn.lip, rec.conn.lport),
            remote = %format!("{}:{}", rec.conn.rip, rec.conn.rport),
            host = %host,
            service = %svc,
            duration_ms = dur,
            opened = %rec.t0_wall,
            bytes_sent,
            bytes_recv,
            "CLOSE   {}  ({}ms)", endpoint, dur
        );
    }
}

fn main() {
    enable_vt_mode();
    wsa_startup();

    let _guards = init_logging();

    info!(event = "START", time = %timestamp_iso(), "vac_sniffer started");

    let mut dns_cache: HashMap<String, String> = HashMap::new();
    let mut pid_sessions: BTreeMap<u32, i32> = BTreeMap::new();
    let mut active: HashMap<String, ConnectionRecord> = HashMap::new();
    let mut session_counter: i32 = 0;

    loop {
        let pids = find_pids_by_name("vgc.exe");

        for &pid in &pids {
            if !pid_sessions.contains_key(&pid) {
                session_counter += 1;
                pid_sessions.insert(pid, session_counter);
                info!(
                    event = "PROCESS_START",
                    pid,
                    session = session_counter,
                    "vgc.exe started  pid={}  session={}",
                    pid, session_counter
                );
            }
        }

        let exited: Vec<u32> = pid_sessions
            .keys()
            .filter(|p| !pids.contains(p))
            .copied()
            .collect();
        for pid in exited {
            let session = pid_sessions.remove(&pid).unwrap();
            warn!(
                event = "PROCESS_EXIT",
                pid,
                session,
                "vgc.exe exited  pid={}  session={}",
                pid, session
            );
        }

        if pids.is_empty() {
            let recs: Vec<ConnectionRecord> = active.drain().map(|(_, v)| v).collect();
            for r in &recs {
                log_connection_close(&mut dns_cache, r);
            }
            print!("\r\x1b[90mwaiting for vgc.exe...\x1b[0m    ");
            let _ = std::io::stdout().flush();
            sleep(Duration::from_millis(500));
            continue;
        }

        let conns = enumerate_connections(&pids);
        let mut current_keys: HashSet<String> = HashSet::new();

        for c in &conns {
            let k = c.key();
            current_keys.insert(k.clone());
            if !active.contains_key(&k) {
                let opened_ts = timestamp_iso();
                let host = resolve_dns(&mut dns_cache, &c.rip);
                let svc = port_service(c.rport);
                let direction = if c.rip == "*" { "listen" } else { "outbound" };
                let endpoint = fmt_endpoint(c);

                info!(
                    event = "OPEN",
                    proto = %c.proto,
                    local = %format!("{}:{}", c.lip, c.lport),
                    remote = %format!("{}:{}", c.rip, c.rport),
                    host = %host,
                    service = %svc,
                    state = tcp_state_name(c.state),
                    direction,
                    "OPEN    {}", endpoint
                );

                active.insert(
                    k,
                    ConnectionRecord {
                        conn: c.clone(),
                        t0: Instant::now(),
                        t0_wall: opened_ts,
                    },
                );
            } else {
                let rec = active.get_mut(&k).unwrap();
                if rec.conn.state != c.state {
                    let old = tcp_state_name(rec.conn.state);
                    let new = tcp_state_name(c.state);
                    tracing::debug!(
                        event = "STATE",
                        key = %c.key(),
                        old,
                        new,
                        "state change {} -> {}", old, new
                    );
                    rec.conn.state = c.state;
                }
            }
        }

        let stale: Vec<String> = active
            .keys()
            .filter(|k| !current_keys.contains(*k))
            .cloned()
            .collect();
        for k in stale {
            if let Some(rec) = active.remove(&k) {
                log_connection_close(&mut dns_cache, &rec);
            }
        }

        print!(
            "\r\x1b[90mpids={}  active={}\x1b[0m   ",
            pids.len(),
            conns.len()
        );
        let _ = std::io::stdout().flush();

        sleep(Duration::from_millis(100));
    }
}
