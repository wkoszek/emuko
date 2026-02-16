use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

const REGISTRY_JSON: &str = include_str!("../registry.json");

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

fn parse_u64(arg: &str) -> Option<u64> {
    if let Some(hex) = arg.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        arg.parse::<u64>().ok()
    }
}

fn decode_escapes(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(ch) = it.next() {
        if ch != '\\' {
            out.push(ch as u8);
            continue;
        }
        let Some(next) = it.next() else {
            out.push(b'\\');
            break;
        };
        match next {
            'n' => out.push(b'\n'),
            'r' => out.push(b'\r'),
            't' => out.push(b'\t'),
            '\\' => out.push(b'\\'),
            'x' => {
                let Some(h1) = it.next() else {
                    return Err("incomplete \\x escape".to_string());
                };
                let Some(h2) = it.next() else {
                    return Err("incomplete \\x escape".to_string());
                };
                let hi = h1
                    .to_digit(16)
                    .ok_or_else(|| "invalid \\x escape".to_string())?;
                let lo = h2
                    .to_digit(16)
                    .ok_or_else(|| "invalid \\x escape".to_string())?;
                out.push(((hi << 4) | lo) as u8);
            }
            other => out.push(other as u8),
        }
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn http_get(addr: &str, path: &str) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        path, addr
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&bytes);
    let mut sections = text.splitn(2, "\r\n\r\n");
    let head = sections.next().unwrap_or_default();
    let body = sections.next().unwrap_or_default().to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(500);
    Ok((status, body))
}

// ---------------------------------------------------------------------------
// `emuko dow` — download command
// ---------------------------------------------------------------------------

struct RegistryFile {
    url: String,
    save_as: String,
    sha256: String,
    size: u64,
}

struct RegistrySet {
    name: String,
    arch: String,
    files: Vec<RegistryFile>,
}

fn json_str_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{}\"", key);
    let idx = line.find(&pat)?;
    let after = &line[idx + pat.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim();
    if rest.starts_with('"') {
        let inner = &rest[1..];
        let end = inner.find('"')?;
        Some(&inner[..end])
    } else {
        let end = inner_token_end(rest);
        Some(&rest[..end])
    }
}

fn inner_token_end(s: &str) -> usize {
    s.find(|c: char| c == ',' || c == '}' || c == ']' || c.is_whitespace())
        .unwrap_or(s.len())
}

fn parse_registry(json: &str) -> Vec<RegistrySet> {
    let mut sets = Vec::new();
    let lines: Vec<&str> = json.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if line.starts_with('"') && line.contains("}: {") == false && line.ends_with('{') {
            if let Some(end) = line[1..].find('"') {
                let set_name = &line[1..1 + end];
                if set_name == "sets" {
                    i += 1;
                    continue;
                }
                let mut arch = String::new();
                let mut files = Vec::new();
                i += 1;
                let mut in_files = false;
                let mut cur_url = String::new();
                let mut cur_save = String::new();
                let mut cur_sha = String::new();
                let mut cur_size: u64 = 0;
                let mut in_file_obj = false;
                while i < lines.len() {
                    let l = lines[i].trim();
                    if !in_files {
                        if let Some(v) = json_str_value(l, "arch") {
                            arch = v.to_string();
                        }
                        if l.contains("\"files\"") {
                            in_files = true;
                        }
                    } else if in_file_obj {
                        if let Some(v) = json_str_value(l, "url") {
                            cur_url = v.to_string();
                        }
                        if let Some(v) = json_str_value(l, "save_as") {
                            cur_save = v.to_string();
                        }
                        if let Some(v) = json_str_value(l, "sha256") {
                            cur_sha = v.to_string();
                        }
                        if let Some(v) = json_str_value(l, "size") {
                            cur_size = v.parse::<u64>().unwrap_or(0);
                        }
                        if l.starts_with('}') {
                            files.push(RegistryFile {
                                url: cur_url.clone(),
                                save_as: cur_save.clone(),
                                sha256: cur_sha.clone(),
                                size: cur_size,
                            });
                            cur_url.clear();
                            cur_save.clear();
                            cur_sha.clear();
                            cur_size = 0;
                            in_file_obj = false;
                        }
                    } else {
                        if l.starts_with('{') {
                            in_file_obj = true;
                        }
                        if l.starts_with(']') {
                            break;
                        }
                    }
                    i += 1;
                }
                sets.push(RegistrySet {
                    name: set_name.to_string(),
                    arch,
                    files,
                });
            }
        }
        i += 1;
    }
    sets
}

fn emuko_home() -> PathBuf {
    if let Ok(v) = env::var("EMUKO_HOME") {
        return PathBuf::from(v);
    }
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".emuko")
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

fn verify_sha256(path: &Path, expected: &str) -> bool {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let computed = stdout.split_whitespace().next().unwrap_or("");
            computed == expected
        }
        _ => false,
    }
}

fn download_file(url: &str, dest: &Path) -> Result<(), String> {
    let status = Command::new("curl")
        .args(["-sL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .map_err(|e| format!("failed to run curl: {}", e))?;
    if !status.success() {
        return Err(format!("curl exited with status {}", status));
    }
    Ok(())
}

fn run_dow(filter: Option<&str>) {
    let sets = parse_registry(REGISTRY_JSON);
    if sets.is_empty() {
        eprintln!("No download sets found in registry.");
        std::process::exit(1);
    }

    let selected: Vec<&RegistrySet> = if let Some(name) = filter {
        let found: Vec<_> = sets.iter().filter(|s| s.name == name).collect();
        if found.is_empty() {
            eprintln!("Unknown set: {}", name);
            eprintln!("Available sets:");
            for s in &sets {
                eprintln!("  {}", s.name);
            }
            std::process::exit(1);
        }
        found
    } else {
        sets.iter().collect()
    };

    let mut errors = 0;
    for set in &selected {
        let dir = emuko_home().join(&set.arch).join(&set.name);
        if let Err(e) = fs::create_dir_all(&dir) {
            eprintln!("Failed to create {}: {}", dir.display(), e);
            errors += 1;
            continue;
        }
        println!("[{}] -> {}", set.name, dir.display());

        for file in &set.files {
            let dest = dir.join(&file.save_as);

            if dest.exists() && verify_sha256(&dest, &file.sha256) {
                println!("  {} SKIP (already present, sha256 verified)", file.save_as);
                continue;
            }

            println!(
                "  Downloading {} ({})...",
                file.save_as,
                format_size(file.size)
            );
            match download_file(&file.url, &dest) {
                Ok(()) => {
                    if verify_sha256(&dest, &file.sha256) {
                        println!("  {} OK (sha256 verified)", file.save_as);
                    } else {
                        eprintln!(
                            "  {} FAILED: sha256 mismatch (expected {})",
                            file.save_as, file.sha256
                        );
                        let _ = fs::remove_file(&dest);
                        errors += 1;
                    }
                }
                Err(e) => {
                    eprintln!("  {} FAILED: {}", file.save_as, e);
                    errors += 1;
                }
            }
        }
    }
    if errors > 0 {
        eprintln!("{} file(s) failed", errors);
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// emukod subprocess management
// ---------------------------------------------------------------------------

fn find_emukod() -> PathBuf {
    if let Ok(v) = env::var("EMUKOD_BIN") {
        return PathBuf::from(v);
    }
    if let Ok(exe) = env::current_exe() {
        let mut p = exe.clone();
        p.set_file_name("emukod");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("emukod")
}

fn wait_for_api(addr: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if http_get(addr, "/v1/api/dump").is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

fn run_start(args: &[String], addr: &str) {
    // If a daemon is already running at this address, reuse it.
    if http_get(addr, "/v1/api/dump").is_ok() {
        eprintln!("Reusing existing emukod at http://{}", addr);
    } else {
        let emukod = find_emukod();
        let mut cmd = Command::new(&emukod);
        cmd.args(args);
        // Detach emukod's stdio: stdin (we own the console), stdout+stderr (UART comes via HTTP).
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        let child = cmd.spawn();
        match child {
            Ok(mut child) => {
                eprintln!("Started emukod (pid {})", child.id());
                if wait_for_api(addr, 30) {
                    eprintln!("emukod API ready at http://{}", addr);
                } else {
                    eprintln!("Warning: emukod API not ready after 30s at {}", addr);
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            eprintln!("emukod exited with {}", status);
                            std::process::exit(1);
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to start emukod ({}): {}", emukod.display(), e);
                std::process::exit(1);
            }
        }
    }

    // Make sure emulator is running.
    let _ = http_get(addr, "/v1/api/continue");

    run_console(addr);
}

fn save_terminal() -> Option<String> {
    Command::new("stty")
        .args(["-g"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn set_raw_terminal() {
    let _ = Command::new("stty").args(["raw", "-echo"]).status();
}

fn restore_terminal(saved: &str) {
    let _ = Command::new("stty").arg(saved).status();
}

// --- Minimal WebSocket client (frame encode/decode) ---

fn ws_client_encode(payload: &[u8]) -> Vec<u8> {
    // Client frames MUST be masked (RFC 6455 sec 5.1).
    let mask: [u8; 4] = [0x12, 0x34, 0x56, 0x78]; // fixed mask is fine for local use
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.push(0x82); // FIN + binary
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8); // masked + len
    } else if payload.len() <= 65535 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i % 4]);
    }
    frame
}

fn ws_client_decode(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 2 { return None; }
    let opcode = buf[0] & 0x0F;
    let len1 = (buf[1] & 0x7F) as usize;
    let (payload_len, offset) = if len1 < 126 {
        (len1, 2)
    } else if len1 == 126 {
        if buf.len() < 4 { return None; }
        (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
    } else {
        if buf.len() < 10 { return None; }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&buf[2..10]);
        (u64::from_be_bytes(arr) as usize, 10)
    };
    if buf.len() < offset + payload_len { return None; }
    // Server frames are unmasked.
    let payload = buf[offset..offset + payload_len].to_vec();
    // Treat close frame as disconnect.
    if opcode == 8 { return Some((Vec::new(), offset + payload_len)); }
    Some((payload, offset + payload_len))
}

fn ws_handshake(stream: &mut TcpStream, addr: &str) -> Result<(), String> {
    let req = format!(
        "GET /v1/ws/uart HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        addr
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    if !resp.contains("101") {
        return Err(format!("WebSocket handshake failed: {}", resp.lines().next().unwrap_or("")));
    }
    Ok(())
}

fn run_console(addr: &str) {
    let mut socket = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot connect to emukod at {}: {}", addr, e);
            return;
        }
    };
    if let Err(e) = ws_handshake(&mut socket, addr) {
        eprintln!("WebSocket error: {}", e);
        return;
    }
    let _ = socket.set_read_timeout(Some(std::time::Duration::from_millis(100)));

    let saved = save_terminal();
    eprintln!("Connected to emukod at {}", addr);
    eprintln!("  Ctrl+]      Detach (daemon keeps running)");
    eprintln!("  emuko start Reattach later");
    eprintln!("  emuko kill  Shut down daemon");
    eprintln!();
    set_raw_terminal();

    let quit = Arc::new(AtomicBool::new(false));

    // Stdin thread: read bytes, send as WebSocket binary frames.
    let quit_tx = quit.clone();
    let mut sock_tx = socket.try_clone().expect("socket clone");
    thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut locked = stdin.lock();
        let mut buf = [0u8; 256];
        loop {
            if quit_tx.load(Ordering::Relaxed) { break; }
            match locked.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if buf[..n].contains(&0x1d) {
                        // Send close frame, then quit.
                        let _ = sock_tx.write_all(&ws_client_encode(&[]));
                        quit_tx.store(true, Ordering::Relaxed);
                        break;
                    }
                    let frame = ws_client_encode(&buf[..n]);
                    if sock_tx.write_all(&frame).is_err() {
                        quit_tx.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    // Main thread: read WebSocket frames, print payload to stdout.
    let mut stdout = std::io::stdout();
    let mut read_buf = Vec::new();
    let mut tmp = [0u8; 8192];
    while !quit.load(Ordering::Relaxed) {
        match socket.read(&mut tmp) {
            Ok(0) => {
                let _ = stdout.write_all(b"\r\nemukod disconnected.\r\n");
                let _ = stdout.flush();
                break;
            }
            Ok(n) => read_buf.extend_from_slice(&tmp[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No data yet, loop around.
            }
            Err(_) => {
                let _ = stdout.write_all(b"\r\nemukod disconnected.\r\n");
                let _ = stdout.flush();
                break;
            }
        }
        // Decode all complete frames.
        while let Some((payload, consumed)) = ws_client_decode(&read_buf) {
            read_buf.drain(..consumed);
            if payload.is_empty() { continue; } // close or empty
            let _ = stdout.write_all(&payload);
            let _ = stdout.flush();
        }
    }

    if let Some(ref s) = saved {
        restore_terminal(s);
    }
    eprintln!();
    eprintln!("Detached. Emulator is still running in the background.");
    eprintln!("  emuko start   Reattach console");
    eprintln!("  emuko kill    Shut down the emulator");
}

// ---------------------------------------------------------------------------
// HTTP client command dispatch
// ---------------------------------------------------------------------------

fn run_ctl(cmd: &str, args: &mut impl Iterator<Item = String>, addr: &str) {
    let mut raw_output = false;
    let path = match cmd {
        "stop" => "/v1/api/stop".to_string(),
        "kill" | "shutdown" => "/v1/api/shutdown".to_string(),
        "con" | "continue" => "/v1/api/continue".to_string(),
        "dump" => "/v1/api/dump".to_string(),
        "disas" => "/v1/api/disas".to_string(),
        "step" => {
            if let Some(v) = args.next() {
                if parse_u64(&v).is_none() {
                    eprintln!("invalid step count: {}", v);
                    std::process::exit(1);
                }
                format!("/v1/api/step/{}", v)
            } else {
                "/v1/api/step".to_string()
            }
        }
        "restore" => {
            let Some(name) = args.next() else {
                eprintln!("Usage: emuko restore <snapshot>");
                std::process::exit(1);
            };
            format!("/v1/api/restore/{}", name)
        }
        "ls" => "/v1/api/ls".to_string(),
        "snap" => {
            if let Some(arg) = args.next() {
                if arg == "stop" || arg == "off" {
                    "/v1/api/snap/stop".to_string()
                } else if parse_u64(&arg).is_some() {
                    format!("/v1/api/snap/every/{}", arg)
                } else {
                    eprintln!("Usage: emuko snap [N|stop]");
                    std::process::exit(1);
                }
            } else {
                "/v1/api/snap".to_string()
            }
        }
        "set" => {
            let Some(reg) = args.next() else {
                eprintln!("Usage: emuko set <register> <value>");
                std::process::exit(1);
            };
            let Some(val) = args.next() else {
                eprintln!("Usage: emuko set <register> <value>");
                std::process::exit(1);
            };
            if parse_u64(&val).is_none() {
                eprintln!("invalid value: {}", val);
                std::process::exit(1);
            }
            format!("/v1/api/set/{}/{}", reg, val)
        }
        "uart" | "uart-inject" => {
            let rest: Vec<String> = args.collect();
            if rest.is_empty() {
                eprintln!("Usage: emuko uart-inject <text>");
                std::process::exit(1);
            }
            let joined = rest.join(" ");
            let bytes = match decode_escapes(&joined) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("invalid uart payload: {}", e);
                    std::process::exit(1);
                }
            };
            format!("/v1/api/uart/inject-hex/{}", hex_encode(&bytes))
        }
        "uart-read" => {
            raw_output = true;
            if let Some(v) = args.next() {
                if parse_u64(&v).is_none() {
                    eprintln!("invalid read size: {}", v);
                    std::process::exit(1);
                }
                format!("/v1/api/uart/read/{}", v)
            } else {
                "/v1/api/uart/read".to_string()
            }
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            print_usage();
            std::process::exit(1);
        }
    };

    let (status, body) = match http_get(addr, &path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("request failed: {}", e);
            std::process::exit(1);
        }
    };
    if !body.is_empty() {
        if raw_output {
            print!("{}", body);
        } else {
            println!("{}", body);
        }
    }
    if status >= 300 {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Usage and main
// ---------------------------------------------------------------------------

fn print_usage() {
    eprintln!("Usage: emuko <command> [args...]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  dow [set-name]            Download kernel/initrd from registry");
    eprintln!("  start [emukod-args...]    Start daemon + attach console (Ctrl+] to detach)");
    eprintln!("  stop                      Stop (pause) the emulator");
    eprintln!("  kill                      Shut down the daemon");
    eprintln!("  con                       Continue execution");
    eprintln!("  dump                      Print CPU state");
    eprintln!("  step [n]                  Step N instructions (default 1)");
    eprintln!("  disas                     Disassemble at current PC");
    eprintln!("  snap [N|stop]             Snapshot now / auto every N steps / stop auto");
    eprintln!("  ls                        List snapshots");
    eprintln!("  restore <snapshot>        Restore a snapshot");
    eprintln!("  set <register> <value>    Set register value");
    eprintln!("  uart-inject <text>        Inject text into guest UART");
    eprintln!("  uart-read [n]             Read from guest UART");
    eprintln!();
    eprintln!("Env: EMUKO_ADDR=127.0.0.1:7788");
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_usage();
        std::process::exit(1);
    };

    if cmd == "dow" {
        let filter = args.next();
        run_dow(filter.as_deref());
        return;
    }

    let addr = env::var("EMUKO_ADDR").unwrap_or_else(|_| "127.0.0.1:7788".to_string());

    if cmd == "start" {
        let remaining: Vec<String> = args.collect();
        run_start(&remaining, &addr);
        return;
    }

    run_ctl(&cmd, &mut args, &addr);
}
