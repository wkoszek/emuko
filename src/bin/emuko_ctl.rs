use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

fn print_usage_and_exit() -> ! {
    eprintln!("Usage:");
    eprintln!("  emu start");
    eprintln!("  emu stop");
    eprintln!("  emu step [n]");
    eprintln!("  emu dump");
    eprintln!("  emu disas");
    eprintln!("  emu con");
    eprintln!("  emu restore <snapshot>");
    eprintln!("  emu ls");
    eprintln!("  emu snap");
    eprintln!("  emu set <register> <value>");
    eprintln!("  emu uart-inject <text>");
    eprintln!("  emu uart-read [n]");
    eprintln!("Env:");
    eprintln!("  EMUKO_ADDR=127.0.0.1:7788");
    std::process::exit(1);
}

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

fn main() {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_usage_and_exit();
    };
    let addr = env::var("EMUKO_ADDR").unwrap_or_else(|_| "127.0.0.1:7788".to_string());

    let mut raw_output = false;
    let path = match cmd.as_str() {
        "start" => "/v1/api/start".to_string(),
        "stop" => "/v1/api/stop".to_string(),
        "dump" => "/v1/api/dump".to_string(),
        "disas" => "/v1/api/disas".to_string(),
        "con" | "continue" => "/v1/api/continue".to_string(),
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
                print_usage_and_exit();
            };
            format!("/v1/api/restore/{}", name)
        }
        "ls" => "/v1/api/ls".to_string(),
        "snap" => "/v1/api/snap".to_string(),
        "set" => {
            let Some(reg) = args.next() else {
                print_usage_and_exit();
            };
            let Some(val) = args.next() else {
                print_usage_and_exit();
            };
            if parse_u64(&val).is_none() {
                eprintln!("invalid value: {}", val);
                std::process::exit(1);
            }
            format!("/v1/api/set/{}/{}", reg, val)
        }
        "uart-inject" => {
            let rest: Vec<String> = args.collect();
            if rest.is_empty() {
                print_usage_and_exit();
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
        _ => print_usage_and_exit(),
    };

    let (status, body) = match http_get(&addr, &path) {
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
