use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

fn print_usage_and_exit() -> ! {
    eprintln!("Usage:");
    eprintln!("  kor start");
    eprintln!("  kor stop");
    eprintln!("  kor step [n]");
    eprintln!("  kor dump");
    eprintln!("  kor disas");
    eprintln!("  kor con");
    eprintln!("  kor restore <snapshot>");
    eprintln!("  kor ls");
    eprintln!("  kor snap");
    eprintln!("  kor set <register> <value>");
    eprintln!("Env:");
    eprintln!("  KOR_ADDR=127.0.0.1:7788");
    std::process::exit(1);
}

fn parse_u64(arg: &str) -> Option<u64> {
    if let Some(hex) = arg.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        arg.parse::<u64>().ok()
    }
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
    let addr = env::var("KOR_ADDR").unwrap_or_else(|_| "127.0.0.1:7788".to_string());

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
        println!("{}", body);
    }
    if status >= 300 {
        std::process::exit(1);
    }
}
