use std::env;
use std::path::PathBuf;
use std::process::Command;

fn target_bin(name: &str) -> Result<PathBuf, String> {
    let mut path = env::current_exe().map_err(|e| e.to_string())?;
    path.set_file_name(name);
    Ok(path)
}

fn main() {
    let target = match target_bin("emuko-ctl") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to locate emuko-ctl: {}", e);
            std::process::exit(1);
        }
    };
    let status = Command::new(target).args(env::args().skip(1)).status();
    match status {
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("failed to exec emuko-ctl: {}", e);
            std::process::exit(1);
        }
    }
}
