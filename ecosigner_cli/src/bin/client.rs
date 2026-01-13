// src/bin/client.rs
use anyhow::{anyhow, Context, Result};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn usage() -> &'static str {
    r#"Usage:
  client sign --proxy 127.0.0.1:8000 --digest ./hello.exe.dig [--parties 1,2]
  client dkg  --proxy 127.0.0.1:8000

Examples:
  cargo run --bin client -- dkg  --proxy 127.0.0.1:8000
  cargo run --bin client -- sign --proxy 127.0.0.1:8000 --digest ./hello.exe.dig --parties 1,2
"#
}

fn parse_arg(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|x| x == key)
        .and_then(|pos| args.get(pos + 1).cloned())
}

fn parse_parties(s: &str) -> Result<Vec<u16>> {
    let mut v = Vec::new();
    for part in s.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        v.push(p.parse::<u16>().with_context(|| format!("Invalid party: {}", p))?);
    }
    if v.is_empty() {
        return Err(anyhow!("--parties provided but empty"));
    }
    Ok(v)
}

/// 支持：
/// - "http://127.0.0.1:8000"
/// - "127.0.0.1:8000"
/// - "127.0.0.1"（默认 80）
/// 返回：(tcp_addr, host_header)
fn normalize_proxy(proxy: &str) -> (String, String) {
    let p = proxy.trim().trim_end_matches('/');

    let host_port = if p.starts_with("http://") {
        p.trim_start_matches("http://").to_string()
    } else {
        p.to_string()
    };

    let tcp_addr = if host_port.contains(':') {
        host_port.clone()
    } else {
        format!("{}:80", host_port)
    };

    (tcp_addr, host_port)
}

/// 最小 HTTP/1.1 POST（纯文本，非 TLS）
/// 返回 (status_code, body)
async fn http_post_raw(proxy: &str, path: &str, body: &str) -> Result<(u16, String)> {
    let (tcp_addr, host_header) = normalize_proxy(proxy);

    eprintln!("[client] connect to {}", tcp_addr);

    let mut stream = TcpStream::connect(&tcp_addr)
        .await
        .with_context(|| format!("Failed to connect to proxy {}", tcp_addr))?;

    let req = format!(
        "POST {} HTTP/1.1\r\n\
Host: {}\r\n\
Content-Type: application/json\r\n\
Accept: */*\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
\r\n\
{}",
        path,
        host_header,
        body.as_bytes().len(),
        body
    );

    stream.write_all(req.as_bytes()).await?;

    // 读取响应（加超时，避免卡死）
    let read_fut = async {
        let mut buf = Vec::with_capacity(64 * 1024);
        let mut tmp = [0u8; 8192];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        Ok::<Vec<u8>, anyhow::Error>(buf)
    };

    let buf = tokio::time::timeout(std::time::Duration::from_secs(10), read_fut)
        .await
        .map_err(|_| anyhow!("Read timeout (10s). Is proxy responding?"))??;

    if buf.is_empty() {
        return Err(anyhow!(
            "Empty response from proxy {}. \
Possible causes: wrong port, proxy not running, or you connected to a non-HTTP service.",
            tcp_addr
        ));
    }

    let resp = String::from_utf8_lossy(&buf).to_string();
    let (head, body_part) = resp.split_once("\r\n\r\n").unwrap_or((resp.as_str(), ""));

    let status_line = head.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("Failed to parse HTTP status line: {}", status_line))?;

    Ok((status_code, body_part.to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", usage());
        return Err(anyhow!("Missing subcommand"));
    }

    let cmd = args[1].as_str();
    match cmd {
        "sign" => {
            let proxy = parse_arg(&args, "--proxy").unwrap_or_else(|| "127.0.0.1:8000".to_string());
            let digest_path = parse_arg(&args, "--digest").ok_or_else(|| anyhow!("Missing --digest"))?;
            let parties = parse_arg(&args, "--parties").map(|s| parse_parties(&s)).transpose()?;

            let tbs_base64 = tokio::fs::read_to_string(&digest_path)
                .await
                .with_context(|| format!("Failed to read digest file: {}", digest_path))?
                .trim()
                .to_string();

            let body = if let Some(p) = parties {
                json!({ "tobesigned": tbs_base64, "parties": p })
            } else {
                json!({ "tobesigned": tbs_base64 })
            };

            let (code, resp_body) = http_post_raw(&proxy, "/sign", &body.to_string()).await?;
            println!("HTTP {}", code);
            println!("{}", resp_body);
            Ok(())
        }
        "dkg" => {
            let proxy = parse_arg(&args, "--proxy").unwrap_or_else(|| "127.0.0.1:8000".to_string());
            let body = json!({}).to_string();

            let (code, resp_body) = http_post_raw(&proxy, "/dkg", &body).await?;
            println!("HTTP {}", code);
            println!("{}", resp_body);
            Ok(())
        }
        _ => {
            eprintln!("{}", usage());
            Err(anyhow!("Unknown subcommand: {}", cmd))
        }
    }
}
