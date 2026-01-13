// src/bin/proxy.rs
use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use ecosigner_cli::common_structs::{DKGRequest, Node, NodesConfig, SigningRequest};
use ecosigner_cli::mpe::gg20_signing::DataType;
use rand::Rng;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use ecosigner_cli::mpe::gg20_sm_manager;

// -------------------------
// Frame protocol helpers (Step3)
// -------------------------
const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024; // 10MB

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) => {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(e.into());
        }
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(anyhow!("invalid frame length: 0"));
    }
    if len > MAX_FRAME_SIZE {
        return Err(anyhow!("frame too large: {} > {}", len, MAX_FRAME_SIZE));
    }

    let mut data = vec![0u8; len];
    r.read_exact(&mut data).await?;
    Ok(Some(data))
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len();
    if len == 0 {
        return Err(anyhow!("cannot write empty frame"));
    }
    if len > MAX_FRAME_SIZE {
        return Err(anyhow!("frame too large to write: {} > {}", len, MAX_FRAME_SIZE));
    }

    let len_buf = (len as u32).to_be_bytes();
    w.write_all(&len_buf).await?;
    w.write_all(data).await?;
    Ok(())
}

// -------------------------
// Config structs
// -------------------------
#[derive(Debug, Deserialize, Clone)]
struct ProxyRelayConfig {
    /// 兼容：把 NodesConfig 的字段直接摊平到这里
    #[serde(flatten)]
    nodes: NodesConfig,

    /// proxy 对外 HTTP 端口（Rocket bind）
    #[serde(default = "default_proxy_bind")]
    proxy_bind: String,

    /// relay(sm_manager) 端口
    #[serde(default = "default_relay_port")]
    relay_port: i32,

    /// proxy fanout 超时
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

fn default_proxy_bind() -> String {
    "0.0.0.0:8080".to_string()
}
fn default_relay_port() -> i32 {
    8000
}
fn default_timeout_ms() -> u64 {
    3000
}

#[derive(Clone)]
struct ProxyState {
    nodes_config: NodesConfig,
    timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
struct SignIn {
    /// base64 digest/tbs
    tobesigned: String,
    /// optional: participant indices
    parties: Option<Vec<u16>>,
    /// optional: default Base64
    input_data_type: Option<DataType>,
    /// optional: if empty proxy auto gen
    request_index: Option<String>,
    /// optional: if empty use cfg.identity
    identity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DkgIn {
    threshold: Option<u16>,
    number_of_parties: Option<u16>,
    request_index: Option<String>,
    identity: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct NodeForward {
    node_index: u16,
    ok: bool,
    raw: String,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct FanoutResponse {
    request_index: String,
    ok: bool,
    took_ms: u128,
    forwarded: Vec<NodeForward>,
}

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
// 全局计数器（进程内唯一）
static REQ_SEQ: AtomicU64 = AtomicU64::new(0);
fn rnd_request_index() -> String {
    // ms 时间戳
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    // 进程 id（多 proxy 实例也更不容易撞）
    let pid = std::process::id();

    // 原子递增序号（同 ms 内并发也不撞）
    let seq = REQ_SEQ.fetch_add(1, Ordering::Relaxed);

    // 随机后缀（跨进程/重启进一步降低概率）
    let mut rng = rand::thread_rng();
    let r: u32 = rng.gen::<u32>();

    format!("{}-{}-{}-{:08x}", now_ms, pid, seq, r)
}

async fn read_proxy_relay_config(path: &str) -> Result<ProxyRelayConfig> {
    let buf = tokio::fs::read(path)
        .await
        .with_context(|| format!("Failed to read config file: {}", path))?;

    // 新格式（带 proxy_bind/relay_port/timeout_ms）
    if let Ok(cfg) = serde_json::from_slice::<ProxyRelayConfig>(&buf) {
        return Ok(cfg);
    }

    // 旧格式（只有 NodesConfig）
    let nodes = serde_json::from_slice::<NodesConfig>(&buf)
        .context("Failed to parse config as NodesConfig or ProxyRelayConfig")?;

    Ok(ProxyRelayConfig {
        nodes,
        proxy_bind: default_proxy_bind(),
        relay_port: default_relay_port(),
        timeout_ms: default_timeout_ms(),
    })
}

fn default_parties_from_cfg(cfg: &NodesConfig) -> Result<Vec<u16>> {
    let need = (cfg.threshold as usize) + 1;
    let mut indices: Vec<u16> = cfg.nodes.iter().map(|n| n.index).collect();
    indices.sort_unstable();
    indices.dedup();
    if indices.len() < need {
        return Err(anyhow!(
            "Not enough nodes in config: need {} (t+1), got {}",
            need,
            indices.len()
        ));
    }
    indices.truncate(need);
    Ok(indices)
}

fn pick_nodes(cfg: &NodesConfig, parties: &[u16]) -> Result<Vec<Node>> {
    let party_set: HashSet<u16> = parties.iter().copied().collect();
    let nodes: Vec<Node> = cfg
        .nodes
        .iter()
        .filter(|n| party_set.contains(&n.index))
        .cloned()
        .collect();

    if nodes.len() != party_set.len() {
        let existing: HashSet<u16> = nodes.iter().map(|n| n.index).collect();
        let missing: Vec<u16> = parties
            .iter()
            .copied()
            .filter(|p| !existing.contains(p))
            .collect();
        return Err(anyhow!("Some parties not found in config: {:?}", missing));
    }
    Ok(nodes)
}

/// spawn 前把 Node(ip=surf::Url) 解析成纯 Send 的 SocketAddr
fn resolve_node_addr(node: &Node, port: i32) -> Result<SocketAddr> {
    let host = node
        .ip
        .host_str()
        .ok_or_else(|| anyhow!("node.ip.host_str() is None (index={})", node.index))?;

    let addr_str = format!("{}:{}", host, port);
    let addr = addr_str
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve {}", addr_str))?
        .next()
        .ok_or_else(|| anyhow!("No resolved address for {}", addr_str))?;

    Ok(addr)
}

/// Step3 关键：用 frame 协议转发（与 node 对齐）
/// - 写：len(u32be)+json
/// - 读：len(u32be)+response
async fn forward_tcp(
    node_index: u16,
    addr: SocketAddr,
    payload: String,
    timeout_ms: u64,
) -> NodeForward {
    let fut = async move {
        let mut stream = TcpStream::connect(addr).await?;

        // write frame
        write_frame(&mut stream, payload.as_bytes()).await?;

        // read frame (single response)
        let resp = read_frame(&mut stream).await?;
        let resp = resp.ok_or_else(|| anyhow!("Empty response (EOF)"))?;
        let raw = String::from_utf8(resp).context("Response not valid utf8")?;

        Ok::<String, anyhow::Error>(raw)
    };

    match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut).await {
        Ok(Ok(raw)) => {
            // best-effort: parse NodeResponse, status=="Error" => fail
            let ok = serde_json::from_str::<ecosigner_cli::common_structs::NodeResponse<
                serde_json::Value,
            >>(&raw)
            .ok()
            .map(|nr| nr.status != "Error")
            .unwrap_or(true);

            NodeForward {
                node_index,
                ok,
                raw,
                error: None,
            }
        }
        Ok(Err(e)) => NodeForward {
            node_index,
            ok: false,
            raw: "".to_string(),
            error: Some(format!("Connect/IO/proto error: {:#}", e)),
        },
        Err(_) => NodeForward {
            node_index,
            ok: false,
            raw: "".to_string(),
            error: Some(format!("Timeout after {} ms", timeout_ms)),
        },
    }
}

#[rocket::post("/sign", format = "json", data = "<body>")]
async fn sign_proxy(
    state: &State<ProxyState>,
    body: Json<SignIn>,
) -> (Status, Json<FanoutResponse>) {
    let start = Instant::now();
    let cfg = state.nodes_config.clone();

    let parties = match &body.parties {
        Some(p) if !p.is_empty() => p.clone(),
        _ => match default_parties_from_cfg(&cfg) {
            Ok(p) => p,
            Err(e) => {
                let resp = FanoutResponse {
                    request_index: body.request_index.clone().unwrap_or_else(rnd_request_index),
                    ok: false,
                    took_ms: start.elapsed().as_millis(),
                    forwarded: vec![NodeForward {
                        node_index: 0,
                        ok: false,
                        raw: "".to_string(),
                        error: Some(format!("{:#}", e)),
                    }],
                };
                return (Status::BadRequest, Json(resp));
            }
        },
    };

    let signing_nodes = match pick_nodes(&cfg, &parties) {
        Ok(n) => n,
        Err(e) => {
            let resp = FanoutResponse {
                request_index: body.request_index.clone().unwrap_or_else(rnd_request_index),
                ok: false,
                took_ms: start.elapsed().as_millis(),
                forwarded: vec![NodeForward {
                    node_index: 0,
                    ok: false,
                    raw: "".to_string(),
                    error: Some(format!("{:#}", e)),
                }],
            };
            return (Status::BadRequest, Json(resp));
        }
    };

    let request_index = body.request_index.clone().unwrap_or_else(rnd_request_index);
    let identity = body.identity.clone().unwrap_or_else(|| cfg.identity.clone());
    let input_data_type = body.input_data_type.clone().unwrap_or(DataType::Base64);

    let req = SigningRequest {
        tobesigned: body.tobesigned.clone(),
        parties: parties.clone(),
        input_data_type,
        request_index: request_index.clone(),
        identity,
    };

    let payload = match serde_json::to_string(&req) {
        Ok(s) => s,
        Err(e) => {
            let resp = FanoutResponse {
                request_index,
                ok: false,
                took_ms: start.elapsed().as_millis(),
                forwarded: vec![NodeForward {
                    node_index: 0,
                    ok: false,
                    raw: "".to_string(),
                    error: Some(format!("Serialize request failed: {:#}", e)),
                }],
            };
            return (Status::InternalServerError, Json(resp));
        }
    };

    // spawn 前：把 Node -> (index, SocketAddr) 解析好，避免非 Send 类型进入 future
    let mut tasks = Vec::with_capacity(signing_nodes.len());
    for node in signing_nodes {
        let idx = node.index;
        let addr = match resolve_node_addr(&node, node.signing_port) {
            Ok(a) => a,
            Err(e) => {
                tasks.push(tokio::spawn(async move {
                    NodeForward {
                        node_index: idx,
                        ok: false,
                        raw: "".to_string(),
                        error: Some(format!("{:#}", e)),
                    }
                }));
                continue;
            }
        };

        let payload_clone = payload.clone();
        let timeout_ms = state.timeout_ms;
        tasks.push(tokio::spawn(async move {
            forward_tcp(idx, addr, payload_clone, timeout_ms).await
        }));
    }

    let mut forwarded = Vec::new();
    for t in tasks {
        match t.await {
            Ok(fwd) => forwarded.push(fwd),
            Err(e) => forwarded.push(NodeForward {
                node_index: 0,
                ok: false,
                raw: "".to_string(),
                error: Some(format!("Join error: {:#}", e)),
            }),
        }
    }

    let ok = forwarded.iter().all(|x| x.ok);
    let status = if ok { Status::Ok } else { Status::BadGateway };

    let resp = FanoutResponse {
        request_index,
        ok,
        took_ms: start.elapsed().as_millis(),
        forwarded,
    };

    (status, Json(resp))
}

#[rocket::post("/dkg", format = "json", data = "<body>")]
async fn dkg_proxy(
    state: &State<ProxyState>,
    body: Json<DkgIn>,
) -> (Status, Json<FanoutResponse>) {
    let start = Instant::now();
    let cfg = state.nodes_config.clone();

    let request_index = body.request_index.clone().unwrap_or_else(rnd_request_index);
    let identity = body.identity.clone().unwrap_or_else(|| cfg.identity.clone());
    let threshold = body.threshold.unwrap_or(cfg.threshold);
    let number_of_parties = body.number_of_parties.unwrap_or(cfg.number_of_parties);

    let req = DKGRequest {
        threshold,
        number_of_parties,
        request_index: request_index.clone(),
        identity,
    };

    let payload = match serde_json::to_string(&req) {
        Ok(s) => s,
        Err(e) => {
            let resp = FanoutResponse {
                request_index,
                ok: false,
                took_ms: start.elapsed().as_millis(),
                forwarded: vec![NodeForward {
                    node_index: 0,
                    ok: false,
                    raw: "".to_string(),
                    error: Some(format!("Serialize request failed: {:#}", e)),
                }],
            };
            return (Status::InternalServerError, Json(resp));
        }
    };

    let mut tasks = Vec::with_capacity(cfg.nodes.len());
    for node in cfg.nodes.clone() {
        let idx = node.index;
        let addr = match resolve_node_addr(&node, node.dkg_port) {
            Ok(a) => a,
            Err(e) => {
                tasks.push(tokio::spawn(async move {
                    NodeForward {
                        node_index: idx,
                        ok: false,
                        raw: "".to_string(),
                        error: Some(format!("{:#}", e)),
                    }
                }));
                continue;
            }
        };

        let payload_clone = payload.clone();
        let timeout_ms = state.timeout_ms;
        tasks.push(tokio::spawn(async move {
            forward_tcp(idx, addr, payload_clone, timeout_ms).await
        }));
    }

    let mut forwarded = Vec::new();
    for t in tasks {
        match t.await {
            Ok(fwd) => forwarded.push(fwd),
            Err(e) => forwarded.push(NodeForward {
                node_index: 0,
                ok: false,
                raw: "".to_string(),
                error: Some(format!("Join error: {:#}", e)),
            }),
        }
    }

    let ok = forwarded.iter().all(|x| x.ok);
    let status = if ok { Status::Ok } else { Status::BadGateway };

    let resp = FanoutResponse {
        request_index,
        ok,
        took_ms: start.elapsed().as_millis(),
        forwarded,
    };

    (status, Json(resp))
}

#[rocket::get("/health")]
fn health() -> &'static str {
    "ok"
}

fn parse_bind(s: &str) -> Result<(String, u16)> {
    let sa: SocketAddr = s.parse().with_context(|| format!("Invalid bind addr: {}", s))?;
    Ok((sa.ip().to_string(), sa.port()))
}

async fn run_proxy_http(bind: &str, state: ProxyState) -> Result<()> {
    let (addr, port) = parse_bind(bind)?;
    let figment = rocket::Config::figment()
        .merge(("address", addr))
        .merge(("port", port));

    rocket::custom(figment)
        .manage(state)
        .mount("/", rocket::routes![health, sign_proxy, dkg_proxy])
        .launch()
        .await
        .map_err(|e| anyhow!("Proxy Rocket launch failed: {:#}", e))?;

    Ok(())
}

async fn run_relay(relay_port: i32) -> Result<()> {
    let args = gg20_sm_manager::Cli::from_port(relay_port);
    gg20_sm_manager::gg20_sm_manager(args)
        .await
        .map_err(|e| anyhow!("Relay(sm_manager) failed: {}", e))?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut config_path =
        std::env::var("ECOSIGNER_CONFIG").unwrap_or_else(|_| "./config.json".to_string());

    let mut bind_override: Option<String> = None;
    let mut relay_port_override: Option<i32> = None;
    let mut timeout_override: Option<u64> = None;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                if i < args.len() {
                    config_path = args[i].clone();
                }
            }
            "--bind" => {
                i += 1;
                if i < args.len() {
                    bind_override = Some(args[i].clone());
                }
            }
            "--relay-port" => {
                i += 1;
                if i < args.len() {
                    relay_port_override = args[i].parse().ok();
                }
            }
            "--timeout-ms" => {
                i += 1;
                if i < args.len() {
                    timeout_override = args[i].parse().ok();
                }
            }
            _ => {}
        }
        i += 1;
    }

    let cfg = read_proxy_relay_config(&config_path).await?;

    let proxy_bind = bind_override.unwrap_or_else(|| cfg.proxy_bind.clone());
    let relay_port = relay_port_override.unwrap_or(cfg.relay_port);
    let timeout_ms = timeout_override.unwrap_or(cfg.timeout_ms);

    let state = ProxyState {
        nodes_config: cfg.nodes.clone(),
        timeout_ms,
    };

    tokio::try_join!(run_proxy_http(&proxy_bind, state), run_relay(relay_port))?;

    Ok(())
}
