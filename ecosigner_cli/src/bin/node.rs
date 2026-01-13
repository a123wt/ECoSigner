use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use curv::elliptic::curves::Point;
use serde::Serialize;
use structopt::StructOpt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use ecosigner_cli::common_structs::{DKGRequest, NodeResponse, SigningRequest};
use ecosigner_cli::mpe::gg20_keygen;
use ecosigner_cli::mpe::gg20_signing;

type ECCURVE = curv::elliptic::curves::secp256_k1::Secp256k1;

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

#[derive(Debug, StructOpt, Clone)]
#[structopt(name = "Share Node")]
struct Cli {
    #[structopt(short, long)]
    index: u16,

    #[structopt(short, long, default_value = "12370")]
    dkg_listen_port: i32,

    #[structopt(short, long, default_value = "12380")]
    signing_listen_port: i32,

    /// IMPORTANT: store as String so Cli becomes Send (surf::Url may be !Send)
    #[structopt(short = "c", long, default_value = "http://localhost:8000/")]
    inter_node_comm: String,

    /// Base directory for per-node local shares.
    /// Default keeps old layout: ./local-shares-<index>/id_<identity>.json
    #[structopt(long, default_value = ".")]
    shares_base: String,
}

/// <shares_base>/local-shares-<index>
fn shares_dir(cfg: &Cli) -> PathBuf {
    let base = cfg.shares_base.trim_end_matches('/');
    PathBuf::from(format!("{}/local-shares-{}", base, cfg.index))
}

/// <shares_base>/local-shares-<index>/id_<identity>.json
fn share_file(cfg: &Cli, identity: &str) -> PathBuf {
    shares_dir(cfg).join(format!("id_{}.json", identity))
}

fn ensure_shares_dir(cfg: &Cli) {
    let dir = shares_dir(cfg);
    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            eprintln!("Error creating directory {}: {}", dir.display(), e);
        } else {
            println!("Created directory: {}", dir.display());
        }
    }
}

fn print_node_info(cfg: &Cli) {
    ensure_shares_dir(cfg);

    println!("{}", "\nNode info:".bold());
    println!("   >> Node index: {}", cfg.index);
    println!("   >> Local shares dir: {}", shares_dir(cfg).display());
    println!("   >> inter-node communication: {}", cfg.inter_node_comm);
}

#[tokio::main] // ✅ multi-thread runtime
async fn main() -> Result<()> {
    let config = Cli::from_args();
    print_node_info(&config);

    let cfg1 = config.clone();
    let cfg2 = config.clone();

    let dkg_task = tokio::spawn(async move { listen_dkg(cfg1).await });
    let signing_task = tokio::spawn(async move { listen_signing(cfg2).await });

    let _ = tokio::try_join!(dkg_task, signing_task);
    Ok(())
}

#[allow(non_snake_case)]
async fn listen_dkg(config: Cli) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.dkg_listen_port))
        .await
        .context("bind dkg listener")?;
    println!("   >> DKG listening port: {}", config.dkg_listen_port);

    loop {
        let (mut socket, _) = listener.accept().await.context("accept dkg")?;
        let cfg = config.clone();

        tokio::spawn(async move {
            println!("{}", "\nNew DKG connection:".bold());

            loop {
                let frame = match read_frame(&mut socket).await {
                    Ok(Some(b)) => b,
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("Failed to read frame: {}", e);
                        break;
                    }
                };

                let request_str = match String::from_utf8(frame) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Invalid utf8 request: {}", e);
                        let _ = write_frame(
                            &mut socket,
                            b"{\"status\":\"Error\",\"data\":\"Invalid UTF-8\"}",
                        )
                        .await;
                        continue;
                    }
                };

                if request_str.len() <= 512 {
                    println!("   >> Received request: {}", request_str);
                } else {
                    println!("   >> Received request: ({} bytes)", request_str.len());
                }

                let parsed_request: std::result::Result<DKGRequest, serde_json::Error> =
                    serde_json::from_str(&request_str);

                if let Err(error) = parsed_request {
                    eprintln!("Failed to parse DKG request: {}", error);
                    let _ = write_frame(&mut socket, b"Error: Wrong request").await;
                    continue;
                }
                let parsed_request = parsed_request.unwrap();
                println!("   >> Parsing request successfully");

                if !authenticate(parsed_request.identity.clone()) {
                    println!("{}{}", "   >> Authentication result: ", "false".red());
                    let _ = write_frame(&mut socket, b"Error: Authentication failed").await;
                    continue;
                }
                println!("{}{}", "   >> Authentication result: ", "True".green());

                let result = invoke_gg20_dkg(cfg.clone(), parsed_request.clone()).await;
                let response =
                    prepare_response(parsed_request.request_index.clone(), result).await;

                match response {
                    Ok(resp) => {
                        if let Err(e) = write_frame(&mut socket, resp.as_bytes()).await {
                            eprintln!("Error writing frame: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        let msg = format!("Error: {}", e);
                        let _ = write_frame(&mut socket, msg.as_bytes()).await;
                    }
                }
            }
        });
    }
}

async fn listen_signing(config: Cli) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.signing_listen_port))
        .await
        .context("bind signing listener")?;
    println!(
        "   >> Signing listening port: {}",
        config.signing_listen_port
    );

    loop {
        let (mut socket, _) = listener.accept().await.context("accept signing")?;
        let cfg = config.clone();

        tokio::spawn(async move {
            println!("{}", "\nNew signing connection:".bold());

            loop {
                let frame = match read_frame(&mut socket).await {
                    Ok(Some(b)) => b,
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("Failed to read frame: {}", e);
                        break;
                    }
                };

                let request_str = match String::from_utf8(frame) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Invalid utf8 request: {}", e);
                        let _ = write_frame(
                            &mut socket,
                            b"{\"status\":\"Error\",\"data\":\"Invalid UTF-8\"}",
                        )
                        .await;
                        continue;
                    }
                };

                if request_str.len() <= 512 {
                    println!("   >> Received request: {}", request_str);
                } else {
                    println!("   >> Received request: ({} bytes)", request_str.len());
                }

                let parsed_request: std::result::Result<SigningRequest, serde_json::Error> =
                    serde_json::from_str(&request_str);

                if let Err(error) = parsed_request {
                    eprintln!("Failed to parse signing request: {}", error);
                    let _ = write_frame(&mut socket, b"Error: Wrong request").await;
                    continue;
                }
                let parsed_request = parsed_request.unwrap();
                println!("   >> Parsing request successfully");

                if !authenticate(parsed_request.identity.clone()) {
                    println!("{}{}", "   >> Authentication result: ", "false".red());
                    let _ = write_frame(&mut socket, b"Error: Authentication failed").await;
                    continue;
                }
                println!("{}{}", "   >> Authentication result: ", "True".green());

                // ✅ 关键：signing 不做 renumber，让 share index 和协议 index 保持一致
                let result = invoke_gg20_signing(cfg.clone(), parsed_request.clone()).await;
                let response =
                    prepare_response(parsed_request.request_index.clone(), result).await;

                match response {
                    Ok(resp) => {
                        if let Err(e) = write_frame(&mut socket, resp.as_bytes()).await {
                            eprintln!("Error writing frame: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        let msg = format!("Error: {}", e);
                        let _ = write_frame(&mut socket, msg.as_bytes()).await;
                    }
                }
            }
        });
    }
}

async fn invoke_gg20_dkg(config: Cli, request: DKGRequest) -> Result<Point<ECCURVE>> {
    ensure_shares_dir(&config);

    let path = share_file(&config, &request.identity);
    if path.exists() {
        let _ = fs::remove_file(&path);
    }

    let address = surf::Url::parse(&config.inter_node_comm)
        .with_context(|| format!("invalid inter_node_comm url: {}", config.inter_node_comm))?;

    let args_dkg = gg20_keygen::Cli {
        address,
        room: format!("dkg_room_{}", request.request_index),
        output: path,
        index: config.index,
        threshold: request.threshold,
        number_of_parties: request.number_of_parties,
    };

    println!("{}{}", "   >> Threshold is : ", args_dkg.threshold);
    println!(
        "{}{:?}",
        "   >> Number of parties is: ",
        args_dkg.number_of_parties
    );
    println!(
        "{}{}",
        "   >> Index of signing request is: ",
        args_dkg.room
    );

    gg20_keygen::gg20_keygen(args_dkg).await
}

async fn invoke_gg20_signing(config: Cli, request: SigningRequest) -> Result<String> {
    ensure_shares_dir(&config);

    let path = share_file(&config, &request.identity);
    if !path.exists() {
        return Err(anyhow!(
            "local share not found: {} (run DKG first?)",
            path.display()
        ));
    }

    // ✅ 强约束：这里不做 renumber。proxy/client 必须传连续 parties，或默认 [1..t+1]
    // 如收到 [1,3]/[2,3] 这种非连续子集，会导致协议或 share 不匹配（应由 proxy 拦截）。
    println!(
        "   >> Signing parties (must be contiguous [1..k]): {:?}",
        request.parties
    );

    let address = surf::Url::parse(&config.inter_node_comm)
        .with_context(|| format!("invalid inter_node_comm url: {}", config.inter_node_comm))?;

    let args_signing = gg20_signing::Cli {
        address,
        room: format!("signing_room_{}", request.request_index.clone()),
        local_share: path,

        // ✅ 使用节点 index（与 share 绑定）
        index: config.index,

        // ✅ 使用请求 parties（要求连续）
        parties: request.parties,

        data_to_sign: request.tobesigned,
        input_data_type: request.input_data_type,
        output_data_type: gg20_signing::DataType::Base64,
    };

    gg20_signing::gg20_signing(args_signing).await
}

fn authenticate(authinfo: String) -> bool {
    !authinfo.is_empty()
}

async fn prepare_response<T: Serialize>(request_index: String, result: Result<T>) -> Result<String> {
    match result {
        Ok(data) => {
            println!("   >> Success: {}", serde_json::to_string(&data)?);
            let response = NodeResponse {
                request_index,
                status: "New".to_string(),
                data,
            };
            serde_json::to_string(&response).context("Failed to generate json response")
        }
        Err(error) => {
            eprintln!("Error: {}", error);
            let response = NodeResponse {
                request_index,
                status: "Error".to_string(),
                data: error.to_string(),
            };
            serde_json::to_string(&response).context("Failed to generate json response")
        }
    }
}
