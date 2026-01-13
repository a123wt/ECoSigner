use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use curv::elliptic::curves::Point;
use serde::Serialize;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;

use ecosigner_cli::common_structs::{DKGRequest, NodeResponse, SigningRequest};
use ecosigner_cli::mpe::gg20_keygen;
use ecosigner_cli::mpe::gg20_signing;

type ECCURVE = curv::elliptic::curves::secp256_k1::Secp256k1;

#[derive(Debug, StructOpt, Clone)]
#[structopt(name = "Share Node")]
struct Cli {
    #[structopt(short, long)]
    index: u16,

    #[structopt(short, long, default_value = "12370")]
    dkg_listen_port: i32,

    #[structopt(short, long, default_value = "12380")]
    signing_listen_port: i32,

    #[structopt(short = "c", long, default_value = "http://localhost:8000/")]
    inter_node_comm: surf::Url,

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = Cli::from_args();
    print_node_info(&config);

    // LocalSet 允许 spawn_local（不要求 Send），解决 surf::Url 非 Send 导致的 tokio::spawn 报错
    let local = LocalSet::new();

    local
        .run_until(async move {
            let cfg1 = config.clone();
            let cfg2 = config.clone();

            tokio::task::spawn_local(async move {
                listen_dkg(cfg1).await;
            });

            tokio::task::spawn_local(async move {
                listen_signing(cfg2).await;
            });

            // 两个 listener 都是无限循环，这里 await 一个永远不会结束的 future
            futures::future::pending::<()>().await;
        })
        .await;

    Ok(())
}

#[allow(non_snake_case)]
async fn listen_dkg(config: Cli) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.dkg_listen_port))
        .await
        .unwrap();
    println!("   >> DKG listening port: {}", config.dkg_listen_port);

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let cfg = config.clone();

        tokio::task::spawn_local(async move {
            println!("{}", "\nNew DKG connection:".bold());

            let mut buffer = vec![0u8; 64 * 1024];
            let bytes_read = match socket.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error reading socket: {}", e);
                    return;
                }
            };
            if bytes_read == 0 {
                eprintln!("Empty request");
                return;
            }
            let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
            println!("   >> Received request: {}", request);

            let parsed_request: Result<DKGRequest, serde_json::Error> = serde_json::from_str(&request);
            if let Err(error) = parsed_request {
                eprintln!("Failed to parse DKG request: {}", error);
                let _ = socket.write_all(b"Error: Wrong request").await;
                return;
            }
            let parsed_request = parsed_request.unwrap();
            println!("   >> Parsing request successfully");

            if !authenticate(parsed_request.identity.clone()) {
                println!("{}{}", "   >> Authentication result: ", "false".red());
                let _ = socket.write_all(b"Error: Authentication failed").await;
                return;
            }
            println!("{}{}", "   >> Authentication result: ", "True".green());

            let result = invoke_gg20_dkg(cfg, parsed_request.clone()).await;
            let response = prepare_response(parsed_request.request_index.clone(), result).await;

            match response {
                Ok(resp) => {
                    let _ = socket.write_all(resp.as_bytes()).await;
                }
                Err(e) => {
                    let _ = socket
                        .write_all(format!("Error: {}", e).as_bytes())
                        .await;
                }
            }
        });
    }
}

async fn listen_signing(config: Cli) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.signing_listen_port))
        .await
        .unwrap();
    println!("   >> Signing listening port: {}", config.signing_listen_port);

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let cfg = config.clone();

        tokio::task::spawn_local(async move {
            println!("{}", "\nNew signing connection:".bold());

            let mut buffer = vec![0u8; 64 * 1024];
            let bytes_read = match socket.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error reading socket: {}", e);
                    return;
                }
            };
            if bytes_read == 0 {
                eprintln!("Empty request");
                return;
            }
            let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
            println!("   >> Received request: {}", request);

            let parsed_request: Result<SigningRequest, serde_json::Error> =
                serde_json::from_str(&request);

            if let Err(error) = parsed_request {
                eprintln!("Failed to parse signing request: {}", error);
                let _ = socket.write_all(b"Error: Wrong request").await;
                return;
            }
            let parsed_request = parsed_request.unwrap();
            println!("   >> Parsing request successfully");

            if !authenticate(parsed_request.identity.clone()) {
                println!("{}{}", "   >> Authentication result: ", "false".red());
                let _ = socket.write_all(b"Error: Authentication failed").await;
                return;
            }
            println!("{}{}", "   >> Authentication result: ", "True".green());

            let result = invoke_gg20_signing(cfg, parsed_request.clone()).await;
            let response = prepare_response(parsed_request.request_index.clone(), result).await;

            match response {
                Ok(resp) => {
                    let _ = socket.write_all(resp.as_bytes()).await;
                }
                Err(e) => {
                    let _ = socket
                        .write_all(format!("Error: {}", e).as_bytes())
                        .await;
                }
            }
        });
    }
}

async fn invoke_gg20_dkg(config: Cli, request: DKGRequest) -> Result<Point<ECCURVE>> {
    ensure_shares_dir(&config);

    let path = share_file(&config, &request.identity);

    // 覆盖逻辑：如果文件已存在，先删掉，确保覆盖（避免 gg20_keygen 内部写入策略差异）
    if path.exists() {
        let _ = fs::remove_file(&path);
    }

    let args_dkg = gg20_keygen::Cli {
        address: config.inter_node_comm,
        room: format!("dkg_room_{}", request.request_index),
        output: path,
        index: config.index,
        threshold: request.threshold,
        number_of_parties: request.number_of_parties,
    };

    println!("{}{}", "   >> Threshold is : ", args_dkg.threshold);
    println!("{}{:?}", "   >> Number of parties is: ", args_dkg.number_of_parties);
    println!("{}{}", "   >> Index of signing request is: ", args_dkg.room);

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

    let args_signing = gg20_signing::Cli {
        address: config.inter_node_comm,
        room: format!("signing_room_{}", request.request_index.clone()),
        local_share: path,
        index: config.index, // ✅ 修复：补上 index
        parties: request.parties,
        data_to_sign: request.tobesigned,
        input_data_type: request.input_data_type,
        output_data_type: gg20_signing::DataType::Base64,
    };

    println!("{}{}", "   >> To be signed data is: ", args_signing.data_to_sign);
    println!("{}{:?}", "   >> Index of signing nodes is: ", args_signing.parties);
    println!("{}{}", "   >> Index of signing request is: ", args_signing.room);
    println!("{}{:?}", "   >> Type of input data is: ", args_signing.input_data_type);

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
