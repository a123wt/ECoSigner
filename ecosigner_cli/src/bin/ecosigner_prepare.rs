// use core::slice::SlicePattern;

use anyhow::{Context, Result};
use colored::Colorize;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use ecosigner_cli::common_structs::{
    DKGRequest, Node, NodeResponse, NodesConfig, SigningRequest, X509Config, self,
};
use futures::{
    future::{join_all, ok},
    stream::{FuturesOrdered, FuturesUnordered},
};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{self, PKey},
    x509::{X509NameBuilder, X509Req, X509ReqBuilder},
};
use rand::Rng;
use rocket::http::hyper::request;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};
use surf::Url;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::main]
async fn main() -> Result<()> {
    let nodes_config = read_config_nodes(
        "/root/workspace/ecosigner/ecosigner_cli/src/bin/config_nodes.json".to_string(),
    )
    .await
    .context("Failed to read nodes config file")?;
    let _ = request_dkg(&nodes_config).await;
    Ok(())
}

async fn read_config_nodes(path: String) -> Result<NodesConfig> {
    let nodesconfig_file = tokio::fs::read(PathBuf::from(path))
        .await
        .context("Failed to read nodes config file")?;
    let nodesconfig = serde_json::from_slice::<NodesConfig>(nodesconfig_file.as_slice())
        .context("Failed to parse nodes config file")?;
    return Ok(nodesconfig);
}

async fn read_config_csr(path: String) -> Result<X509Config> {
    let x509config_file = tokio::fs::read(PathBuf::from(path))
        .await
        .context("Failed to read csr config file")?;
    let x509config = serde_json::from_slice::<X509Config>(x509config_file.as_slice())
        .context("Failed to parse csr config file")?;
    return Ok(x509config);
}

async fn request_dkg(nodes_config: &NodesConfig) -> Result<()> {
    println!("{}", "\nRequest Distributed Key Generation:".bold());
    let nodes_config = nodes_config.clone();
    let request = DKGRequest {
        threshold: nodes_config.threshold,
        number_of_parties: nodes_config.number_of_parties,
        request_index: rnd_request_index(),
        identity: nodes_config.identity,
    };
    let request = serde_json::to_string(&request).context("Fail to read config to request DKG")?;
    println!("   >> DKG request is: {}", request);

    let mut tasks = vec![];
    // let mut responses = Vec::<NodeResponse>::with_capacity(nodes_config.number_of_parties as usize);

    for i in nodes_config.nodes {
        let request_clone = request.clone();

        let task: tokio::task::JoinHandle<
            Result<String, Box<dyn std::error::Error + Send + Sync>>,
        > = tokio::spawn(async move {
            let i_clone = i.clone();

            // 连接到目标主机的 TCP 服务器
            let addr = format!("{}:{}", i_clone.ip.host_str().unwrap(), i_clone.dkg_port)
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap();
            let mut stream = TcpStream::connect(addr).await?;

                // 要发送的文本数据
                let message = request_clone.clone();

                // 将文本数据写入 TCP 连接
                stream.write_all(message.as_bytes()).await?;

                // 接收服务器的响应
                // let mut response = String::new();
                // stream.read_to_string(&mut response).await?;
                let mut buffer=[0u8;1024];
                let bytes_read = stream.read(&mut buffer).await.unwrap();
                let response = String::from_utf8_lossy(&buffer[..bytes_read]);

                // 打印服务器响应
                println!(
                    "   >> DKG response of node {} is: {}",
                    i_clone.index, response
                );
            
            Ok(response.to_string())
        });
        std::thread::sleep(std::time::Duration::from_secs(1));

        tasks.push(task);
    }

    // 读取每个task返回的response并将其压入responses
    let task_results = join_all(tasks).await;

    for result in task_results {
        match result {
            Ok(Ok(r_ok_ok))=>{
                let parsed_response: common_structs::NodeResponse<Point<Secp256k1>>=serde_json::from_str(&r_ok_ok).context("Failed to parse the response")?;
                println!("   >> Public key: {}",serde_json::to_string(&parsed_response.data).context("Failed to parse the response")?)
            },
            Ok(Err(r_ok_err))=>{
                eprintln!("   >> Net error: {}",r_ok_err)
            },
            Err(err)=>{
                eprintln!("   >> Async tasks error: {}",err)
            }
        }

    }

    Ok(())
}

fn rnd_request_index() -> String {
    let mut rng = rand::thread_rng();
    let number: u32 = rng.gen_range(100..=999);
    number.to_string()
}

fn create_certificate(nodes: NodesConfig, x509config: X509Config) -> Result<()> {
    Ok(())
}

fn pre_build_req() {}

fn sign_req() {}

async fn build_req(x509config: X509Config) -> Result<X509Req> {
    let public_key_point = x509config.public_key;
    let public_key_bytes = public_key_point.to_bytes(false).to_vec();
    let public_key_pkey =
        PKey::public_key_from_raw_bytes(public_key_bytes.as_slice(), pkey::Id::EC)
            .context("Failed to get public key bytes")?;

    // 创建证书请求生成器
    let mut req_builder = X509ReqBuilder::new().unwrap();
    req_builder.set_version(3)?;

    // 设置主题（subject）
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_nid(Nid::COMMONNAME, "beishulian.com")?;
    subject.append_entry_by_nid(Nid::ORGANIZATIONNAME, "背书链 积至")?;

    // 添加其他主题字段（根据需要添加）
    req_builder.set_subject_name(&subject.build())?;
    req_builder.set_pubkey(&public_key_pkey)?;

    let req = req_builder.build();

    Ok(req)
}

fn request_x509() {}
