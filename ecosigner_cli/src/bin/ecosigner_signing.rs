// use core::slice::SlicePattern;

use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use ecosigner_cli::common_structs::{
    self, DKGRequest, Node, NodeResponse, NodesConfig, SigningRequest, X509Config,
};
use futures::{
    future::{join_all, ok},
    stream::{FuturesOrdered, FuturesUnordered},
};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{self, PKey},
    x509::{X509NameBuilder, X509Req, X509ReqBuilder}, ec, base64,
};
use rand::Rng;
use rocket::{http::hyper::request, config};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf, io::Write,
};
use surf::Url;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use secp256k1::ecdsa::Signature;

type ECCURVE = curv::elliptic::curves::secp256_k1::Secp256k1;

#[tokio::main]
async fn main() -> Result<()> {
    let nodes_config=read_config_nodes("./config_nodes.json".to_string()).await?;
    let tbs_base64 = tokio::fs::read_to_string(PathBuf::from("./hello.exe.dig"))
        .await
        .context("Failed to read nodes config file")?;

    let signing_response=request_signing(tbs_base64, vec![1,2], &nodes_config).await?;
    let result=check_responses_signing(signing_response)?;
    println!("   >> 代码摘要签名值 {}",result);

    let mut file = std::fs::File::create("./hello.exe.dig.signed").expect("Failed to create file");
    file.write_all(result.as_bytes()).expect("Failed to write to file");

    Ok(())
}

async fn read_config_nodes(path: String) -> Result<NodesConfig> {
    let nodesconfig_file = tokio::fs::read(PathBuf::from(path))
        .await
        .context("Failed to read nodes config file")?;
    let nodesconfig = serde_json::from_slice::<NodesConfig>(nodesconfig_file.as_slice())
        .context("Failed to parse nodes config file")?;
    Ok(nodesconfig)
}

fn check_responses_signing(responses:Vec<NodeResponse<String>>)->Result<String>{
    // todo
    let is_equal = responses.iter().all(|x| x.data == responses[0].data);

    if is_equal{
        println!("   >> 检查签名响应: {}","Valid".green().bold());
        return Ok(responses[0].data.to_owned())
    }
    eprintln!("   >> 检查签名响应: {}","Invalid".red().bold());
    return Err(anyhow!("Failed to pass responses check"))

}
fn verify_signature(tbs_base64:String,sig:String,public_key:Point<Secp256k1>)->Result<bool>{
    let tbs_bytes=base64::decode_block(&tbs_base64).map_err(|_| anyhow!("Failed decode to be signed data as base64"))?;
    let sig_bytes=base64::decode_block(&sig).map_err(|_| anyhow!("Failed decode signature as base64"))?;
    let sig_secp256k1=Signature::from_compact(&sig_bytes)?;
    let sig_der=sig_secp256k1.serialize_der();
    let sig_openssl=EcdsaSig::from_der(&sig_der)?;

    let public_key_bytes = public_key.to_bytes(true).to_vec();
    let ecg = ec::EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let public_key_ec_point=openssl::ec::EcPoint::from_bytes(ecg.as_ref(), public_key_bytes.as_ref(), &mut ctx)?;
    let public_key_eckey =
        openssl::ec::EcKey::from_public_key(ecg.as_ref(), public_key_ec_point.as_ref()).context("Failed to get public key bytes")?;
    // let public_key_der=public_key_eckey.public_key_to_der()?;
    // let public_key_pkey=PKey::from_ec_key(public_key_eckey)?;
    
    let result=sig_openssl.verify(&tbs_bytes, public_key_eckey.as_ref()).context("Failed to verify signature")?;
    Ok(result)
}


fn rnd_request_index() -> String {
    let mut rng = rand::thread_rng();
    let number: u32 = rng.gen_range(100..=999);
    number.to_string()
}



use der_parser::{ber::BerObject, nom::AsBytes};
use der_parser::ber::BerObjectContent;
use der_parser::ber::BitStringObject;
use std::vec;
use openssl::bn::BigNum;
use openssl::bn::BigNumContext;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::ec::EcPoint;
use openssl::ecdsa::EcdsaSig;


async fn request_signing(tbs_base64:String,signing_parties:Vec<u16>,nodes_config: &NodesConfig) -> Result<Vec<NodeResponse<String>>> {
    println!("{}", "\n发起签名请求".bold());
    let nodes_config = nodes_config.clone();

    // create a new dkg request to nodes
    // let request = DKGRequest {
    //     threshold: nodes_config.threshold,
    //     number_of_parties: nodes_config.number_of_parties,
    //     request_index: rnd_request_index(),
    //     identity: nodes_config.identity,
    // };
    let request=SigningRequest{
        tobesigned: tbs_base64,
        parties: signing_parties.clone(),
        input_data_type: ecosigner_cli::mpe::gg20_signing::DataType::Base64,
        request_index: rnd_request_index(),
        identity: nodes_config.identity,
    };
    let request = serde_json::to_string(&request).context("Fail to read config to request DKG")?;
    println!("   >> 签名请求数据包为: {}", request);
    
    
    let signing_nodes:Vec<Node>=nodes_config.nodes
    .iter()
    .enumerate()
    .filter(|(i, _)| signing_parties.clone().contains(&(*i as u16 +1)))
    .map(|(_, item)| item.clone())
    .collect();


    let mut tasks = vec![];
    for node in signing_nodes.clone() {
        let request_clone = request.clone();
        let task: tokio::task::JoinHandle<
            Result<String, Box<dyn std::error::Error + Send + Sync>>,
        > = tokio::spawn(async move {
            let node_clone = node.clone();
            // 连接到目标主机的 TCP 服务器
            let addr = format!("{}:{}", node_clone.ip.host_str().unwrap(), node_clone.signing_port )
                .to_socket_addrs()?
                .next()
                .unwrap();
            let mut stream = TcpStream::connect(addr).await?;

            let message = request_clone.clone();
            stream.write_all(message.as_bytes()).await?;

            let mut buffer = [0u8; 1024];
            let bytes_read = stream.read(&mut buffer).await?;
            let response = String::from_utf8_lossy(&buffer[..bytes_read]);

            println!( "   >> 收到节点 {} 的响应: {}", node_clone.index, response );
            Ok(response.to_string())
        });
        std::thread::sleep(std::time::Duration::from_secs(1));
        tasks.push(task);
    }
    // 等待所有task完成
    let task_results = join_all(tasks).await;

    //处理task的结果，取出各个节点的返回值，存入responses中并返回
    let mut responses =
        Vec::<NodeResponse<String>>::with_capacity(signing_nodes.clone().capacity());
    for (i, result) in task_results.iter().enumerate() {
        match result {
            Ok(Ok(r_ok_ok)) => {
                let parsed_response: common_structs::NodeResponse<String> =
                    serde_json::from_str(&r_ok_ok).context("Failed to parse the response")?;
                responses.push(parsed_response.to_owned());
            }
            Ok(Err(r_ok_err)) => {
                return Err(anyhow!("Net errror occured on node {}: {}", i, r_ok_err.to_string()))
            }
            Err(err) => {
                return Err(anyhow!("Net errror occured on node {}: {}",i,err.to_string()))
            }
        }
    }

    Ok(responses)
}