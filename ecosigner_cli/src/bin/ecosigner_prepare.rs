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
use rocket::http::hyper::request;
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
    let nodes_config = read_config_nodes("./config_nodes.json".to_string()).await?;

    let dkg_responses = request_dkg(&nodes_config).await?;
    let public_key=check_dkg_responses(dkg_responses)?;
    
    println!("   >> DKG公钥 {}",serde_json::to_string(&public_key)?);

    let _=sign_csr_manually(public_key,&nodes_config).await?;



    // let signing_respopnse
    //     =request_signing("YWFh".to_string(), vec![1 as u16,2], &nodes_config).await?;
    // println!("{:?}",signing_respopnse);
    // let sig=verify_signing(signing_respopnse)?;
    // println!("{}",sig);
    // let result=verify_signature("YWFh".to_string(), sig, public_key);
    // println!("sig verify{:?}",result);

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

async fn read_config_csr(path: String) -> Result<X509Config> {
    let x509config_file = tokio::fs::read(PathBuf::from(path))
        .await
        .context("Failed to read csr config file")?;
    let x509config = serde_json::from_slice::<X509Config>(x509config_file.as_slice())
        .context("Failed to parse csr config file")?;
    return Ok(x509config);
}

fn check_dkg_responses(responses:Vec<NodeResponse<Point<ECCURVE>>>)->Result<Point<ECCURVE>>{
    // todo
    let is_equal = responses.iter().all(|x| x.data == responses[0].data);

    if is_equal{
        println!("   >> 检查DKG响应: {}","Valid".green().bold());
        return Ok(responses[0].data.to_owned())
    }
    eprintln!("   >> 检查DKG响应: {}","Invalid".red().bold());
    return Err(anyhow!("Failed to pass responses check"))

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

async fn request_dkg(nodes_config: &NodesConfig) -> Result<Vec<NodeResponse<Point<ECCURVE>>>> {
    println!("{}", "\n发起DKG请求".bold());
    let nodes_config = nodes_config.clone();

    // create a new dkg request to nodes
    let request = DKGRequest {
        threshold: nodes_config.threshold,
        number_of_parties: nodes_config.number_of_parties,
        request_index: rnd_request_index(),
        identity: nodes_config.identity,
    };
    let request = serde_json::to_string(&request).context("Fail to read config to request DKG")?;
    println!("   >> DKG请求数据包为: {}", request);

    let mut tasks = vec![];
    for node in nodes_config.nodes {
        let request_clone = request.clone();
        let task: tokio::task::JoinHandle<
            Result<String, Box<dyn std::error::Error + Send + Sync>>,
        > = tokio::spawn(async move {
            let node_clone = node.clone();
            // 连接到目标主机的 TCP 服务器
            let addr = format!("{}:{}", node_clone.ip.host_str().unwrap(), node_clone.dkg_port )
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
        Vec::<NodeResponse<Point<ECCURVE>>>::with_capacity(nodes_config.number_of_parties as usize);
    for (i, result) in task_results.iter().enumerate() {
        match result {
            Ok(Ok(r_ok_ok)) => {
                let parsed_response: common_structs::NodeResponse<Point<ECCURVE>> =
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

async fn build_req(csrconfig: X509Config) -> Result<X509Req> {
    let public_key_point = csrconfig.public_key;
    let public_key_bytes = public_key_point.to_bytes(true).to_vec();
    let ecg = ec::EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let public_key_ec_point=openssl::ec::EcPoint::from_bytes(ecg.as_ref(), public_key_bytes.as_ref(), &mut ctx)?;
    let public_key_eckey =
        openssl::ec::EcKey::from_public_key(ecg.as_ref(), public_key_ec_point.as_ref()).context("Failed to get public key bytes")?;
    // let public_key_der=public_key_eckey.public_key_to_der()?;
    let public_key_pkey=PKey::from_ec_key(public_key_eckey)?;
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



async fn sign_csr_manually(public_key_point:Point<ECCURVE>,nodes_config: &NodesConfig)->Result<()> {
    // 加载私钥
    let tmp_private_key_pem =
        include_str!("./private.key");
    let tmp_private_key = PKey::private_key_from_pem(tmp_private_key_pem.as_bytes()).unwrap();
    // let private_eckey=EcKey::private_key_from_pem(tmp_private_key_pem.as_bytes()).unwrap();

    // 获取mp公钥
    let ecg = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    let mp_public_key_point = EcPoint::from_bytes(&ecg, &public_key_point.to_bytes(true).as_bytes(), &mut ctx).unwrap();
    let mp_public_key_eckey = EcKey::from_public_key(&ecg, &mp_public_key_point).unwrap();
    let mp_public_key_der = mp_public_key_eckey.public_key_to_der().unwrap();
    let mp_public_key = PKey::public_key_from_der(&mp_public_key_der).unwrap();

    // 创建证书请求生成器
    let mut req_builder = X509ReqBuilder::new().unwrap();

    // 设置主体信息
    let mut subject_name = X509NameBuilder::new().unwrap();
    subject_name.append_entry_by_nid(Nid::COMMONNAME, "Geedge BSL Group")?;
    // subject_name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Geedge BSL Group")?;
    let subject_name = subject_name.build();
    // req_builder.set_subject_name(&subject_name)?;

    // 设置证书请求生成器中的信息
    req_builder.set_version(2).unwrap();
    req_builder
        .set_subject_name(&subject_name)
        .unwrap();
    req_builder.set_pubkey(&mp_public_key).unwrap();

    // 签名
    let _ = req_builder.sign(&tmp_private_key, MessageDigest::sha256());

    // build
    let req = req_builder.build();

    // println!(
    //     "validte tmp req    {}",
    //     req.verify(&tmp_private_key).unwrap()
    // );

    // 转为der
    let req_der = req.to_der().unwrap();

    // 使用der_parser解析
    use der_parser::der::*;

    let (_i, req_parsed) = parse_der_sequence(&req_der).unwrap();
    let req_parsed_pretty = req_parsed.as_pretty(0, 4);

    // println!("req_parsed\n{:?}", req_parsed);
    // println!("req_parsed_pretty\n{:?}", req_parsed_pretty);

    // 待签名部分
    let tbs_req = req_parsed[0].to_vec().unwrap();
    // tbs_req.extend(req_parsed[1].to_vec().unwrap());
    let tbs_req_hash = openssl::hash::hash(MessageDigest::sha256(), &tbs_req).unwrap();

    // println!("{:?}", tbs_req_hash);

    let tbs_req_hash_base64=openssl::base64::encode_block(&tbs_req_hash);
    let signging_response=request_signing(tbs_req_hash_base64, vec![1,2], nodes_config).await?;
    let sig_string_base64=check_responses_signing(signging_response)?;
    let sig_bytes=base64::decode_block(&sig_string_base64).map_err(|_| anyhow!("Failed decode signature as base64"))?;
    let sig_secp256k1=Signature::from_compact(&sig_bytes)?;
    let sig_der=sig_secp256k1.serialize_der();
    let sig_ecdsa=EcdsaSig::from_der(&sig_der)?;
    let sig = sig_ecdsa.to_der().unwrap();

    // println!(
    //     "   >> verify mp sig    {}",
    //     sig_ecdsa
    //         .verify(tbs_req_hash.as_bytes(), &mp_public_key_eckey)
    //         .unwrap()
    // );

    // req_parsed[2].content.as_bitstring().unwrap().data=&sig.to_vec();
    // println!("\n\nnew\n{:?}",req_parsed);

    let req_sig_header = der_parser::der::Header::new(
        Class::Universal,
        false,
        Tag(3),
        der_parser::ber::Length::Definite(sig.len()),
    );
    let req_sig_bit_string_object = BitStringObject { data: &sig };
    let req_sig_content = BerObjectContent::BitString(0, req_sig_bit_string_object);
    let req_tmp_sig = BerObject::from_header_and_content(req_sig_header, req_sig_content);

    let req_tmp_data_and_sigalgo =
        BerObject::from_seq(vec![req_parsed[0].clone(), req_parsed[1].clone()]);

    // println!("\n\ndata and sig algo\n{:?}",req_tmp_data_and_sigalgo.as_pretty(0, 4));
    // println!("\n\nsig\n{:?}",req_tmp_sig.as_pretty(0, 4));

    let req_new_der = BerObject::from_seq(vec![
        req_tmp_data_and_sigalgo[0].clone(),
        req_tmp_data_and_sigalgo[1].clone(),
        req_tmp_sig,
    ])
    .to_vec()
    .unwrap();

    let (_, req_final) = parse_der_sequence(&req_new_der).unwrap();
    let req_final_der = req_final.to_vec().unwrap();
    let req_final_pretty = req_final.as_pretty(0, 4);

    // println!("\n\ncheck\n{:?}", req_final);
    // println!("\n\ncheck\n{:?}", req_final_pretty);
    // println!("\n\ncheck\n{:?}", req_final_der);

    let req_final_x509req = X509Req::from_der(&req_final_der).unwrap();
    let r = req_final_x509req.verify(&mp_public_key);
    // println!("\nresult{:?}", r);

    let req_final_pemfile=String::from_utf8(req_final_x509req.to_pem().unwrap()).unwrap();    
    println!("   >> 证书申请文件\n{}",req_final_pemfile);

    let mut file = std::fs::File::create("./csr.pem").expect("Failed to create file");
    file.write_all(req_final_pemfile.as_bytes()).expect("Failed to write to file");
    Ok(())
}



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