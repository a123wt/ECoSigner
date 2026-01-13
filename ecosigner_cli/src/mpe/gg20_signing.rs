// use std::io::Write;
// use std::ops::Add;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use curv::elliptic::curves::Scalar;
use futures::{SinkExt, StreamExt, TryStreamExt};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::SignatureRecid;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::Secp256k1;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{
    OfflineStage, SignManual,
};
use round_based::async_runtime::AsyncProtocol;
use round_based::Msg;

use super::gg20_sm_client;
use gg20_sm_client::join_computation_with_parties;


use openssl::base64;

#[derive(Debug, StructOpt, Clone, Serialize, Deserialize)]
pub enum DataType {
    #[structopt(name="utf8",about="decode input from Utf8")]
    Utf8,
    #[structopt(name="base64",about="decode input from Base64")]
    Base64,
    #[structopt(name="vector",about="not decode input and read it as vector")]
    Vector,
}

impl std::str::FromStr for DataType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self,String> {
        match s {
            "Utf8" => Ok(DataType::Utf8),
            "Base64" => Ok(DataType::Base64),
            "Vector" => Ok(DataType::Vector),
            _ => Err(format!("Invalid input data type: {}", s)),
        }
    }
}




#[derive(Debug, StructOpt,Clone, Serialize, Deserialize)]
pub struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    pub address: surf::Url,
    #[structopt(short, long, default_value = "default-signing")]
    pub room: String,
    #[structopt(short, long)]
    pub local_share: PathBuf,

    #[structopt(long, default_value = "0")]
    pub index: u16,

    #[structopt(short, long, use_delimiter(true))]
    pub parties: Vec<u16>,
    #[structopt(short, long)]
    pub data_to_sign: String,

    #[structopt(short,long,possible_values =  &["Utf8", "Base64", "Vector"],default_value="Utf8")]
    pub input_data_type:DataType,

    #[structopt(short,long,possible_values =  &["Base64", "Vector"],default_value="Base64")]
    pub output_data_type:DataType,
}


async fn gg20_signing_original(args:Cli) -> Result<String> {
    let args_clone = args.clone();

    if args.index == 0 {
        return Err(anyhow!(
            "--index must be non-zero (use the node's fixed index, e.g. 1..n) to avoid self-message error"
        ));
    }
    // Stable id of this node (user-chosen). It can be any u16 > 0,
    // but must be contained in --parties.
    let party_id = args.index;

    let local_share = tokio::fs::read(args.local_share)
        .await
        .context("cannot read local share")?;
    let local_share = serde_json::from_slice(&local_share).context("parse local share")?;
    let number_of_parties = args.parties.len();

    // -------- Offline: always join with fixed index --------
    let (room_idx, incoming, outgoing) = join_computation_with_parties(
        args.address.clone(),
        &format!("{}-offline", args.room),
        party_id,
        args.parties.clone(),
    )
    .await
    .context("join offline computation (v2 idx mapping)")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    // IMPORTANT:
    // - `room_idx` is the contiguous (1..k) index used by the state machine/runtime
    // - `args.parties` keeps the original party ids (e.g. [1,3]) for crypto math
    //   and must be identical across all participants.
    let signing = OfflineStage::new(room_idx, args.parties.clone(), local_share)?;

    let completed_offline_stage = AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    // -------- Online: always join with the same fixed index --------
    let (room_idx_online, incoming, outgoing) = join_computation_with_parties(
        args.address,
        &format!("{}-online", args.room),
        party_id,
        args.parties.clone(),
    )
    .await
    .context("join online computation (v2 idx mapping)")?;

    if room_idx_online != room_idx {
        return Err(anyhow!(
            "online stage index mismatch: offline={}, online={}",
            room_idx, room_idx_online
        ));
    }

    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    // 处理输入的数据，按照 base64/utf8 等方式解码
    let data_to_sign = process_data_to_sign(&args_clone)?;

    let (signing, partial_signature) = SignManual::new(
        BigInt::from_bytes(&data_to_sign),
        completed_offline_stage,
    )?;

    // 注意 sender 必须用 my_index
    outgoing
        .send(Msg {
            sender: room_idx,
            receiver: None,
            body: partial_signature,
        })
        .await?;

    let partial_signatures: Vec<_> = incoming
        .take(number_of_parties - 1)
        .map_ok(|msg| msg.body)
        .try_collect()
        .await?;

    let signature = signing
        .complete(&partial_signatures)
        .context("online stage failed")?;

    let signature = serde_json::to_string(&signature).context("serialize signature")?;
    Ok(signature)
}

fn process_data_to_sign(args: &Cli)->Result<Vec<u8>>{
    match args.input_data_type {
        DataType::Utf8=>{
            Ok(args.data_to_sign.as_bytes().to_vec())
        },
        DataType::Base64=>{       
            Ok(base64::decode_block(&args.data_to_sign).map_err(|_| anyhow!("Failed decode input data as base64"))?)
        },
        DataType::Vector=>{
            Ok(serde_json::from_str::<Vec<u8>>(&args.data_to_sign).map_err(|_| anyhow!("Failed read input data as bytes"))?)
        },
    }
}

fn process_signed_data(signed_data_string : String, output_data_type : DataType) -> Result<String> {
    let signed_data :SignatureRecid= serde_json::from_str(&signed_data_string.clone())?;
    let vec_r = scalar_to_vec(signed_data.r);
    let vec_s = scalar_to_vec(signed_data.s);
    let sig_vec: Vec<u8> = vec_r.into_iter().chain(vec_s.into_iter()).collect();
    match output_data_type {

        DataType::Base64=>{       
            Ok(base64::encode_block(&sig_vec))
        },
        DataType::Vector=>{
            Ok(format!("{:?}",sig_vec))
        },
        DataType::Utf8 =>{
            Ok(serde_json::to_string(&signed_data_string)?)
        }
        
    }
}

fn scalar_to_vec(signed_data : Scalar<Secp256k1>) -> Vec<u8> {
    let sub_sig = serde_json::to_string(&signed_data).context("serialize signature").unwrap();
    let sub_serial = String::from(&sub_sig[31..&sub_sig.len()-2]);
    let vec_str: Vec<u8> = sub_serial.split(',').map(|s|String::from(s).parse().unwrap()).collect();
    return vec_str;
}

pub async fn gg20_signing(args:Cli) -> Result<String> {
    let sig = gg20_signing_original(args.clone()).await?;
    let sig_str = process_signed_data(sig, args.output_data_type)?;
    Ok(sig_str)
}