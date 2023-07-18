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
use gg20_sm_client::join_computation;


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
    let local_share = tokio::fs::read(args.local_share)
        .await
        .context("cannot read local share")?;
    let local_share = serde_json::from_slice(&local_share).context("parse local share")?;
    let number_of_parties = args.parties.len();

    let (i, incoming, outgoing) =
        join_computation(args.address.clone(), &format!("{}-offline", args.room))
            .await
            .context("join offline computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let signing = OfflineStage::new(i, args.parties, local_share)?;
    let completed_offline_stage = AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    let (i, incoming, outgoing) = join_computation(args.address, &format!("{}-online", args.room))
        .await
        .context("join online computation")?;

    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    //处理输入的数据，按照base64、utf8等方式解码 
    let data_to_sign=process_data_to_sign(&args_clone)?;

    let (signing, partial_signature) = SignManual::new(
        BigInt::from_bytes(&data_to_sign),
        completed_offline_stage,
    )?;

    outgoing
        .send(Msg {
            sender: i,
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

fn process_signed_data(signed_data : String, output_data_type : DataType) -> Result<String> {
    let signed_data :SignatureRecid= serde_json::from_str(&signed_data)?;
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
        _ =>{
            Err( anyhow!("wrong type of input data"))
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