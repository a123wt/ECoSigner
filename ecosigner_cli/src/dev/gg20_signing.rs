use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use curv::arithmetic::Converter;
use curv::BigInt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{
    OfflineStage, SignManual,
};
use round_based::async_runtime::AsyncProtocol;
use round_based::Msg;

use super::gg20_sm_client;
use gg20_sm_client::join_computation;

use openssl::base64;


#[derive(Debug, StructOpt,Clone, Serialize, Deserialize)]
pub enum InputDataType {
    #[structopt(name="utf8",about="decode input from Utf8")]
    Utf8,
    #[structopt(name="base64",about="decode input from Base64")]
    Base64,
    #[structopt(name="vector",about="not decode input and read it as vector")]
    Vector,
}

impl std::str::FromStr for InputDataType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "utf8" => Ok(InputDataType::Utf8),
            "base64" => Ok(InputDataType::Base64),
            "Vector" => Ok(InputDataType::Vector),
            _ => Err(format!("Invalid input data type: {}", s)),
        }
    }
}




#[derive(Debug, StructOpt,Clone)]
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

    #[structopt(short,long,possible_values =  &["utf8", "base64", "vector"],default_value="Utf8")]
    pub input_data_type:InputDataType,

}


pub async fn gg20_signing(args:Cli) -> Result<String> {
    let args_clone=args.clone();
    
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

    // let tobesigned=process_data_to_sign(&&args_clone)?;

    let (signing, partial_signature) = SignManual::new(
        BigInt::from_bytes(args.data_to_sign.as_bytes()),
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
    println!("{}", signature);

    Ok(signature)
}

fn process_data_to_sign(args: &Cli)->Result<Vec<u8>>{
    match args.input_data_type {
        InputDataType::Utf8=>{
            return Ok(args.data_to_sign.as_bytes().to_vec())
        },
        InputDataType::Base64=>{
            return Ok(base64::decode_block(&args.data_to_sign)?)
        },
        InputDataType::Vector=>{
            Ok(serde_json::from_str::<Vec<u8>>(&args.data_to_sign)?)
        },
        _ =>{
            return Err(anyhow::Error::msg("wrong type of input data") )
        }
    }
}

// async fn process_localshare(args: &Cli)->Result<Vec<u8>,String>{
//     let local_share = tokio::fs::read(args.local_share)
//         .await
//         .context("cannot read local share")?;
//     let local_share = serde_json::from_slice(&local_share).context("parse local share")?;
//     return local_share;
// }
