use anyhow::{anyhow, Context, Result};
use curv::elliptic::curves::{Secp256k1, Point};
use futures::StreamExt;
use std::path::PathBuf;
use structopt::StructOpt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use round_based::async_runtime::AsyncProtocol;

use super::gg20_sm_client;
use gg20_sm_client::join_computation;

#[derive(Debug, StructOpt,Clone)]
pub struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    pub address: surf::Url,
    #[structopt(short, long, default_value = "default-keygen")]
    pub room: String,
    #[structopt(short, long)]
    pub output: PathBuf,

    #[structopt(short, long)]
    pub index: u16,
    #[structopt(short, long)]
    pub threshold: u16,
    #[structopt(short, long)]
    pub number_of_parties: u16,
}


pub async fn gg20_keygen(args:Cli) -> Result<Point<Secp256k1>> {
    // let args: Cli = Cli::from_args();
    let mut output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(args.output)
        .await
        .context("cannot create output file")?;

    let (_i, incoming, outgoing) = join_computation(args.address, &args.room)
        .await
        .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(args.index, args.threshold, args.number_of_parties)?;
    let output = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    
    let publikey=&output.y_sum_s;

    let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
    tokio::io::copy(&mut output.as_slice(), &mut output_file)
        .await
        .context("save output to file")?;

    Ok(publikey.to_owned())
}
