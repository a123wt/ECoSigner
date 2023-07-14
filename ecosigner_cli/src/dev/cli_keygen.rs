use structopt::StructOpt;
use tokio;
use ecosigner_cli::mpe_lib;

#[tokio::main]
async fn main()->Result<(),Box<dyn std::error::Error>> {
    let args=mpe_lib::gg20_keygen::Cli::from_args();
    mpe_lib::gg20_keygen::gg20_keygen(args).await?;
    Ok(())
}