use ecosigner_cli::mpe_lib;
use ecosigner_cli::mpe_lib::gg20_sm_manager::Cli;
use tokio;
use structopt::StructOpt;



#[tokio::main]
async fn main()->Result<(), Box<dyn std::error::Error>>{
    let args=Cli::from_args();
    mpe_lib::gg20_sm_manager::gg20_sm_manager(args).await?;
    Ok(())
}