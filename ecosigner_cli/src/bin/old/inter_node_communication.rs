use ecosigner_cli::mpe;
use ecosigner_cli::mpe::gg20_sm_manager::Cli;
use tokio;
use structopt::StructOpt;



#[tokio::main]
async fn main()->Result<(), Box<dyn std::error::Error>>{
    let args=Cli::from_args();
    mpe::gg20_sm_manager::gg20_sm_manager(args).await?;
    Ok(())
}