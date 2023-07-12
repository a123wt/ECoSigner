use mytauri;
use tokio;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "8000")]
    port: i32
}

#[tokio::main]
async fn main()->Result<(), Box<dyn std::error::Error>>{
    let args=Cli::from_args();
    mytauri::use_mpe::gg20_sm_manager::gg20_sm_manager(args.port).await?;
    Ok(())
}