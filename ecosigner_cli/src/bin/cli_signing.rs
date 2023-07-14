use ecosigner_cli::mpe_lib;
use ecosigner_cli::mpe_lib::gg20_signing::Cli;
use tokio;
use structopt::StructOpt;


#[tokio::main]
async fn main(){
    let args = Cli::from_args();
    let _=mpe_lib::gg20_signing::gg20_signing(args);
}