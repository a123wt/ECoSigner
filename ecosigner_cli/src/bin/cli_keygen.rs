use mytauri;
use tokio;

#[tokio::main]
async fn main()->Result<(),Box<dyn std::error::Error>> {
    mytauri::use_mpe::gg20_keygen::gg20_keygen().await?;
    Ok(())
}