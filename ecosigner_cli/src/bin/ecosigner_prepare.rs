use anyhow::Result;
use serde::{Deserialize, Serialize};
use surf::Url;


#[derive(Debug, Serialize, Deserialize, Clone)]
struct NodesConfig{
    nodes:Vec<Node>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Node{
    index:u16,
    ip:surf::Url,
    dkg_port:i32,
    signing_port:i32,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct X509Config{

}

fn main(){

}


fn request_dkg(nodes:NodesConfig)->Result<()>{
    Ok(())
}

fn create_certificate(nodes:NodesConfig,x509config:X509Config)->Result<()>{
    Ok(())
}

fn pre_build_req(){}

fn sign_req(){}

fn build_req(){}

fn request_x509(){}