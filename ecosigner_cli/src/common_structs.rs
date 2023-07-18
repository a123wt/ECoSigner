
use super::mpe::gg20_signing;
use curv::elliptic::curves::{Point, Secp256k1};
use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SigningRequest {
    pub tobesigned: String,
    pub parties: Vec<u16>,
    pub input_data_type: gg20_signing::DataType,
    pub request_index: String,
    pub identity: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DKGRequest {
    pub threshold: u16,
    pub number_of_parties: u16,
    pub request_index: String,
    pub identity: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeResponse<T:Serialize>{
    pub request_index:String,
    pub is_success:String,
    pub data:T,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodesConfig {
    pub threshold: u16,
    pub number_of_parties: u16,
    pub identity:String,
    pub nodes: Vec<Node>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Node {
    pub index: u16,
    pub ip: surf::Url,
    pub dkg_port: i32,
    pub signing_port: i32,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct X509Config {
    pub comman_name:String,
    pub organization_name:String,
    pub public_key:Point<Secp256k1>
}