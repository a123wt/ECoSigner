
// use std::fmt::format;

use std::fmt::Debug;

use anyhow::Context;
use anyhow::anyhow;
use colored::Colorize;
use curv::elliptic::curves::Point;
use curv::elliptic::curves::Secp256k1;
use der_parser::nom::Err;
use ecosigner_cli::mpe::gg20_keygen;
use ecosigner_cli::mpe::gg20_signing;
use ecosigner_cli::common_structs::{DKGRequest,SigningRequest,NodeResponse};
use rocket::response;
// use openssl::conf;
// use rocket::http::hyper::request;
use serde::{Deserialize, Serialize};
use serde_json;
use structopt::StructOpt;
use surf;
use tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use anyhow::Result;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::SignatureRecid;
type ECCURVE=curv::elliptic::curves::secp256_k1::Secp256k1;

#[derive(Debug, StructOpt, Clone)]
#[structopt(name="Share Node")]
struct Cli {
    #[structopt(short, long)]
    index: u16,
    #[structopt(short, long, default_value = "12370")]
    dkg_listen_port: i32,
    #[structopt(short, long, default_value = "12380")]
    signing_listen_port: i32,
    #[structopt(short="c", long, default_value = "http://localhost:8000/")]
    inter_node_comm: surf::Url,
}

#[tokio::main]
async fn main() {
    // Get args
    let config = Cli::from_args();
    print_node_info(config.clone());

    // Start listening for DKG messages
    let config_clone=config.clone();
    let dkg_task = tokio::spawn(async move {
        listen_DKG(&config_clone).await;
    });

    // Start listening for signing messages
    let signing_task = tokio::spawn(async move {
        listen_signing(&config).await;
    });

    // Await both tasks
    tokio::try_join!(dkg_task, signing_task).unwrap();
}

fn print_node_info(args: Cli) {
    let path = format!("./local-shares-{}", args.index.clone().to_string());

    println!("{}", "\nNode info:".bold());
    println!("   >> Node index: {}", args.index);
    println!("   >> Local shares path: {}", path);
    println!(
        "   >> inter-node communication: {}",
        args.inter_node_comm
    );
}


#[allow(non_snake_case)]
async fn listen_DKG(config:&Cli) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.clone().dkg_listen_port))
        .await
        .unwrap();
    println!("   >> DKG listening port: {}", config.clone().dkg_listen_port);

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let config = config.clone();

        // Spawn a new task to handle each incoming connection
        tokio::spawn(async move {
            println!("{}", "\nNew DKG connection:".bold());

            // Read the request from the socket
            let mut buffer = [0u8; 1024];
            let bytes_read = socket.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..bytes_read]);

            println!("   >> Received request: {}", request);

            // Parse the request as JSON
            let parsed_request: Result<DKGRequest, serde_json::Error> =
                serde_json::from_str(&request);

            // Handle the dkg request
            if let Err(error) = parsed_request {
                // If parse json wrong, response error and return
                eprintln!("Failed to parse DKG request: {}", error);
                let response = format!("Error: Wrong request");
                socket
                    .write_all(response.as_bytes())
                    .await
                    .map_err(|e| eprintln!("Error: {}", e))
                    .unwrap();
                return;
            }
            let parsed_request = parsed_request.unwrap();
            println!("   >> Parsing request successfully");

            // Validate identity (not implemented in this example)
            // todo
            if !authenticate(parsed_request.identity.clone()) {
                println!("{}{}", "   >> Authentication result: ", "false".red());
                return;
            }
            println!("{}{}", "   >> Authentication result: ", "True".green());

            // Call gg20_dkg
            let result = invoke_gg20_dkg(config, parsed_request.clone()).await;

            // Prepare the response
            let response=prepare_response(parsed_request.request_index.clone(), result).await;


            // Write the response to the socket
            socket
                .write_all(response.unwrap().as_bytes())
                .await
                .map_err(|e| eprintln!("Error: {}", e))
                .unwrap();
        });
    }
}

async fn listen_signing( config: &Cli) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.clone().signing_listen_port))
        .await
        .unwrap();
    println!("   >> Signing listening port: {}", config.clone().signing_listen_port);

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let config = config.clone();

        // Spawn a new task to handle each incoming connection
        tokio::spawn(async move {
            println!("{}", "\nNew signing connection:".bold());

            // Read the request from the socket
            let mut buffer = [0u8; 1024];
            let bytes_read = socket.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..bytes_read]);

            println!("   >> Received request: {}", request);

            // Parse the request as JSON
            let parsed_request: Result<SigningRequest, serde_json::Error> =
                serde_json::from_str(&request);

            // Handle the signing request
            if let Err(error) = parsed_request {
                // If parse json wrong, response error and return
                eprintln!("Failed to parse signing request: {}", error);
                let response = format!("Error: Wrong request");
                socket
                    .write_all(response.as_bytes())
                    .await
                    .map_err(|e| eprintln!("Error: {}", e))
                    .unwrap();
                return;
            }
            let parsed_request = parsed_request.unwrap();
            println!("   >> Parsing request successfully");

            // Validate identity (not implemented in this example)
            // todo
            if !authenticate(parsed_request.identity.clone()) {
                println!("{}{}", "   >> Authentication result: ", "false".red());
                return;
            }
            println!("{}{}", "   >> Authentication result: ", "True".green());

            // Call my_gg20_signing_base64 to sign the message
            let result = invoke_gg20_signing(config.clone(), parsed_request.clone()).await;

            // Prepare the response
            let response=prepare_response(parsed_request.request_index.clone(), result).await;


            // Write the response to the socket
            socket
                .write_all(response.unwrap().as_bytes())
                .await
                .map_err(|e| eprintln!("Error: {}", e))
                .unwrap();
        });
    }
}


async fn invoke_gg20_dkg(
    config: Cli,
    request: DKGRequest,
) -> Result<Point<ECCURVE>> {
    // set dkg args from node config and request
    let config=config.clone();
    let request=request.clone();
    let path = format!("./local-shares-{}/id_{}.json", config.index.to_string(),request.identity.to_string());

    let args_dkg=gg20_keygen::Cli { 
        address: config.inter_node_comm, 
        room: format!("dkg_room_{}", request.request_index), 
        output: std::path::PathBuf::from(path), 
        index: config.index, 
        threshold: request.threshold, 
        number_of_parties: request.number_of_parties, 
    };

    println!(
        "{}{}",
        "   >> Threshold is : ",
        args_dkg.threshold.clone()
    );
    println!(
        "{}{:?}",
        "   >> Number of parties is: ",
        args_dkg.number_of_parties.clone()
    );
    println!(
        "{}{}",
        "   >> Index of signing request is: ",
        args_dkg.room.clone()
    );

    let result = gg20_keygen::gg20_keygen(args_dkg).await;
    result
}


async fn invoke_gg20_signing(
    config: Cli,
    request: SigningRequest,
) -> Result<String> {
    // set signing args from node config and request
    let config=config.clone();
    let request=request.clone();
    let path = format!("./local-shares-{}/id_{}.json", config.index.to_string(),request.identity.to_string());

    let args_signing=gg20_signing::Cli { 
        address: config.inter_node_comm, 
        room: format!("signing_room_{}", request.request_index.clone()), 
        local_share: std::path::PathBuf::from(path), 
        parties: request.parties, 
        data_to_sign: request.tobesigned, 
        input_data_type: request.input_data_type, 
        output_data_type: gg20_signing::DataType::Base64, 
    };

    println!(
        "{}{}",
        "   >> To be signed data is: ",
        args_signing.data_to_sign.clone()
    );
    println!(
        "{}{:?}",
        "   >> Index of signing nodes is: ",
        args_signing.parties.clone()
    );
    println!(
        "{}{}",
        "   >> Index of signing request is: ",
        args_signing.room.clone()
    );
    println!(
        "{}{:?}",
        "   >> Type of input data is: ",
        args_signing.input_data_type.clone()
    );
    let result = gg20_signing::gg20_signing(args_signing).await;
    result
}

fn authenticate(authinfo: String) -> bool {
    // todo
    if !authinfo.is_empty() {
        return true;
    }
    false
}

async fn prepare_response<T:Serialize>(request_index:String,result :Result<T>)->Result<String>{
    match result {
        Ok(data) => {
            println!("   >> Success: {}", serde_json::to_string(&data)?);
            let response=NodeResponse{
                request_index: request_index,
                status: "New".to_string(),
                data:data,
            };
            return serde_json::to_string(&response).context("Failed to generate json response");
        },
        Err(error) => {
            eprintln!("Error: {}", error);
            let response=NodeResponse{
                request_index: request_index,
                status: "Error".to_string(),
                data:error.to_string(),
            };
            return serde_json::to_string(&response).context("Failed to generate json response");
        }
    };
    // let response=serde_json::to_string(&response).map_err(|_| println!("Failed to generate json response")).unwrap();
    // println!("{}",response);
    // response
}