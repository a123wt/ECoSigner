
// use std::fmt::format;

use colored::Colorize;
use ecosigner_cli::mpe::gg20_keygen;
use ecosigner_cli::mpe::gg20_signing;
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

#[derive(Debug, StructOpt, Clone)]
#[structopt(name="Share Node")]
struct Cli {
    #[structopt(short, long, default_value = "1")]
    index: u16,
    #[structopt(short, long, default_value = "12370")]
    dkg_listen_port: i32,
    #[structopt(short, long, default_value = "12380")]
    signing_listen_port: i32,
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    chat_channel_of_nodes: surf::Url,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SigningRequest {
    tobesigned: String,
    parties: Vec<u16>,
    input_data_type: gg20_signing::DataType,
    request_index: String,
    identity: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DKGRequest {
    threshold: u16,
    number_of_parties: u16,
    request_index: String,
    identity: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct NodeResponse{
    request_index:String,
    is_success:String,
    data:String,
}

#[tokio::main]
async fn main() {
    // Get args
    let config = Cli::from_args();
    print_node_info(config.clone());

    // // pre config dkg and signing, some items will be changed by request
    // let signing_config = pre_config_signing(config.clone());
    // let dkg_config = pre_config_dkg(config.clone());

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
    println!("    >> Node index: {}", args.index);
    println!("    >> Local shares path: {}", path);
    println!(
        "    >> Inter-node chat channel: {}",
        args.chat_channel_of_nodes
    );
}

// fn pre_config_dkg(args: Cli) -> gg20_keygen::Cli {
//     // let path = format!("./local-share{}.json", args.index.clone().to_string());
//     gg20_keygen::Cli {
//         address: args.chat_channel_of_nodes,
//         room: "default-signing".to_string(), // change as dkg request
//         output: std::path::PathBuf::from("./local-shares-unknown"), // change as dkg request
//         index: args.index,
//         threshold: 1,         // change as dkg request
//         number_of_parties: 3, // change as dkg request
//     }
// }

// fn pre_config_signing(args: Cli) -> gg20_signing::Cli {
//     // let path = format!("./local-share{}.json", args.index.clone().to_string());
//     gg20_signing::Cli {
//         address: args.chat_channel_of_nodes,
//         room: "default-signing".to_string(), // change as signing request
//         local_share: std::path::PathBuf::from("./local-shares-unknown"), // change as signing request
//         parties: vec![0 as u16],                  // change as signing request
//         data_to_sign: "To Be Signed".to_string(), // change as signing request
//         input_data_type: gg20_signing::DataType::Base64, // change as signing request
//         output_data_type:gg20_signing::DataType::Base64,
//     }
// }

#[allow(non_snake_case)]
async fn listen_DKG(config:&Cli) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.clone().dkg_listen_port))
        .await
        .unwrap();
    println!("    >> DKG listening port: {}", config.clone().dkg_listen_port);

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

            println!("    >> Received request: {}", request);

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
            println!("    >> Parsing request successfully");

            // Validate identity (not implemented in this example)
            // todo
            if !authenticate(parsed_request.identity.clone()) {
                println!("{}{}", "    >> Authentication result: ", "false".red());
                return;
            }
            println!("{}{}", "    >> Authentication result: ", "True".green());

            // Call gg20_dkg
            let result = invoke_gg20_dkg(config, parsed_request.clone()).await;

            // Prepare the response
            let response=prepare_response(parsed_request.request_index.clone(), result);
            // let response = match result {
            //     Ok(_) => {
            //         println!("    >> DKG result: {}", "Success");
            //         format!("DKG result: {}", "Success")
            //     }
            //     Err(error) => {
            //         eprintln!("Failed to dkg: {}", error);
            //         format!("Error: {}", error)
            //     }
            // };

            // Write the response to the socket
            socket
                .write_all(response.as_bytes())
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
    println!("    >> Signing listening port: {}", config.clone().signing_listen_port);

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

            println!("    >> Received request: {}", request);

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
            println!("    >> Parsing request successfully");

            // Validate identity (not implemented in this example)
            // todo
            if !authenticate(parsed_request.identity.clone()) {
                println!("{}{}", "    >> Authentication result: ", "false".red());
                return;
            }
            println!("{}{}", "    >> Authentication result: ", "True".green());

            // Call my_gg20_signing_base64 to sign the message
            let result = invoke_gg20_signing(config.clone(), parsed_request.clone()).await;

            // Prepare the response
            let response=prepare_response(parsed_request.request_index.clone(), result);
            // let response = match result {
            //     Ok(signature) => {
            //         println!("    >> Signature: {}", signature);
            //         format!("Signature: {}", signature)
            //     }
            //     Err(error) => {
            //         eprintln!("Failed to generate signature: {}", error);
            //         format!("Error: {}", error)
            //     }
            // };

            // Write the response to the socket
            socket
                .write_all(response.as_bytes())
                .await
                .map_err(|e| eprintln!("Error: {}", e))
                .unwrap();
        });
    }
}


async fn invoke_gg20_dkg(
    config: Cli,
    request: DKGRequest,
) -> Result<String> {
    let config=config.clone();
    let request=request.clone();
    let path = format!("./local-shares-{}/id_{}.json", config.index.to_string(),request.identity.to_string());

    let args_dkg=gg20_keygen::Cli { 
        address: config.chat_channel_of_nodes, 
        room: format!("dkg_room_{}", request.request_index), 
        output: std::path::PathBuf::from(path), 
        index: config.index, 
        threshold: request.threshold, 
        number_of_parties: request.number_of_parties, 
    };



    println!(
        "{}{}",
        "    >> Threshold is : ",
        args_dkg.threshold.clone()
    );
    println!(
        "{}{:?}",
        "    >> Number of parties is: ",
        args_dkg.number_of_parties.clone()
    );
    println!(
        "{}{}",
        "    >> Index of signing request is: ",
        args_dkg.room.clone()
    );

    let result = gg20_keygen::gg20_keygen(args_dkg).await.map(|_| "Key Share has been stored".to_string());
    result
}


async fn invoke_gg20_signing(

    config: Cli,
    request: SigningRequest,
) -> Result<String> {
    // let mut args = config.clone();
    // args.data_to_sign = request.tobesigned.clone();
    // args.parties = request.parties.clone();
    // args.input_data_type = request.input_data_type.clone();
    // args.room = format!("signing_room_{}", request.request_index.clone());
    let config=config.clone();
    let request=request.clone();
    let path = format!("./local-shares-{}/id_{}.json", config.index.to_string(),request.identity.to_string());

    let args_signing=gg20_signing::Cli { 
        address: config.chat_channel_of_nodes, 
        room: format!("signing_room_{}", request.request_index.clone()), 
        local_share: std::path::PathBuf::from(path), 
        parties: request.parties, 
        data_to_sign: request.tobesigned, 
        input_data_type: request.input_data_type, 
        output_data_type: gg20_signing::DataType::Base64, 
    };

    println!(
        "{}{}",
        "    >> To be signed data is: ",
        args_signing.data_to_sign.clone()
    );
    println!(
        "{}{:?}",
        "    >> Index of signing nodes is: ",
        args_signing.parties.clone()
    );
    println!(
        "{}{}",
        "    >> Index of signing request is: ",
        args_signing.room.clone()
    );
    println!(
        "{}{:?}",
        "    >> Type of input data is: ",
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

fn prepare_response(request_index:String,result :Result<String>)->String{
    let response = match result {
        Ok(data) => {
            println!("    >> Success: {}", data);
            NodeResponse{
                request_index: request_index,
                is_success: "Success".to_string(),
                data:data,
            }
        }
        Err(error) => {
            eprintln!("Failed to generate signature: {}", error);
            NodeResponse{
                request_index: request_index,
                is_success: "Error".to_string(),
                data:error.to_string(),
            }
        }
    };
    let response=serde_json::to_string(&response).map_err(|_| println!("Failed to generate json response")).unwrap();
    response
}