
use colored::Colorize;
use ecosigner_cli::mpe_lib::gg20_keygen;
use ecosigner_cli::mpe_lib::gg20_signing;
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
    authinfo: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DKGRequest {
    threshold: u16,
    number_of_parties: u16,
    request_index: String,
    authinfo: String,
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
    let args = Cli::from_args();
    print_node_info(args.clone());

    // pre config dkg and signing, some items will be changed by request
    let signing_config = pre_config_signing(args.clone());
    let dkg_config = pre_config_dkg(args.clone());

    // Start listening for DKG messages
    let dkg_task = tokio::spawn(async move {
        listen_DKG(args.dkg_listen_port, dkg_config).await;
    });

    // Start listening for signing messages
    let signing_task = tokio::spawn(async move {
        listen_signing(args.signing_listen_port, signing_config).await;
    });

    // Await both tasks
    tokio::try_join!(dkg_task, signing_task).unwrap();
}

fn print_node_info(args: Cli) {
    let path = format!("./local-share{}.json", args.index.clone().to_string());

    println!("{}", "\nNode info:".bold());
    println!("    >> Node index: {}", args.index);
    println!("    >> Local share path: {}", path);
    println!(
        "    >> Inter-node chat channel: {}",
        args.chat_channel_of_nodes
    );
}

fn pre_config_dkg(args: Cli) -> gg20_keygen::Cli {
    let path = format!("./local-share{}.json", args.index.clone().to_string());
    gg20_keygen::Cli {
        address: args.chat_channel_of_nodes,
        room: "default-signing".to_string(), // change as dkg request
        output: std::path::PathBuf::from(path),
        index: args.index,
        threshold: 1,         // change as dkg request
        number_of_parties: 3, // change as dkg request
    }
}

fn pre_config_signing(args: Cli) -> gg20_signing::Cli {
    let path = format!("./local-share{}.json", args.index.clone().to_string());
    gg20_signing::Cli {
        address: args.chat_channel_of_nodes,
        room: "default-signing".to_string(), // change as signing request
        local_share: std::path::PathBuf::from(path),
        parties: vec![0 as u16],                  // change as signing request
        data_to_sign: "To Be Signed".to_string(), // change as signing request
        input_data_type: gg20_signing::DataType::Base64, // change as signing request
        output_data_type:gg20_signing::DataType::Base64,
    }
}

#[allow(non_snake_case)]
async fn listen_DKG(port: i32, config: gg20_keygen::Cli) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    println!("    >> DKG listening port: {}", port);

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let config_clone = config.clone();

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
            if !authenticate(parsed_request.authinfo.clone()) {
                println!("{}{}", "    >> Authentication result: ", "false".red());
                return;
            }
            println!("{}{}", "    >> Authentication result: ", "True".green());

            // Call gg20_dkg
            let result = invoke_gg20_dkg(&config_clone, parsed_request).await;

            // Prepare the response
            let response = match result {
                Ok(_) => {
                    println!("    >> DKG result: {}", "Success");
                    format!("DKG result: {}", "Success")
                }
                Err(error) => {
                    eprintln!("Failed to dkg: {}", error);
                    format!("Error: {}", error)
                }
            };

            // Write the response to the socket
            socket
                .write_all(response.as_bytes())
                .await
                .map_err(|e| eprintln!("Error: {}", e))
                .unwrap();
        });
    }
}

async fn listen_signing(port: i32, config: gg20_signing::Cli) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    println!("    >> Signing listening port: {}", port);

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let config_clone = config.clone();

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
            if !authenticate(parsed_request.authinfo.clone()) {
                println!("{}{}", "    >> Authentication result: ", "false".red());
                return;
            }
            println!("{}{}", "    >> Authentication result: ", "True".green());

            // Call my_gg20_signing_base64 to sign the message
            let result = invoke_my_gg20_signing(&config_clone, parsed_request).await;

            // Prepare the response
            let response = match result {
                Ok(signature) => {
                    println!("    >> Signature: {}", signature);
                    format!("Signature: {}", signature)
                }
                Err(error) => {
                    eprintln!("Failed to generate signature: {}", error);
                    format!("Error: {}", error)
                }
            };

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
    config: &gg20_keygen::Cli,
    request: DKGRequest,
) -> Result<String> {
    let mut args = config.clone();
    args.threshold=request.threshold.clone();
    args.number_of_parties=request.number_of_parties.clone();
    args.room=format!("dkg_room_{}", request.request_index.clone());

    println!(
        "{}{}",
        "    >> Threshold is : ",
        args.threshold.clone()
    );
    println!(
        "{}{:?}",
        "    >> Number of parties is: ",
        args.number_of_parties.clone()
    );
    println!(
        "{}{}",
        "    >> Index of signing request is: ",
        args.room.clone()
    );

    let result = gg20_keygen::gg20_keygen(args).await.map(|_| "".to_string());
    result
}


async fn invoke_my_gg20_signing(
    config: &gg20_signing::Cli,
    request: SigningRequest,
) -> Result<String> {
    let mut args = config.clone();
    args.data_to_sign = request.tobesigned.clone();
    args.parties = request.parties.clone();
    args.input_data_type = request.input_data_type.clone();
    args.room = format!("signing_room_{}", request.request_index.clone());

    println!(
        "{}{}",
        "    >> To be signed data is: ",
        args.data_to_sign.clone()
    );
    println!(
        "{}{:?}",
        "    >> Index of signing nodes is: ",
        args.parties.clone()
    );
    println!(
        "{}{}",
        "    >> Index of signing request is: ",
        args.room.clone()
    );
    println!(
        "{}{:?}",
        "    >> Type of input data is: ",
        args.input_data_type.clone()
    );
    let result = gg20_signing::gg20_signing(args).await;
    result
}

fn authenticate(authinfo: String) -> bool {
    // todo
    if !authinfo.is_empty() {
        return true;
    }
    false
}

// fn prepare_response(result :Result<String>)->NodeResponse{
//     let response = match result {
//         Ok(data) => {
//             println!("    >> Success: {}", data);
//             NodeResponse{
//                 request_index: todo!(),
//                 is_success: todo!(),
//                 data,
//             }
//         }
//         Err(error) => {
//             eprintln!("Failed to generate signature: {}", error);
//             format!("Error: {}", error)
//         }
//     };
// }