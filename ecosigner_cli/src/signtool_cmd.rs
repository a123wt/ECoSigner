use std::process::Command;
use std::env;
use std::path::Path;
fn main() {
    match switch_to_path("D:\\Rust") {
        Ok(()) => println!("Switched to path successfully"),
        Err(err) => eprintln!("Failed to switch to path: {}", err),
    }
    create_digest(r#"D:\Rust\cert\codesigning.crt"#.to_string(), r#".\text.exe"#.to_string(), r#"SHA256"#.to_string());
    build(r#".\text.exe"#.to_string());
}
fn create_digest(cert_path : String, input_path : String, hash_type : String) {
    //let cmd_str = r#".\signtool.exe sign /fd SHA256 /f "C:\Users\a\Documents\cert\cert_multi_party\mp_certificate.crt"  /dg ./ /dxml .\hello.exe"#;

    let pre_str = r#".\signtool.exe sign"#.to_string();
    let fd_str = r#" /fd "#.to_string() + &hash_type;
    let cert_str = r#" /f "#.to_string() + &cert_path + &(r#"  /dg ./ /dxml "#.to_string());
    let dig_cmd = pre_str + &fd_str + &cert_str + &input_path;

    let output = Command::new("cmd")
        .args(&["/C", &dig_cmd])
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Command output: {}", stdout);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Command failed: {}", stderr);
    }

}
fn switch_to_path(path: &str) -> Result<(), String> {
    let target_path = Path::new(path);
    env::set_current_dir(target_path).map_err(|e| format!("Failed to switch to path: {}", e))?;
    Ok(())
}

fn build(input_path : String) {
    let cmd_str = r#".\signtool.exe sign /di ./ "#.to_string() + &input_path;
    let output = Command::new("cmd")
        .args(&["/C", &cmd_str])
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Command output: {}", stdout);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Command failed: {}", stderr);
    }
}