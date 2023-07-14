use tokio::{process::Command};
use tokio::io::{AsyncBufReadExt, BufReader,BufWriter,AsyncWriteExt};
use std::io::Write;

// 测试使用子进程执行命令并重定向输入输出
async fn run_command() -> std::io::Result<tokio::process::Child> {
    let mut child=Command::new("/root/mytauri/src-tauri/target/debug/examples/cli_sm_manager")
        // .arg("Hello, World!")
        .stdout(std::process::Stdio::piped())
        .spawn()?;
        // .await?;

        //方式一：直接使用.stdout(std::process::Stdio::inherit())继承输出流

        // .stdout(std::process::Stdio::piped())
        let stdout = child.stdout.take().unwrap();
        let  mut reader = BufReader::new(stdout);
        

        // 方式二：使用tokio io为子进程输出
        let mut stdout = tokio::io::stdout();
        tokio::io::copy(&mut reader, &mut stdout).await?;

        // 方式三：逐行获取子进程输出流并输出到标准输出流stdio
        // let mut writer = std::io::stdout();
        // let mut lines = reader.lines();
        // while let Some(line) = lines.next_line().await.transpose() {
        //     writeln!(writer, "{}", line.unwrap())?;
        //     writer.flush()?;
        // }

        // 方式四：逐行获取子进程输出流并print
        // let mut lines=reader.lines();
        // while let line = lines.next_line().await {
        //     match line {
        //         Ok(line) => {
        //             println!("Output: {}", line.unwrap());
        //         },
        //         Err(err) => {
        //             eprintln!("Error reading line: {}", err);
        //             break;
        //         }
        //     }
        // }

    Ok(child)
}


// 测试子进程的处理
#[tokio::main]
async fn main() {
    // run_command().await;
    let mut child =match run_command().await {
        Ok(child) => {
            println!("Command completed successfully");
            child
        },
        Err(err) => {
            eprintln!("Error: {}", err);
        return;
        },
    };
    let _=tokio::signal::ctrl_c().await;
    //终止子进程
    if let Err(err) = child.kill().await {
        eprintln!("Error killing child process: {}", err);
    }
}








// 用sender传递异步消息的基本例子
use tokio::sync::mpsc;
use tokio::{task, time};
use tokio::time::Duration;

async fn async_print(sender: mpsc::Sender<String>) {
    // 监听端口并处理客户端连接
    // 在适当的位置，将输出发送给 sender
    // 例如，假设你有一条输出：println!("Output: {}", output);
    // 你可以将它发送给 sender：sender.send(output.to_string()).await.unwrap();
    let mut count = 0;

    loop {
        // 每隔 2 秒发送一个递增的数字到发送者
        sender.send(count.to_string()).await.unwrap();
        count += 1;

        // 休眠 2 秒
        time::sleep(Duration::from_secs(2)).await;
    }
}

// #[tokio::main]
// async fn main() {
//     let (sender, mut receiver) = mpsc::channel(100); // 创建异步通道，设置缓冲区大小

//     // 启动异步函数
//     let task = tokio::spawn(async move {
//         async_function(sender).await;
//     });

//     // 从异步通道中接收输出并进行处理
//     while let Some(output) = receiver.recv().await {
//         // 在这里可以对接收到的输出进行实时处理，例如打印到控制台或者其他操作
//         println!("Received Output: {}", output);
//     }

//     task.await.unwrap(); // 等待异步函数完成
// }
