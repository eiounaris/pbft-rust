use reqwest::Client;
use std::error::Error;
use std::io;
use std::io::Write;
use tokio::time::{sleep, Duration};
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    loop {
        println!("\n请选择要测试的请求类型：");
        println!("1. GET /last");
        println!("2. GET block/index");
        println!("3. POST block");
        println!("4. 退出！");
        print!("请输入选项（1-4）：");
        io::stdout().flush()?;

        let mut option = String::new();
        io::stdin().read_line(&mut option)?;
        let option: u32 = option.trim().parse().unwrap_or(4);

        if option == 4 {
            println!("程序已退出。");
            return Ok(());
        }
        let mut index: u64 = 0;
        if option == 2 {
            println!("请输入测试请求索引：(默认0）");
            let mut input: String = String::new();
            io::stdin().read_line(&mut input)?;
            index = input.trim().parse().unwrap_or(0);
        }

        println!("请输入测试次数：(默认1次）");
        let mut count = String::new();
        io::stdin().read_line(&mut count)?;
        let count: u32 = count.trim().parse().unwrap_or(1);

        println!("请输入请求间隔时间（毫秒）：(默认1000毫秒）");
        let mut interval_ms = String::new();
        io::stdin().read_line(&mut interval_ms)?;
        let interval_ms: u64 = interval_ms.trim().parse().unwrap_or(1000);

        let interval = Duration::from_millis(interval_ms);

        for i in 0..count {
            match option {
                1 => send_last(&client).await?,
                2 => send_block_index(&client, index).await?,
                3 => send_operation(&client).await?,
                _ => {
                    println!("无效的选项，请重新选择。");
                    break;
                }
            }

            sleep(interval).await;
            println!("第 {} 次请求完成", i + 1);
        }
    }
}

async fn send_last(client: &Client) -> Result<(), Box<dyn Error>> {
    println!("\n发送 GET 请求到 /last...");

    let response = client.get("http://localhost:8080/last").send().await?;
    let status = response.status();

    if status.is_success() {
        let body = response.text().await?;
        println!("请求成功，响应状态码：{}", status);
        println!("响应内容：{}", body);
    } else {
        println!("请求失败，状态码：{}", status);
    }

    Ok(())
}

async fn send_block_index(client: &Client, index : u64) -> Result<(), Box<dyn Error>> {
    println!("\n发送 GET 请求到 block/index...");

    let response = client.get(format!("http://localhost:8080/block/{}", index)).send().await?;
    let status = response.status();

    if status.is_success() {
        let body = response.text().await?;
        println!("请求成功，响应状态码：{}", status);
        println!("响应内容：{}", body);
    } else {
        println!("请求失败，状态码：{}", status);
    }

    Ok(())
}

async fn send_operation(client: &Client) -> Result<(), Box<dyn Error>> {
    println!("\n发送 POST 请求到 block...");

    let response = client
        .post("http://localhost:8080/block")
        .header("Content-Type", "application/json")
        .body(r#""Operation1""#)
        .send()
        .await?;
    let status = response.status();

    if status.is_success() {
        let body = response.text().await?;
        println!("请求成功，响应状态码：{}", status);
        println!("响应内容：{}", body);
    } else {
        println!("请求失败，状态码：{}", status);
    }

    Ok(())
}