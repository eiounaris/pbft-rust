use reqwest::blocking::Client;
use std::error::Error;
use std::io;
use std::time::Duration;
use std::io::Write;

fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    loop {
        println!("\n请选择要测试的请求类型：");
        println!("1. GET /last");
        println!("2. GET block/index");
        println!("3. POST block (Operation1)");
        println!("4. 退出");
        print!("请输入选项（1-4）：");
        io::stdout().flush().unwrap();

        let mut option = String::new();
        io::stdin().read_line(&mut option)?;
        let option: u32 = option.trim().parse().unwrap_or(0);

        if option == 4 {
            println!("程序已退出。");
            return Ok(());
        }

        println!("请输入测试次数：");
        let mut count = String::new();
        io::stdin().read_line(&mut count)?;
        let count: u32 = count.trim().parse().unwrap_or(0);

        println!("请输入请求间隔时间（毫秒）：");
        let mut interval_ms = String::new();
        io::stdin().read_line(&mut interval_ms)?;
        let interval_ms: u64 = interval_ms.trim().parse().unwrap_or(0);

        let interval = Duration::from_millis(interval_ms);

        for i in 0..count {
            match option {
                1 => send_last(&client)?,
                2 => send_block_index(&client)?,
                3 => send_operation(&client)?,
                _ => {
                    println!("无效的选项，请重新选择。");
                    break;
                }
            }


            std::thread::sleep(interval);

            println!("第 {} 次请求完成", i + 1);
        }
    }
}

fn send_last(client: &Client) -> Result<(), Box<dyn Error>> {
    println!("\n发送 GET 请求到 /last...");

    let response = client.get("http://localhost:8080/last").send()?;
    let status = response.status();

    if status.is_success() {
        let body = response.text()?;
        println!("请求成功，响应状态码：{}", status);
        println!("响应内容：{}", body);
    } else {
        println!("请求失败，状态码：{}", status);
    }

    Ok(())
}

fn send_block_index(client: &Client) -> Result<(), Box<dyn Error>> {
    println!("\n发送 GET 请求到 block/index...");

    let response = client.get("http://localhost:8080/block/1").send()?;
    let status = response.status();

    if status.is_success() {
        let body = response.text()?;
        println!("请求成功，响应状态码：{}", status);
        println!("响应内容：{}", body);
    } else {
        println!("请求失败，状态码：{}", status);
    }

    Ok(())
}

fn send_operation(client: &Client) -> Result<(), Box<dyn Error>> {
    println!("\n发送 POST 请求到 block...");

    let response = client
        .post("http://localhost:8080/block")
        .header("Content-Type", "application/json")
        .body(r#""Operation1""#)
        .send()?;
    let status = response.status();

    if status.is_success() {
        let body = response.text()?;
        println!("请求成功，响应状态码：{}", status);
        println!("响应内容：{}", body);
    } else {
        println!("请求失败，状态码：{}", status);
    }

    Ok(())
}