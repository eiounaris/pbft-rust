use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

use serde::{Deserialize, Serialize};

use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use hex; // 导入 hex 模块

// 定义节点配置结构
#[derive(Serialize, Deserialize, Debug)]
struct NodeConfig {
    node_id: u32,
    ip: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>, // 在新配置文件中添加公钥
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 读取配置文件
    let config_data = fs::read_to_string("config/nodes_config.json")?;
    let mut nodes: Vec<NodeConfig> = serde_json::from_str(&config_data)?;

    // 遍历每个节点，生成密钥并保存
    for node in &mut nodes {
        // 创建节点目录，例如 node_1, node_2, ...
        let dir_name = format!("config/node_{}", node.node_id);
        if !Path::new(&dir_name).exists() {
            fs::create_dir(&dir_name)?;
        }

        // 生成密钥对
        let mut rng = OsRng;
        let keypair: Keypair = Keypair::generate(&mut rng);

        // 将公钥和私钥转换为十六进制字符串
        let public_key_hex = hex::encode(keypair.public.to_bytes());
        let secret_key_hex = hex::encode(keypair.secret.to_bytes());

        // 保存私钥到文件
        let private_key_path = format!("{}/private_key.txt", dir_name);
        let mut priv_file = File::create(&private_key_path)?;
        priv_file.write_all(secret_key_hex.as_bytes())?;

        // 保存公钥到文件
        let public_key_path = format!("{}/public_key.txt", dir_name);
        let mut pub_file = File::create(&public_key_path)?;
        pub_file.write_all(public_key_hex.as_bytes())?;

        // 更新节点配置，添加公钥
        node.public_key = Some(public_key_hex);
    }

    // 生成包含公钥的新配置文件
    let new_config_data: String = serde_json::to_string_pretty(&nodes)?;
    fs::write("nodes_config_with_publickey.json", new_config_data)?;

    println!("密钥生成完成，配置文件已保存为 nodes_config_with_publickey.json");
    Ok(())
}