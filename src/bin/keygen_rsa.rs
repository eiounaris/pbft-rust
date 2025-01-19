use rsa::{ 
    pkcs1::{ EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding}, 
    RsaPrivateKey, RsaPublicKey 
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{ fs::{ self, File }, io::Write };
use std::path::Path;

// 定义节点配置结构
#[derive(Serialize, Deserialize, Debug)]
struct NodeConfig {
    node_id: u32,
    ip: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>, // 在新配置文件中添加公钥
}

fn main() {
    // 读取配置文件
    let config_data = fs::read_to_string("config/nodes_config.json").unwrap();
    let mut nodes: Vec<NodeConfig> = serde_json::from_str(&config_data).unwrap();

    // 遍历每个节点，生成密钥并保存
    for node in &mut nodes {
        // 创建节点目录，例如 node_1, node_2, ...
        let dir_name = format!("config/node_{}", node.node_id);
        if !Path::new(&dir_name).exists() {
            fs::create_dir_all(&dir_name).unwrap();
        }

        // 生成RSA密钥对
        let bits = 2048; // RSA密钥大小
        let line_ending = LineEnding::default();
        let (priv_key, pub_key) = generate_rsa_keys(bits);

        // 将私钥和公钥序列化为PEM格式
        let priv_key_pem = serialize_private_key(&priv_key, line_ending);
        let pub_key_pem = serialize_public_key(&pub_key, line_ending);

        // 将私钥保存到文件
        let private_key_path = format!("{}/private_key.pem", dir_name);
        save_key_to_file(&priv_key_pem, &private_key_path);

        // 将公钥保存到文件
        let public_key_path = format!("{}/public_key.pem", dir_name);
        save_key_to_file(&pub_key_pem, &public_key_path);

        // 更新节点配置，添加公钥
        node.public_key = Some(pub_key_pem); // 这里只存储PEM格式的公钥
    }

    // 生成包含公钥的新配置文件
    let new_config_data: String = serde_json::to_string_pretty(&nodes).unwrap();
    fs::write("config/nodes_config_with_publickey.json", &new_config_data).unwrap();

    println!("节点配置生成完毕，已保存在 config/nodes_config_with_publickey.json");
}

// 生成RSA密钥对
fn generate_rsa_keys(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate RSA private key");
    let pub_key = RsaPublicKey::from(&priv_key);
    (priv_key, pub_key)
}

// 将私钥序列化为 PEM 格式
fn serialize_private_key(priv_key: &RsaPrivateKey, line_ending: LineEnding) -> String {
    priv_key.to_pkcs1_pem(line_ending).expect("failed to encode private key").to_string()
}

// 将公钥序列化为 PEM 格式
fn serialize_public_key(pub_key: &RsaPublicKey, line_ending: LineEnding) -> String {
    pub_key.to_pkcs1_pem(line_ending).expect("failed to encode public key")
}

// 将 PEM 格式的密钥保存到文件
fn save_key_to_file(key_pem: &str, file_path: &str) {
    let mut file = File::create(file_path).expect("Failed to create file");
    file.write_all(key_pem.as_bytes()).expect("Failed to write PEM to file");
}
