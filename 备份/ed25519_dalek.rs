use ed25519_dalek::{Keypair, Signature, Signer, Verifier, PublicKey, SecretKey};
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{Write, Read};
use hex;  // 引入 hex 库用于转换为十六进制字符串


fn main() {
    // 生成密钥对
    let keypair = _generate_keypair();

    // 将密钥对转换为十六进制字符串
    let (public_key_hex, secret_key_hex) = _serialize_keys_to_hex(&keypair);

    // 创建存储密钥的目录
    let dir_name = "ca_keys";
    fs::create_dir_all(dir_name).unwrap(); // 创建目录

    // 将密钥保存到文件
    if !_save_key_to_file(&public_key_hex, &format!("{}/public_key.txt", dir_name)) {
        println!("Failed to save public key to file.");
        return;
    }
    if !_save_key_to_file(&secret_key_hex, &format!("{}/private_key.txt", dir_name)) {
        println!("Failed to save private key to file.");
        return;
    }

    // 从文件中读取十六进制密钥
    let read_public_key_hex = _read_key_from_file(&format!("{}/public_key.txt", dir_name));
    let read_secret_key_hex = _read_key_from_file(&format!("{}/private_key.txt", dir_name));

    // 将读取的十六进制密钥转换为公钥和私钥
    let secret_key = _hex_to_secret_key(&read_secret_key_hex);
    let public_key = _hex_to_public_key(&read_public_key_hex);

    let keypair = Keypair {
        secret: secret_key,
        public: public_key,
    };

    // 消息
    let message = b"Test message";

    // 使用私钥对消息进行签名
    let signature = _sign_message(&keypair, message);

    // 使用公钥验证签名
    if !_verify_signature(&keypair.public, message, &signature) {
        println!("Signature verification failed.");
        return;
    }
    println!("Test passed successfully!");
}


// 生成一个新的密钥对
fn _generate_keypair() -> Keypair {
    let mut rng = OsRng;
    Keypair::generate(&mut rng)
}

// 使用私钥对消息进行签名
fn _sign_message(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign(message)
}

// 使用公钥验证签名
fn _verify_signature(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    public_key.verify(message, signature).is_ok()
}

// 将密钥对转换为十六进制字符串
fn _serialize_keys_to_hex(keypair: &Keypair) -> (String, String) {
    let public_key_hex = hex::encode(keypair.public.to_bytes());
    let secret_key_hex = hex::encode(keypair.secret.to_bytes());
    (public_key_hex, secret_key_hex)
}

// 将十六进制字符串转换为公钥
fn _hex_to_public_key(hex: &str) -> PublicKey {
    PublicKey::from_bytes(&hex::decode(hex).unwrap()).unwrap()
}

// 将十六进制字符串转换为私钥
fn _hex_to_secret_key(hex: &str) -> SecretKey {
    SecretKey::from_bytes(&hex::decode(hex).unwrap()).unwrap()
}

// 将十六进制的密钥保存到文件
fn _save_key_to_file(key_hex: &str, file_path: &str) -> bool {
    let mut file = match File::create(file_path) {
        Ok(file) => file,
        Err(_) => return false, // 文件创建失败
    };

    if file.write_all(key_hex.as_bytes()).is_err() {
        return false; // 写入失败
    }

    true // 成功保存
}

// 从文件中读取密钥并返回十六进制字符串
fn _read_key_from_file(file_path: &str) -> String {
    let mut file = File::open(file_path).unwrap();
    let mut key_hex = String::new();
    file.read_to_string(&mut key_hex).unwrap();
    key_hex
}