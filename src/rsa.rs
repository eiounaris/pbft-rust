use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding},
    Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey
};
use rand::rngs::OsRng;
use std::{ fs::{ self, File }, io::{ Write, Read } };
use sha2::{Sha256, Digest};

// 主程序入口
fn main() {
    let bits = 2048;
    let line_ending = LineEnding::default();

    // 生成密钥对
    let (priv_key, pub_key) = generate_keys(bits);

    // 序列化密钥为 PEM 格式
    let priv_key_pem = serialize_private_key(&priv_key, line_ending);
    let pub_key_pem = serialize_public_key(&pub_key, line_ending);

    // 打印 PEM 格式的密钥
    println!("\nPrivate Key (PEM):\n{}", priv_key_pem);
    println!("\nPublic Key (PEM):\n{}", pub_key_pem);

    // 将 PEM 密钥保存到文件
    let dir = "rsa_keys"; // 目录名
    fs::create_dir_all(dir).expect("Failed to create directory");
    save_key_to_file(&priv_key_pem, &format!("{}/private_key.pem", dir));
    save_key_to_file(&pub_key_pem, &format!("{}/public_key.pem", dir));

    // 从文件读取 PEM 密钥
    let loaded_priv_key = load_private_key_from_file(&format!("{}/private_key.pem", dir));
    let loaded_pub_key = load_public_key_from_file(&format!("{}/public_key.pem", dir));

    // 测试加密解密
    let data = b"hello world";
    let enc_data = encrypt_data(&loaded_pub_key, data);
    let dec_data = decrypt_data(&loaded_priv_key, &enc_data);

    assert_eq!(data, &dec_data[..]);
    println!("\nEncryption and Decryption successful!\n");

     // 测试签名和验证
     let signature = sign_data(&loaded_priv_key, data);
     assert!(verify_signature(&loaded_pub_key, data, &signature));
     println!("\nSignature and Verification successful!\n");
}






// 生成 RSA 密钥对
fn generate_keys(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng(); // let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
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

// 从文件加载私钥
fn load_private_key_from_file(file_path: &str) -> RsaPrivateKey {
    let mut file = File::open(file_path).expect("Failed to open private key file");
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read private key file");
    RsaPrivateKey::from_pkcs1_pem(&pem).expect("Failed to decode private key")
}

// 从文件加载公钥
fn load_public_key_from_file(file_path: &str) -> RsaPublicKey {
    let mut file = File::open(file_path).expect("Failed to open public key file");
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read public key file");
    RsaPublicKey::from_pkcs1_pem(&pem).expect("Failed to decode public key")
}

// 使用公钥加密数据
fn encrypt_data(pub_key: &RsaPublicKey, data: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt")
}

// 使用私钥解密数据
fn decrypt_data(priv_key: &RsaPrivateKey, enc_data: &[u8]) -> Vec<u8> {
    priv_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt")
}

// 使用私钥签名数据
fn sign_data(priv_key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(data);  // 对原始数据进行 SHA-256 哈希
    // 使用私钥和哈希数据签名
    priv_key.sign(Pkcs1v15Sign::new::<Sha256>(), &hashed_data).expect("failed to sign data")
}

// 使用公钥验证签名
fn verify_signature(pub_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(data);  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}