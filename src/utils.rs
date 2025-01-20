use crate::*;

// ---

/// 计算区块哈希
pub fn create_block_hash(index: u64, timestamp: u64, operations: &Vec<Operation>, previous_hash: &str) -> String {
    let serialized = serde_json::to_string(&(index, timestamp, &operations, &previous_hash)).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(serialized);
    let hash = format!("{:x}", hasher.finalize());
    hash
}

// ---

/// 加载时间戳
pub fn get_current_timestamp() -> u64 {
    let start = SystemTime::now();
    let since_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_epoch.as_secs()
}

// ---

// / 从文件加载私钥，错误处理待改进
pub fn load_private_key_from_file(file_path: &str) -> RsaPrivateKey {
    let mut file = File::open(file_path).unwrap();
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read private key file");
    RsaPrivateKey::from_pkcs1_pem(&pem).expect("Failed to decode private key")
}

/// 从文件加载公钥，错误处理待改进
pub fn load_public_key_from_file(file_path: &str) -> RsaPublicKey {
    let mut file = File::open(file_path).expect("Failed to open public key file");
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read public key file");
    RsaPublicKey::from_pkcs1_pem(&pem).expect("Failed to decode public key")
}

// ---

/// 使用私钥签名数据
fn sign_data(priv_key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(data);  // 对原始数据进行 SHA-256 哈希
    // 使用私钥和哈希数据签名
    priv_key.sign(Pkcs1v15Sign::new::<Sha256>(), &hashed_data).expect("failed to sign data")
}

/// 使用公钥验证签名
fn _verify_signature(pub_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(data);  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 使用私钥签名请求消息
pub fn sign_request(priv_key: &RsaPrivateKey, request: &mut Request) {
    request.signature = sign_data(priv_key, serde_json::to_string(&request).unwrap().as_bytes());
}

/// 使用公钥验证请求消息
pub fn verify_request(pub_key: &RsaPublicKey, request: & Request, signature: &[u8]) -> bool {
    let mut request = request.clone();
    request.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&request).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 使用私钥签名预准备消息
pub fn sign_pre_prepare(priv_key: &RsaPrivateKey, pre_prepare: &mut PrePrepare) {
    pre_prepare.signature = sign_data(priv_key, serde_json::to_string(&pre_prepare).unwrap().as_bytes());
}

/// 使用公钥验证预准备消息
pub fn verify_pre_prepare(pub_key: &RsaPublicKey, pre_prepare: & PrePrepare, signature: &[u8]) -> bool {
    let mut pre_prepare = pre_prepare.clone();
    pre_prepare.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&pre_prepare).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 使用私钥签名准备消息
pub fn sign_prepare(priv_key: &RsaPrivateKey, prepare: &mut Prepare) {
    prepare.signature=sign_data(priv_key, serde_json::to_string(&prepare).unwrap().as_bytes());
}

/// 使用公钥验证准备消息
pub fn verify_prepare(pub_key: &RsaPublicKey, prepare: & Prepare, signature: &[u8]) -> bool {
    let mut prepare = prepare.clone();
    prepare.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&prepare).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 使用私钥签名提交消息
pub fn sign_commit(priv_key: &RsaPrivateKey, commit: &mut Commit) {
    commit.signature=sign_data(priv_key, serde_json::to_string(&commit).unwrap().as_bytes());
}

/// 使用公钥验证提交消息
pub fn verify_commit(pub_key: &RsaPublicKey, commit: & Commit, signature: &[u8]) -> bool {
    let mut commit = commit.clone();
    commit.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&commit).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

// ---

// 发送UDP数据
pub async fn send_udp_data(udp_socket: &UdpSocket, node_addr: &SocketAddr, message_type: MessageType, content: &[u8]) {
    // 生成消息的字节数组，先是类型字节，然后是消息内容的字节
    let mut message = Vec::new();
    message.push(message_type as u8);  // 将类型作为第一个字节
    message.extend_from_slice(&content);  // 将内容附加到字节数组后面
    // 发送消息
    udp_socket.send_to(&message, node_addr).await.unwrap();
}

// ---

/// RsaPublicKey 序列化函数
pub fn serialize_public_key<S>(public_key: &RsaPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let pem = public_key.to_pkcs1_pem(LineEnding::default()).expect("Failed to convert public key to PEM");
    serializer.serialize_str(&pem)
}

/// RsaPublicKey 反序列化函数
pub fn deserialize_public_key<'de, D>(deserializer: D) -> Result<RsaPublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let pem: String = Deserialize::deserialize(deserializer)?;
    RsaPublicKey::from_pkcs1_pem(&pem).map_err(serde::de::Error::custom)
}