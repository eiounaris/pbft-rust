#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding}, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use std::{ collections::HashSet, fs::{ File, OpenOptions }, io::{ Read, Write }, net::SocketAddr, sync::Arc, time::{SystemTime, UNIX_EPOCH} };

use sha2::{Sha256, Digest};

use tokio::{ net::UdpSocket, sync::Mutex, io::{AsyncBufReadExt, BufReader}};
// ---


// Custom serializer for RsaPublicKey, converts it to PEM format (Base64 encoded)
pub fn serialize_public_key<S>(public_key: &RsaPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // Convert public public_key to PEM format (Base64 encoded)
    let pem = public_key.to_pkcs1_pem(LineEnding::default()).expect("Failed to convert public key to PEM");
    serializer.serialize_str(&pem)
}

// Custom deserializer for RsaPublicKey, converts PEM string back into RsaPublicKey
pub fn deserialize_public_key<'de, D>(deserializer: D) -> Result<RsaPublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Deserialize PEM string from JSON
    let pem: String = Deserialize::deserialize(deserializer)?;
    RsaPublicKey::from_pkcs1_pem(&pem).map_err(serde::de::Error::custom)
}

// ---

// A custom struct to hold the PEM string for the public key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeConfigWithRsaPublickey {
    pub node_id: u64,
    pub ip: String,
    pub port: u16,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: RsaPublicKey,
}

// ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub timestamp: u64,
    pub transaction_info: String,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: RsaPublicKey,
    pub signature: Vec<u8>,
}

// ---

const BLOCK_SIZE: usize = 3;
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub block_info: String,
    pub hash: String,
}

// ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Blockchain {
    pub blockchain: Vec<Block>,
    pub transaction_pool: Vec<Transaction>,
}

impl Blockchain {
    pub fn new() -> Self {
        Blockchain {
            blockchain: vec![
                Block {
                    index:  0,
                    timestamp: get_current_time(),
                    transactions: Vec::new(),
                    previous_hash: String::new(),
                    block_info: "Genesis Block".to_string(),
                    hash: String::new(),
                }
            ],
            transaction_pool: Vec::new(),
        } 
    }

    pub fn last_block(&self) -> Option<&Block> {
        self.blockchain.last()
    }

    pub fn add_block(&mut self, block: Block) {
        if block.previous_hash == self.last_block().unwrap().hash {
            self.blockchain.push(block);
        }
        // 如果哈希链断了，发送区块请求
    }

    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transaction_pool.push(transaction);
    }

    pub fn create_block(&self, block_info: String, transactions: Vec<Transaction>) -> Block {
        let index: u64 = if let Some(last_block) = self.last_block() {
            last_block.index + 1
        } else {
            0
        };
        let timestamp: u64 = get_current_time();
        let previous_hash = if let Some(last_block) = self.last_block() {
            last_block.hash.clone()
        } else {
            String::new()
        };
        let hash = create_block_hash(index, timestamp, &transactions, &previous_hash, &block_info);

        let block = Block {
            index,
            timestamp,
            transactions,
            previous_hash,
            block_info,
            hash,
        };
        block
    }

    pub async fn store_to_file(&mut self, file_path: &str) {
        let mut num: u64 = 0;
        if let Some(block) = Blockchain::load_last_block_from_file(file_path).await {
            num = block.index + 1;
        }
        let mut file: File = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path).unwrap();

        for block in &self.blockchain {
            if block.index >= num {
                let block = serde_json::to_string(&block).unwrap();
                writeln!(file, "{}", block).unwrap();
            }
        }
        self.clear_blockchain();
    }

    // 清除内存中除最近的所有区块
    pub fn clear_blockchain(&mut self) {
        self.blockchain.drain(..self.blockchain.len() - 1);
    }

    // 异步读取文件的指定索引区块
    pub async fn load_block_by_index(file_path: &str, index: usize) -> Option<Block> {
        Blockchain::load_block_by_line(file_path, index + 1).await
    }
    pub async fn load_block_by_line(file_path: &str, line_number: usize) -> Option<Block> {
        // 尝试异步打开文件
        let file = match tokio::fs::File::open(file_path).await {
            Ok(f) => f,
            Err(_) => return None,
        };
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        // 行号从 1 开始
        let mut current_line = 1;
        // 异步遍历每一行
        while let Ok(Some(line)) = lines.next_line().await {
            if current_line == line_number {
                // 尝试将该行解析为 Block
                match serde_json::from_str::<Block>(&line) {
                    Ok(block) => return Some(block),
                    Err(e) => {
                        eprintln!("解析 JSON 失败: {}", e);
                        return None; // 解析失败，返回 None
                    }
                }
            }
            current_line += 1;
        }
        // 如果没有找到指定行，返回 None
        None
    }
    
    // 异步读取文件的最后一行并返回最后的区块
    pub async fn load_last_block_from_file(file_path: &str) -> Option<Block> {
        // 尝试异步打开文件
        let file = match tokio::fs::File::open(file_path).await {
            Ok(f) => f,
            Err(_) => return None, // 打开文件失败，返回 None
        };
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut last_line: Option<String> = None;
        // 异步遍历每一行
        while let Ok(Some(line)) = lines.next_line().await {
            last_line = Some(line);
        }
        if let Some(line) = last_line {
            let block = serde_json::from_str(&line).unwrap();
            Some(block)
        } else {
            None
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum MessageType {
    Request = 0,
    PrePrepare = 1,
    Prepare = 2,
    Commit = 3,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Request {
    pub transaction: Transaction,
    pub node_id: u64,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: RsaPublicKey,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrePrepare {
    pub view_number: u64,
    pub sequence_number: u64,
    pub block: Block,
    pub node_id: u64,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: RsaPublicKey,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Prepare {
    pub view_number: u64,
    pub sequence_number: u64,
    pub node_id: u64,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: RsaPublicKey,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Commit {
    pub view_number: u64,
    pub sequence_number: u64,
    pub node_id: u64,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: RsaPublicKey,
    pub signature: Vec<u8>,
}

// ---

#[derive(Debug, PartialEq)]
pub enum PbftStep {
    InIdle = 0,
    ReceivePrepare = 1,
    ReceiveCommit = 2,
    RequestBlock = 3,
}

// ---

pub struct PbftState {
    pub view_number: u64,
    pub sequence_number: u64,
    pub pbft_step: PbftStep,
    pub start_time: u64,
    pub end_time: u64,
    pub node_number: u64,
    pub prepares: HashSet<u64>,
    pub commits: HashSet<u64>,
    pub block: Block,
}

impl PbftState {
    pub fn new(
        view_number: u64,
        sequence_number: u64,
        node_number: u64
    ) -> Self {
        PbftState {
            view_number: view_number,
            sequence_number: sequence_number,
            pbft_step: PbftStep::InIdle,
            start_time: 0,
            end_time: 0,
            node_number: node_number,
            prepares: HashSet::new(),
            commits: HashSet::new(),
            block: Block {
                index: 0,
                timestamp: 0,
                transactions: Vec::new(),
                previous_hash: String::new(),
                block_info: String::new(),
                hash: String::new(),
            },
        }
    }
}

// ---

pub struct NodeInfo {
    pub node_id: u64,
    pub is_primarry: bool,
    pub local_addr: String,
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub nodes: Vec<NodeConfigWithRsaPublickey>,
}

impl NodeInfo {
    // 构造函数
    pub fn new(
        node_id: u64,
        is_primarry: bool,
        local_addr: String,
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey,
        nodes: Vec<NodeConfigWithRsaPublickey>,
    ) -> Self {
        NodeInfo {
            node_id,
            is_primarry,
            local_addr,
            private_key,
            public_key,
            nodes,
        }
    }
}


// ---

pub async fn send_udp_data(socket: &UdpSocket, addr: &SocketAddr, message_type: MessageType, content: &[u8]) {
    // 生成消息的字节数组，先是类型字节，然后是消息内容的字节
    let mut message = Vec::new();
    message.push(message_type as u8);  // 将类型作为第一个字节
    message.extend_from_slice(&content);  // 将内容附加到字节数组后面
    // 发送消息
    socket.send_to(&message, addr).await.unwrap();
}

pub async fn receive_udp_data(socket: &UdpSocket) -> (MessageType, Vec<u8>) {
    let mut buf = [0; 1024]; // 接收缓冲区
    let (size, _src) = socket.recv_from(&mut buf).await.unwrap();
    // 提取消息类型（第一个字节）
    let message_type = match buf[0] {
        0 => MessageType::Request,
        1 => MessageType::PrePrepare,
        2 => MessageType::Prepare,
        3 => MessageType::Commit,
        _ => panic!("Unknown message type"),
    };
    // 提取消息内容（剩余的字节）
    let content = buf[1..size].to_vec(); // 转换为 Vec<u8>
    (message_type, content)
}

pub async fn process_udp_data(message_type: MessageType, content: Vec<u8>) {
    match message_type {
        MessageType::Request => {
            println!("\nProcessing TypeA message: {:?}\n", content);
        }
        MessageType::PrePrepare => {
            println!("\nProcessing TypeB message: {:?}\n", content);
        }
        MessageType::Prepare => {
            println!("\nProcessing TypeC message: {:?}\n", content);
        }
        MessageType::Commit => {
            println!("\nProcessing TypeD message: {:?}\n", content);
        }
    }
}

// ---

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

// 使用私钥签名交易
pub fn sign_transaction(priv_key: &RsaPrivateKey, transaction: &mut Transaction) {
    transaction.signature=sign_data(priv_key, serde_json::to_string(&transaction).unwrap().as_bytes());
}

// 使用公钥验证交易
pub fn verify_transaction(pub_key: &RsaPublicKey, transaction: & Transaction, signature: &[u8]) -> bool {
    let mut transaction: Transaction = transaction.clone();
    transaction.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&transaction).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

// 使用私钥签名请求
pub fn sign_request(priv_key: &RsaPrivateKey, request: &mut Request) {
    request.signature=sign_data(priv_key, serde_json::to_string(&request).unwrap().as_bytes());
}

// 使用公钥验证请求
pub fn verify_request(pub_key: &RsaPublicKey, request: & Request, signature: &[u8]) -> bool {
    let mut request = request.clone();
    request.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&request).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

// 使用私钥签名请求
pub fn sign_pre_prepare(priv_key: &RsaPrivateKey, pre_prepare: &mut PrePrepare) {
    pre_prepare.signature = sign_data(priv_key, serde_json::to_string(&pre_prepare).unwrap().as_bytes());
}

// 使用公钥验证请求
pub fn verify_pre_prepare(pub_key: &RsaPublicKey, pre_prepare: & PrePrepare, signature: &[u8]) -> bool {
    let mut pre_prepare = pre_prepare.clone();
    pre_prepare.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&pre_prepare).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

// 使用私钥签名请求
pub fn sign_prepare(priv_key: &RsaPrivateKey, prepare: &mut Prepare) {
    prepare.signature=sign_data(priv_key, serde_json::to_string(&prepare).unwrap().as_bytes());
}

// 使用公钥验证请求
pub fn verify_prepare(pub_key: &RsaPublicKey, prepare: & Prepare, signature: &[u8]) -> bool {
    let mut prepare = prepare.clone();
    prepare.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&prepare).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

// 使用私钥签名请求
pub fn sign_commit(priv_key: &RsaPrivateKey, commit: &mut Commit) {
    commit.signature=sign_data(priv_key, serde_json::to_string(&commit).unwrap().as_bytes());
}

// 使用公钥验证请求
pub fn verify_commit(pub_key: &RsaPublicKey, commit: & Commit, signature: &[u8]) -> bool {
    let mut commit = commit.clone();
    commit.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&commit).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}


// ---


// 任务: 接收命令行指令数据
pub async fn send_message(node_info: &NodeInfo, target_nodes: &[SocketAddr], socket_send: Arc<UdpSocket>, _pbft_state: Arc<Mutex<PbftState>> ) {
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let mut transaction = Transaction {
            from: node_info.node_id.to_string(),
            to: node_info.node_id.to_string(),
            amount: 0,
            timestamp: get_current_time(),
            transaction_info: line,
            public_key: node_info.public_key.clone(),
            signature: Vec::new(),
        };
        sign_transaction(&node_info.private_key, &mut transaction);
        let mut request = Request {
            node_id: node_info.node_id,
            transaction: transaction.clone(),
            public_key: node_info.public_key.clone(),
            signature: Vec::new(),
        };
        sign_request(&node_info.private_key, &mut request);
        // 发送消息
        for target_addr in target_nodes {
            send_udp_data(
                &socket_send,
                target_addr,
                MessageType::Request,
                serde_json::to_string(&request).unwrap().as_bytes(),
            ).await;
        }
    }
}


// 任务: 接收数据
pub async fn receive_message(
    socket: Arc<UdpSocket>, 
    node_info: &NodeInfo, 
    blockchain: Arc<Mutex<Blockchain>>, 
    target_nodes: &[SocketAddr], 
    pbft_state: Arc<Mutex<PbftState>>  
) {
    let mut buf = [0u8; 10240];
    loop {
        let (size, _src) = socket.recv_from(&mut buf).await.unwrap();
        // 提取消息类型（第一个字节）
        let message_type = match buf[0] {
            0 => MessageType::Request,
            1 => MessageType::PrePrepare,
            2 => MessageType::Prepare,
            3 => MessageType::Commit,
            _ => panic!("Unknown message type"),
        };

        // 提取消息内容（剩余的字节）
        let content = buf[1..size].to_vec(); // 转换为 Vec<u8>
        process_message(socket.clone(), message_type, content, node_info, blockchain.clone(), &target_nodes, pbft_state.clone()).await;
    }
}

// 任务: 处理数据
pub async fn process_message(
    socket: Arc<UdpSocket>, 
    message_type: MessageType, 
    content: Vec<u8>, 
    node_info: &NodeInfo, 
    blockchain:Arc<Mutex<Blockchain>>, 
    target_nodes: &[SocketAddr], 
    pbft_state: Arc<Mutex<PbftState>> 
) {
    match message_type {
        MessageType::Request => {
            if node_info.is_primarry {
                println!("\nProcessing request message\n");
                let request: Request = serde_json::from_slice(&content).unwrap();
                if verify_request(&request.public_key, &request, &request.signature) {
                    if verify_transaction(&request.transaction.public_key, &request.transaction, &request.transaction.signature) {
                        let mut blockchain = blockchain.lock().await;
                        {
                            blockchain.add_transaction(request.transaction);
                        }
                        println!("\nblockchain.transaction_pool.len(): {:?}\n", blockchain.transaction_pool.len());
                        if blockchain.transaction_pool.len() >= BLOCK_SIZE {
                            let block: Block = blockchain.create_block("block_info".to_string(), blockchain.transaction_pool.clone());
                            let pbft_state = pbft_state.lock().await;
                            let mut pre_prepare = PrePrepare {
                                view_number: pbft_state.view_number,
                                sequence_number: pbft_state.sequence_number,
                                block: block,
                                node_id: node_info.node_id,
                                public_key: node_info.public_key.clone(),
                                signature: Vec::new(),
                            };
                            sign_pre_prepare(&node_info.private_key, &mut pre_prepare);
                            println!("\nSending preprepare\n");
                            for target_addr in target_nodes {
                                send_udp_data(
                                    &socket,
                                    target_addr,
                                    MessageType::PrePrepare,
                                    serde_json::to_string(&pre_prepare).unwrap().as_bytes(),
                                ).await;
                            }
                            send_udp_data(
                                &socket,
                                &node_info.local_addr.parse().unwrap(),
                                MessageType::PrePrepare,
                                serde_json::to_string(&pre_prepare).unwrap().as_bytes(),
                            ).await;
                        }
                    }
                }
            }
        }
        MessageType::PrePrepare => {
            let mut pbft_state = pbft_state.lock().await;
            if pbft_state.pbft_step == PbftStep::InIdle {
                let pre_prepare: PrePrepare = serde_json::from_slice(&content).unwrap();
                println!("\nProcessing pre_prepare message\n");
                if verify_pre_prepare(&pre_prepare.public_key, &pre_prepare, &pre_prepare.signature) {
                    pbft_state.pbft_step = PbftStep::ReceivePrepare;
                    pbft_state.prepares.clear();
                    pbft_state.commits.clear();
                    pbft_state.block = pre_prepare.block;

                    let mut prepare = Prepare {
                        view_number: pbft_state.view_number,
                        sequence_number: pbft_state.sequence_number,
                        node_id: node_info.node_id,
                        public_key: node_info.public_key.clone(),
                        signature: Vec::new(),
                    };

                    sign_prepare(&node_info.private_key, &mut prepare);

                    println!("\nSending prepare\n");
                    for target_addr in target_nodes {
                        send_udp_data(
                            &socket,
                            target_addr,
                            MessageType::Prepare,
                            serde_json::to_string(&prepare).unwrap().as_bytes(),
                        ).await;
                    }

                    pbft_state.prepares.insert(node_info.node_id);
                    
                    
                    if pbft_state.prepares.len() as u64 >= 2 * (pbft_state.node_number / 3u64) {
                        println!("\nSending commit\n");

                        pbft_state.pbft_step = PbftStep::ReceiveCommit;

                        let mut commit = Commit {
                            view_number: pbft_state.view_number,
                            sequence_number: pbft_state.sequence_number,
                            node_id: node_info.node_id,
                            public_key: node_info.public_key.clone(),
                            signature: Vec::new(),
                        };

                        sign_commit(&node_info.private_key, &mut commit);

                        for target_addr in target_nodes {
                            send_udp_data(
                                &socket,
                                target_addr,
                                MessageType::Commit,
                                serde_json::to_string(&commit).unwrap().as_bytes(),
                            ).await;
                        }

                        pbft_state.commits.insert(node_info.node_id);

                        if pbft_state.commits.len() as u64 >= 2 * (pbft_state.node_number / 3u64) + 1 {
                            println!("\ncomplete PBFT in Processing pre_prepare message\n");
                            pbft_state.pbft_step = PbftStep::InIdle;
                            let mut blockchain = blockchain.lock().await;
                            blockchain.add_block(pbft_state.block.clone());
                            blockchain.store_to_file(&format!("config/node_{}/blockchain.json", node_info.node_id)).await;
                            if node_info.is_primarry {
                                blockchain.transaction_pool.clear();
                            }
                        }
                    }
                }
            }
        }
        MessageType::Prepare => {
            // if !node_info.is_primarry {
                let mut pbft_state = pbft_state.lock().await;
                if pbft_state.pbft_step == PbftStep::ReceivePrepare {
                    let prepare: Prepare = serde_json::from_slice(&content).unwrap();
                    println!("\nProcessing prepare message\n");
                    if verify_prepare(&prepare.public_key, &prepare, &prepare.signature) {
                        pbft_state.end_time = get_current_time();
                        if !pbft_state.prepares.contains(&prepare.node_id) {
                            pbft_state.prepares.insert(prepare.node_id);

                            if pbft_state.prepares.len() as u64 >= 2 * (pbft_state.node_number / 3u64) {
                                println!("\nSending commit\n");
                                pbft_state.pbft_step = PbftStep::ReceiveCommit;
                                let mut commit = Commit {
                                    view_number: pbft_state.view_number,
                                    sequence_number: pbft_state.sequence_number,
                                    node_id: node_info.node_id,
                                    public_key: node_info.public_key.clone(),
                                    signature: Vec::new(),
                                };

                                sign_commit(&node_info.private_key, &mut commit);

                                for target_addr in target_nodes {
                                    send_udp_data(
                                        &socket,
                                        target_addr,
                                        MessageType::Commit,
                                        serde_json::to_string(&commit).unwrap().as_bytes(),
                                    ).await;
                                }

                                pbft_state.commits.insert(node_info.node_id);

                                if pbft_state.commits.len() as u64 >= 2 * (pbft_state.node_number / 3u64) + 1 {
                                    println!("\ncomplete PBFT\n");
                                    pbft_state.pbft_step = PbftStep::InIdle;
                                    let mut blockchain = blockchain.lock().await;
                                    blockchain.add_block(pbft_state.block.clone());
                                    blockchain.store_to_file(&format!("config/node_{}/blockchain.json", node_info.node_id)).await;

                                    if node_info.is_primarry {
                                        blockchain.transaction_pool.clear();
                                    }
                                }
                            }
                        }
                    }
                }
            // }
        }

        MessageType::Commit => {
            let mut pbft_state = pbft_state.lock().await;
            if pbft_state.pbft_step == PbftStep::ReceiveCommit {
                let commit: Commit = serde_json::from_slice(&content).unwrap();
                println!("\nProcessing commit message\n");
                if verify_commit(&commit.public_key, &commit, &commit.signature) {
                    if !pbft_state.commits.contains(&commit.node_id) {
                        pbft_state.commits.insert(commit.node_id);


                        println!("\n{}, {}\n", pbft_state.commits.len() as u64, 2 * (pbft_state.node_number / 3u64) + 1);
                        if pbft_state.commits.len() as u64 >= 2 * (pbft_state.node_number / 3u64) + 1 {
                            println!("\ncomplete PBFT\n");
                            pbft_state.pbft_step = PbftStep::InIdle;
                            let mut blockchain = blockchain.lock().await;
                            blockchain.add_block(pbft_state.block.clone());
                            blockchain.store_to_file(&format!("config/node_{}/blockchain.json", node_info.node_id)).await;

                            if node_info.is_primarry {
                                blockchain.transaction_pool.clear();
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---


pub fn create_block_hash(index: u64, timestamp: u64, transactions: &Vec<Transaction>, previous_hash: &str, block_info: &str, ) -> String {
    let serialized = serde_json::to_string(&(index, timestamp, &transactions, &previous_hash, &block_info)).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(serialized);
    let hash = format!("{:x}", hasher.finalize());
    hash
}

// ---

// 加载时间戳
pub fn get_current_time() -> u64 {
    let start = SystemTime::now();
    let since_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_epoch.as_secs()
}

// ---

// 从文件加载私钥
pub fn load_private_key_from_file(file_path: &str) -> RsaPrivateKey {
    let mut file = File::open(file_path).unwrap();
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read private key file");
    RsaPrivateKey::from_pkcs1_pem(&pem).expect("Failed to decode private key")
}

// 从文件加载公钥
pub fn load_public_key_from_file(file_path: &str) -> RsaPublicKey {
    let mut file = File::open(file_path).expect("Failed to open public key file");
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read public key file");
    RsaPublicKey::from_pkcs1_pem(&pem).expect("Failed to decode public key")
}