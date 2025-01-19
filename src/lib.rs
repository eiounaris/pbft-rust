#![allow(dead_code, unused_variables)]
  
use serde::{Deserialize, Serialize};

use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding}, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use std::{ collections::HashSet, fs::{ File, OpenOptions }, io::{ Read, Write }, net::SocketAddr, sync::Arc, time::{SystemTime, UNIX_EPOCH} };

use sha2::{Sha256, Digest};

use tokio::{ net::UdpSocket, sync::Mutex, io::{AsyncBufReadExt, BufReader}};

// ---

/// 节点配置
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeConfig{
    pub node_id: u64,
    pub ip: String,
    pub port: u16,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: RsaPublicKey,
}

// ---

/// PBFT 操作
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Operation {
    ReadOperation(ReadOperation),
    WriteOperation(WriteOperation),
}

/// 操作分类，读操作
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ReadOperation {
    Read1,
    Read2,
}

/// 操作分类，写操作
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum WriteOperation {
    Write1,
    Write2,
}

// ---

/// 区块
const BLOCK_SIZE: usize = 3;
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub operations: Vec<Operation>,
    pub previous_hash: String,
    pub hash: String,
}

// ---

/// PBFT 状态复制
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReplicationState {
    pub blockchain: Vec<Block>, // 区块链
    pub operation_buffer: Vec<Operation>, // 操作缓冲
}

impl ReplicationState {
    /// 初始化区块链
    pub fn new() -> Self {
        ReplicationState {
            blockchain: vec![
                Block {
                    index:  0,
                    timestamp: get_current_time(),
                    operations: Vec::new(),
                    previous_hash: String::new(),
                    hash: String::new(),
                }
            ],
            operation_buffer: Vec::new(),
        } 
    }

    /// 返回最新区块
    pub fn last_block(&self) -> Option<&Block> {
        self.blockchain.last()
    }

    /// 添加区块到区块链
    pub fn add_block(&mut self, block: Block) -> bool {
        if block.previous_hash == self.last_block().unwrap().hash {
            self.blockchain.push(block);
            true
        } else {
            // 如果哈希链断了，发送区块请求，直接复制区块链到文件但不会跟新内存最新区块
            eprintln!("区块哈希链断了，需向主节点发送区块请求（待完成）");
            false
        }
    }

    /// 添加操作请求添加到操作缓冲池
    pub fn add_operation(&mut self, operation: Operation) {
        self.operation_buffer.push(operation);
    }

    /// 根据操作集创建区块
    pub fn create_block(&self, operations: Vec<Operation>) -> Block {
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
        let hash = create_block_hash(index, timestamp, &operations, &previous_hash);

        let block = Block {
            index,
            timestamp,
            operations,
            previous_hash,
            hash,
        };
        block
    }

    /// 存储区块链到文件，并清除内存中最近未使用的所有区块
    pub async fn store_to_file(&mut self, file_path: &str) {
        let mut num: u64 = 0;
        if let Some(block) = ReplicationState::load_last_block_from_file(file_path).await {
            num = block.index + 1;
        }
        let mut file: File = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path).expect("存储区块链到文件，并清除内存中最近未使用的所有区块");

        for block in &self.blockchain {
            if block.index >= num {
                let block = serde_json::to_string(&block).expect("区块反序列化失败");
                writeln!(file, "{}", block).unwrap();
            }
        }
        self.clear_blockchain();
    }

    /// 保留内存中最新一个区块
    pub fn clear_blockchain(&mut self) {
        self.blockchain.drain(..self.blockchain.len() - 1);
    }

    /// 异步读取文件的指定索引区块
    pub async fn load_block_by_index(file_path: &str, index: usize) -> Option<Block> {
        ReplicationState::load_block_by_line(file_path, index + 1).await
    }

    /// 异步读取文件的指定行号所对应区块
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
    

    /// 异步读取文件的最后一行并构造区块
    pub async fn load_last_block_from_file(file_path: &str) -> Option<Block> {
        // 尝试异步打开文件
        let file = match tokio::fs::File::open(file_path).await {
            Ok(f) => f,
            Err(_) => {
                eprintln!("文件路径{}不存在, 初始化区块链", file_path);
                return None; // 打开文件失败，返回 None
            }
        };
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut last_line: Option<String> = None;
        // 异步遍历每一行
        while let Ok(Some(line)) = lines.next_line().await {
            last_line = Some(line);
        }
        if let Some(line) = last_line {
            let block = serde_json::from_str(&line).expect("区块序反列化失败");
            Some(block)
        } else {
            None
        }
    }
}

/// 消息类型
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum MessageType {
    Request = 0,
    PrePrepare = 1,
    Prepare = 2,
    Commit = 3,
    Reply = 4,
    ViewChange = 5,
    NewView = 6,
    Unknown = 10,
}

/// 请求消息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Request {
    pub operation: Operation,
    pub timestamp: u64,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

impl Request {
    pub fn digest(&self) -> Vec<u8> {
        Sha256::digest(serde_json::to_string(self).unwrap().as_bytes()).to_vec()
    }
}

/// 预准备消息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrePrepare {
    pub view_number: u64,
    pub sequence_number: u64,
    pub digest: Vec<u8>,
    pub node_id: u64, // 可以不要
    pub signature: Vec<u8>,
    pub request: Request,
}

/// 准备消息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Prepare {
    pub view_number: u64,
    pub sequence_number: u64,
    pub digest: Vec<u8>,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 提交消息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Commit {
    pub view_number: u64,
    pub sequence_number: u64,
    pub digest: Vec<u8>,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 回应消息
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Reply {
    pub view_number: u64,
    pub timestamp: u64,
    pub client_id: u64,
    pub node_id: u64,
    pub result: String,
    pub signature: Vec<u8>,
}

// ---

/// 存储pbft共识状态信息
pub struct PbftState {
    pub view_number: u64,
    pub sequence_number: u64,
    pub pbft_step: PbftStep,
    pub start_time: u64,
    pub end_time: u64,
    pub node_id: u64,
    pub preprepare: Option<PrePrepare>,
    pub prepares: HashSet<u64>,
    pub commits: HashSet<u64>,
}

#[derive(Debug, PartialEq)]
pub enum PbftStep {
    InIdle = 0,
    ReceiveingPrepare = 1,
    ReceiveingCommit = 2,
    RequestingLatestState = 3,
}

impl PbftState {
    // 初始化pbft共识状态
    pub fn new(
        view_number: u64,
        sequence_number: u64,
        node_id: u64
    ) -> Self {
        PbftState {
            view_number: view_number,
            sequence_number: sequence_number,
            pbft_step: PbftStep::InIdle,
            start_time: 0,
            end_time: 0,
            node_id: node_id,
            preprepare: None,
            prepares: HashSet::new(),
            commits: HashSet::new(),
        }
    }
}

// ---

/// 存储节点信息
pub struct NodeInfo {
    pub node_id: u64,
    pub local_addr: String,
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub nodes: Vec<NodeConfig>,
}

impl NodeInfo {
    /// 初始化构造函数
    pub fn new(
        node_id: u64,
        local_addr: String,
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey,
        nodes: Vec<NodeConfig>,
    ) -> Self {
        NodeInfo {
            node_id,
            local_addr,
            private_key,
            public_key,
            nodes,
        }
    }

    pub fn is_primarry(&self, view_number: u64) -> bool {
        view_number / self.nodes.len() as u64 == self.node_id
    }
}

// ---

/// 任务: 发送命令行指令数据
pub async fn send_message(node_info: &NodeInfo, target_nodes: &[SocketAddr], socket_send: Arc<UdpSocket>, _pbft_state: Arc<Mutex<PbftState>> ) {
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        
        let mut request = Request {
            operation: Operation::ReadOperation(ReadOperation::Read1),
            timestamp: get_current_time(),
            node_id: node_info.node_id,
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


/// 任务: 接收并处理数据
pub async fn handle_message(
    socket: Arc<UdpSocket>, 
    node_info: &NodeInfo, 
    target_nodes: &[SocketAddr], 
    replication_state: Arc<Mutex<ReplicationState>>, 
    pbft_state: Arc<Mutex<PbftState>>,
) {
    let mut buf = [0u8; 10240];
    loop {
        let (udp_data_size, src_socket_addr) = socket.recv_from(&mut buf).await.expect("udp数据报过大，缓冲区溢出");
        // 提取消息类型（第一个字节）
        let message_type = match buf[0] {
            0 => MessageType::Request,
            1 => MessageType::PrePrepare,
            2 => MessageType::Prepare,
            3 => MessageType::Commit,
            4 => MessageType::ViewChange,
            5 => MessageType::NewView,
            _ => {
                eprintln!("Reiceive unknown message type");
                MessageType::Unknown
            },
        };

        // 提取消息内容（剩余的字节）
        let content = buf[1..udp_data_size].to_vec(); // 转换为 Vec<u8>
        

        match message_type {
            // 处理请求消息
            MessageType::Request => {
                let mut pbft_state = pbft_state.lock().await;
                if node_info.is_primarry(pbft_state.view_number) {
                    println!("\n主节点接收到 Request 消息");
                    let request: Request = serde_json::from_slice(&content).unwrap(); // 怎么避免转换失败报错？
                    if verify_request(&node_info.nodes[request.node_id as usize].public_key, &request, &request.signature) {
                        let mut replication_state = replication_state.lock().await;
                        {
                            replication_state.add_operation(request.operation.clone());
                        }
                        println!("\n操作缓冲大小: {:?}", replication_state.operation_buffer.len());
                        if pbft_state.pbft_step != PbftStep::InIdle && (get_current_time() - pbft_state.start_time > 1) {
                            pbft_state.pbft_step = PbftStep::InIdle;
                            pbft_state.preprepare = None;
                            pbft_state.prepares = HashSet::new();
                            pbft_state.commits = HashSet::new();
                        }
                        if pbft_state.pbft_step == PbftStep::InIdle {
                            if replication_state.operation_buffer.len() >= BLOCK_SIZE {
                                let block: Block = replication_state.create_block(replication_state.operation_buffer.clone());
                                
                                let mut pre_prepare = PrePrepare {
                                    view_number: pbft_state.view_number,
                                    sequence_number: pbft_state.sequence_number,
                                    node_id: node_info.node_id,
                                    digest: request.digest(),
                                    signature: Vec::new(),
                                    request,
                                };
                                pbft_state.preprepare = Some(pre_prepare.clone());
                                sign_pre_prepare(&node_info.private_key, &mut pre_prepare);
                                println!("\n发送preprepare");
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
                } else {
                    println!("\n备份节点接收到 Request 消息");
                    // 判断是否发起 view_change 消息
                }
            }
            // 处理预准备消息
            MessageType::PrePrepare => {
                let mut pbft_state = pbft_state.lock().await;
                if pbft_state.pbft_step != PbftStep::InIdle && (get_current_time() - pbft_state.start_time > 1) {
                    pbft_state.pbft_step = PbftStep::InIdle;
                    pbft_state.preprepare = None;
                    pbft_state.prepares = HashSet::new();
                    pbft_state.commits = HashSet::new();
                }
                if pbft_state.pbft_step == PbftStep::InIdle {
                    let pre_prepare: PrePrepare = serde_json::from_slice(&content).unwrap();
                    println!("\n处理preprepare消息");
                    if verify_pre_prepare(&node_info.nodes[pre_prepare.node_id as usize].public_key, &pre_prepare, &pre_prepare.signature) {
                        pbft_state.pbft_step = PbftStep::ReceiveingPrepare;
                        pbft_state.prepares.clear();
                        pbft_state.commits.clear();
    
                        let mut prepare = Prepare {
                            view_number: pbft_state.view_number,
                            sequence_number: pbft_state.sequence_number,
                            digest: pre_prepare.digest,
                            node_id: node_info.node_id,
                            signature: Vec::new(),
                        };
    
                        sign_prepare(&node_info.private_key, &mut prepare);
    
                        println!("\n发送prepare消息");
                        for target_addr in target_nodes {
                            send_udp_data(
                                &socket,
                                target_addr,
                                MessageType::Prepare,
                                serde_json::to_string(&prepare).unwrap().as_bytes(),
                            ).await;
                        }
    
                        pbft_state.prepares.insert(node_info.node_id);
                        
                        
                        if pbft_state.prepares.len() as u64 >= 2 * ((node_info.nodes.len() - 1) as u64 / 3u64) + 1{
                            println!("\n发送commit消息");
    
                            pbft_state.pbft_step = PbftStep::ReceiveingCommit;
    
                            let mut commit = Commit {
                                view_number: pbft_state.view_number,
                                sequence_number: pbft_state.sequence_number,
                                digest: prepare.digest,
                                node_id: node_info.node_id,
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
    
                            if pbft_state.commits.len() as u64 >= 2 * ((node_info.nodes.len() - 1) as u64 / 3u64) + 1 {
                                println!("\ncomplete PBFT");
                                pbft_state.pbft_step = PbftStep::InIdle;
                                let mut replication_state = replication_state.lock().await;
                                replication_state.add_operation(pbft_state.preprepare.clone().unwrap().request.operation);
                                replication_state.store_to_file(&format!("config/node_{}/replication_state.json", node_info.node_id)).await;
                                if node_info.is_primarry(pbft_state.view_number) {
                                    replication_state.operation_buffer.clear();
                                }
                            }
                        }
                    }
                }
            }
            // 处理准备消息
            MessageType::Prepare => {
                let mut pbft_state = pbft_state.lock().await;
                if pbft_state.pbft_step == PbftStep::ReceiveingPrepare {
                    let prepare: Prepare = serde_json::from_slice(&content).unwrap();
                    println!("\n处理prepare消息\n");
                    if verify_prepare(&node_info.nodes[prepare.node_id as usize].public_key, &prepare, &prepare.signature) {
                        pbft_state.end_time = get_current_time();
                        if !pbft_state.prepares.contains(&prepare.node_id) {
                            pbft_state.prepares.insert(prepare.node_id);

                            if pbft_state.prepares.len() as u64 >= 2 * ((node_info.nodes.len() - 1) as u64 / 3u64) + 1 {
                                println!("\n发送commit\n");
                                pbft_state.pbft_step = PbftStep::ReceiveingCommit;
                                let mut commit = Commit {
                                    view_number: pbft_state.view_number,
                                    sequence_number: pbft_state.sequence_number,
                                    digest: prepare.digest,
                                    node_id: node_info.node_id,
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

                                if pbft_state.commits.len() as u64 >= 2 * ((node_info.nodes.len() - 1) as u64 / 3u64) + 1 {
                                    println!("\ncomplete PBFT\n");
                                    pbft_state.pbft_step = PbftStep::InIdle;
                                    let mut replication_state = replication_state.lock().await;
                                    replication_state.add_operation(pbft_state.preprepare.clone().unwrap().request.operation.clone());
                                    replication_state.store_to_file(&format!("config/node_{}/replication_state.json", node_info.node_id)).await;

                                    if node_info.is_primarry(pbft_state.view_number) {
                                        replication_state.operation_buffer.clear();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // 处理提交消息
            MessageType::Commit => {
                let mut pbft_state = pbft_state.lock().await;
                if pbft_state.pbft_step == PbftStep::ReceiveingCommit {
                    let commit: Commit = serde_json::from_slice(&content).unwrap();
                    println!("\n处理commit消息");
                    if verify_commit(&node_info.nodes[commit.node_id as usize].public_key, &commit, &commit.signature) {
                        if !pbft_state.commits.contains(&commit.node_id) {
                            pbft_state.commits.insert(commit.node_id);
    
                            if pbft_state.commits.len() as u64 >= 2 * ((node_info.nodes.len() - 1) as u64 / 3u64) + 1 {
                                println!("\ncomplete PBFT\n");
                                pbft_state.pbft_step = PbftStep::InIdle;
                                let mut replication_state = replication_state.lock().await;
                                replication_state.add_operation(pbft_state.preprepare.clone().unwrap().request.operation.clone());
                                replication_state.store_to_file(&format!("config/node_{}/replication_state.json", node_info.node_id)).await;
    
                                if node_info.is_primarry(pbft_state.view_number) {
                                    replication_state.operation_buffer.clear();
                                }
                            }
                        }
                    }
                }
            },
            _ => println!("unkown message type"),
        }
    }
}

// ---辅助函数

// 计算区块哈希
pub fn create_block_hash(index: u64, timestamp: u64, operations: &Vec<Operation>, previous_hash: &str) -> String {
    let serialized = serde_json::to_string(&(index, timestamp, &operations, &previous_hash)).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(serialized);
    let hash = format!("{:x}", hasher.finalize());
    hash
}

// ---辅助函数

/// 加载时间戳
pub fn get_current_time() -> u64 {
    let start = SystemTime::now();
    let since_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_epoch.as_secs()
}

// ---辅助函数

/// 从文件加载私钥，错误处理待改进
pub fn load_private_key_from_file(file_path: &str) -> RsaPrivateKey {
    let mut file = File::open(file_path).unwrap();
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read private key file");
    RsaPrivateKey::from_pkcs1_pem(&pem).expect("Failed to decode private key")
}

// 从文件加载公钥，错误处理待改进
pub fn load_public_key_from_file(file_path: &str) -> RsaPublicKey {
    let mut file = File::open(file_path).expect("Failed to open public key file");
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read public key file");
    RsaPublicKey::from_pkcs1_pem(&pem).expect("Failed to decode public key")
}


// ---辅助函数

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

// 使用私钥签名请求消息
pub fn sign_request(priv_key: &RsaPrivateKey, request: &mut Request) {
    request.signature = sign_data(priv_key, serde_json::to_string(&request).unwrap().as_bytes());
}

// 使用公钥验证请求消息
pub fn verify_request(pub_key: &RsaPublicKey, request: & Request, signature: &[u8]) -> bool {
    let mut request = request.clone();
    request.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&request).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

// 使用私钥签名预准备消息
pub fn sign_pre_prepare(priv_key: &RsaPrivateKey, pre_prepare: &mut PrePrepare) {
    pre_prepare.signature = sign_data(priv_key, serde_json::to_string(&pre_prepare).unwrap().as_bytes());
}

// 使用公钥验证预准备消息
pub fn verify_pre_prepare(pub_key: &RsaPublicKey, pre_prepare: & PrePrepare, signature: &[u8]) -> bool {
    let mut pre_prepare = pre_prepare.clone();
    pre_prepare.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&pre_prepare).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

// 使用私钥签名准备消息
pub fn sign_prepare(priv_key: &RsaPrivateKey, prepare: &mut Prepare) {
    prepare.signature=sign_data(priv_key, serde_json::to_string(&prepare).unwrap().as_bytes());
}

// 使用公钥验证准备消息
pub fn verify_prepare(pub_key: &RsaPublicKey, prepare: & Prepare, signature: &[u8]) -> bool {
    let mut prepare = prepare.clone();
    prepare.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&prepare).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

// 使用私钥签名提交消息
pub fn sign_commit(priv_key: &RsaPrivateKey, commit: &mut Commit) {
    commit.signature=sign_data(priv_key, serde_json::to_string(&commit).unwrap().as_bytes());
}

// 使用公钥验证提交消息
pub fn verify_commit(pub_key: &RsaPublicKey, commit: & Commit, signature: &[u8]) -> bool {
    let mut commit = commit.clone();
    commit.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&commit).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}


// ---辅助函数

// 发送UDP数据
pub async fn send_udp_data(socket: &UdpSocket, addr: &SocketAddr, message_type: MessageType, content: &[u8]) {
    // 生成消息的字节数组，先是类型字节，然后是消息内容的字节
    let mut message = Vec::new();
    message.push(message_type as u8);  // 将类型作为第一个字节
    message.extend_from_slice(&content);  // 将内容附加到字节数组后面
    // 发送消息
    socket.send_to(&message, addr).await.unwrap();
}

// 接收UDP数据
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

// ---辅助函数

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
