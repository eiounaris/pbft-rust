// #![allow(dead_code, unused_variables)]
mod utils;
use utils::*;
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
const BLOCK_SIZE: usize = 2;
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
    pub request_buffer: Vec<Request>, // 请求缓冲
}

impl ReplicationState {
    /// 初始化区块链
    pub fn new() -> Self {
        ReplicationState {
            blockchain: vec![
                Block {
                    index:  0,
                    timestamp: get_current_timestamp(),
                    operations: Vec::new(),
                    previous_hash: String::new(),
                    hash: String::new(),
                }
            ],
            operation_buffer: Vec::new(),
            request_buffer: Vec::new(),
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
            // 如果哈希链断了，发送区块请求，直接复制区块链到文件但不会更新内存最新区块
            eprintln!("区块哈希链断了，需向主节点发送区块请求（待完成）");
            false
        }
    }

    /// 添加操作请求到操作缓冲池
    pub fn add_operation(&mut self, operation: Operation) {
        self.operation_buffer.push(operation);
    }

    /// 添加请求消息中的操作请求到操作缓冲池，若操作缓冲池大于区块大小则创建区块链
    pub fn add_operations_of_requests(&mut self, requests: Vec<Request>) {
        for request in requests {
            self.add_operation(request.operation);
        }
        if self.operation_buffer.len() >= BLOCK_SIZE {
            let new_block = self.create_block(self.operation_buffer.clone());
            self.operation_buffer.clear();
            self.add_block(new_block);
        }
    }

    /// 添加待处理请求添加到请求缓冲池
    pub fn add_request(&mut self, request: Request) {
        self.request_buffer.push(request);
    }

    /// 根据操作集创建区块
    pub fn create_block(&self, operations: Vec<Operation>) -> Block {
        let index: u64 = if let Some(last_block) = self.last_block() {
            last_block.index + 1
        } else {
            0
        };
        let timestamp: u64 = get_current_timestamp();
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
    pub fn digest_request(&self) -> Vec<u8> {
        Sha256::digest(serde_json::to_string(self).unwrap().as_bytes()).to_vec()
    }
    pub fn digest_requests(requests: &Vec<Request>) -> Vec<u8> {
        Sha256::digest(serde_json::to_string(requests).unwrap().as_bytes()).to_vec()
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
    pub requests: Vec<Request>,
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
    pub result: String, // 可以只接受结果摘要（待改进）
    pub signature: Vec<u8>,
}

// ---

/// 存储pbft共识状态信息
pub struct PbftState {
    pub view_number: u64,
    pub sequence_number: u64,
    pub pbft_step: PbftStep,
    pub start_time: u64,
    pub nodes_number: u64,
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
        nodes_number: u64
    ) -> Self {
        PbftState {
            view_number: view_number,
            sequence_number: sequence_number,
            pbft_step: PbftStep::InIdle,
            start_time: get_current_timestamp(),
            nodes_number: nodes_number,
            preprepare: None,
            prepares: HashSet::new(),
            commits: HashSet::new(),
        }
    }
}

// ---

/// 存储节点信息
pub struct NodeInfo {
    pub local_node_id: u64,
    pub local_socket_addr: std::net::SocketAddr,
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub node_configs: Vec<NodeConfig>,
}

impl NodeInfo {
    /// 初始化构造函数
    pub fn new(
        local_node_id: u64,
        local_socket_addr: std::net::SocketAddr,
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey,
        node_configs: Vec<NodeConfig>,
    ) -> Self {
        NodeInfo {
            local_node_id,
            local_socket_addr,
            private_key,
            public_key,
            node_configs,
        }
    }

    pub fn is_primarry(&self, view_number: u64) -> bool {
        view_number / self.node_configs.len() as u64 == self.local_node_id
    }
}

// ---

/// 任务: 发送命令行指令数据
pub async fn send_message(udp_socket: Arc<UdpSocket>, node_info: &NodeInfo, multicast_nodes_addr: &[SocketAddr]) {
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
            timestamp: get_current_timestamp(),
            node_id: node_info.local_node_id,
            signature: Vec::new(),
        };
        sign_request(&node_info.private_key, &mut request);
        // 发送消息
        for node_addr in multicast_nodes_addr {
            send_udp_data(
                &udp_socket,
                node_addr,
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
    let mut buf = [0u8; 102400];
    loop {
        let (udp_data_size, _src_socket_addr) = socket.recv_from(&mut buf).await.expect("udp数据报过大，缓冲区溢出");
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
                    if let Ok(request) = serde_json::from_slice::<Request>(&content) {
                        // 成功反序列化，继续处理
                        if verify_request(&node_info.node_configs[request.node_id as usize].public_key, &request, &request.signature) {
                            let mut replication_state = replication_state.lock().await;
                            replication_state.add_request(request.clone());
                            println!("\n请求缓冲大小: {:?}", replication_state.request_buffer.len());
                            if pbft_state.pbft_step != PbftStep::InIdle && (get_current_timestamp() - pbft_state.start_time > 1) {
                                pbft_state.pbft_step = PbftStep::InIdle;
                                pbft_state.preprepare = None;
                                pbft_state.prepares.clear();
                                pbft_state.commits.clear();
                            }
                            if pbft_state.pbft_step == PbftStep::InIdle {
                                if replication_state.request_buffer.len() >= BLOCK_SIZE {
                                    pbft_state.prepares.clear();
                                    pbft_state.commits.clear();
                                    let mut pre_prepare = PrePrepare {
                                        view_number: pbft_state.view_number,
                                        sequence_number: pbft_state.sequence_number,
                                        node_id: node_info.local_node_id,
                                        digest: Request::digest_requests(&replication_state.request_buffer),
                                        signature: Vec::new(),
                                        requests: replication_state.request_buffer.clone(),
                                    };
                                    sign_pre_prepare(&node_info.private_key, &mut pre_prepare);
                                    pbft_state.preprepare = Some(pre_prepare.clone());
                                    println!("\n发送preprepare");
                                    for target_addr in target_nodes {
                                        send_udp_data(
                                            &socket,
                                            target_addr,
                                            MessageType::PrePrepare,
                                            serde_json::to_string(&pre_prepare).unwrap().as_bytes(),
                                        ).await;
                                    }
                                    pbft_state.pbft_step = PbftStep::ReceiveingPrepare;
                                }
                            }
                        }
                    } else {
                        // 反序列化失败，跳过当前循环
                        continue;
                    }                    
                } else {
                    println!("\n备份节点接收到 Request 消息");
                    // 判断是否发起 view_change 消息
                }
            }
            // 处理预准备消息
            MessageType::PrePrepare => {
                let mut pbft_state = pbft_state.lock().await;
                if !node_info.is_primarry(pbft_state.view_number) {
                    println!("\n备份节点接收到 PrePrepare 消息");
                    if pbft_state.pbft_step != PbftStep::InIdle && (get_current_timestamp() - pbft_state.start_time > 1) {
                        pbft_state.pbft_step = PbftStep::InIdle;
                        pbft_state.preprepare = None;
                        pbft_state.prepares.clear();
                        pbft_state.commits.clear();
                    }
                    if pbft_state.pbft_step == PbftStep::InIdle {
                        if let Ok(pre_prepare) = serde_json::from_slice::<PrePrepare>(&content) {
                            // 成功反序列化，继续处理
                            println!("\n成功反序列化，继续处理");
                            if verify_pre_prepare(&node_info.node_configs[pre_prepare.node_id as usize].public_key, &pre_prepare, &pre_prepare.signature) {
                                pbft_state.preprepare = Some(pre_prepare.clone());
                                pbft_state.pbft_step = PbftStep::ReceiveingPrepare;
                                pbft_state.prepares.clear();
                                pbft_state.commits.clear();
    
                                let mut prepare = Prepare {
                                    view_number: pbft_state.view_number,
                                    sequence_number: pbft_state.sequence_number,
                                    digest: pre_prepare.digest,
                                    node_id: node_info.local_node_id,
                                    signature: Vec::new(),
                                };
            
                                sign_prepare(&node_info.private_key, &mut prepare);
            
                                println!("\n发送 prepare 消息");
                                for target_addr in target_nodes {
                                    send_udp_data(
                                        &socket,
                                        target_addr,
                                        MessageType::Prepare,
                                        serde_json::to_string(&prepare).unwrap().as_bytes(),
                                    ).await;
                                }
            
                                pbft_state.prepares.insert(node_info.local_node_id);
                                
                                
                                if pbft_state.prepares.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) {
                                    println!("\n发送commit消息");
            
                                    pbft_state.pbft_step = PbftStep::ReceiveingCommit;
            
                                    let mut commit = Commit {
                                        view_number: pbft_state.view_number,
                                        sequence_number: pbft_state.sequence_number,
                                        digest: prepare.digest,
                                        node_id: node_info.local_node_id,
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
            
                                    pbft_state.commits.insert(node_info.local_node_id);
            
                                    if pbft_state.commits.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) + 1 {
                                        println!("\n2f + 1 个节点达成共识");
                                        pbft_state.pbft_step = PbftStep::InIdle;
                                        let mut replication_state = replication_state.lock().await;
                                        replication_state.add_operations_of_requests(pbft_state.preprepare.clone().unwrap().requests);
                                        replication_state.store_to_file(&format!("config/node_{}/replication_state.json", node_info.local_node_id)).await;
    
                                        if node_info.is_primarry(pbft_state.view_number) {
                                            replication_state.request_buffer.drain(0..pbft_state.preprepare.clone().unwrap().requests.len());
                                        }
                                    }
                                }
                            }
                        } else {
                            // 反序列化失败，跳过当前循环
                            continue;
                        }
                        // let pre_prepare: PrePrepare = serde_json::from_slice(&content).unwrap(); // 怎么让错误数据反序列化不panic
                        
                    }
                }
                
            }
            // 处理准备消息
            MessageType::Prepare => {
                let mut pbft_state = pbft_state.lock().await;
                if pbft_state.pbft_step == PbftStep::ReceiveingPrepare {
                    if let Ok(prepare) = serde_json::from_slice::<Prepare>(&content) {
                        // 成功反序列化，继续处理
                        println!("\n处理 prepare 消息");
                        if verify_prepare(&node_info.node_configs[prepare.node_id as usize].public_key, &prepare, &prepare.signature) {
                            if !pbft_state.prepares.contains(&prepare.node_id) {
                                pbft_state.prepares.insert(prepare.node_id);
                                if pbft_state.prepares.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) {
                                    println!("\n发送 commit 消息");
                                    pbft_state.pbft_step = PbftStep::ReceiveingCommit;
                                    let mut commit = Commit {
                                        view_number: pbft_state.view_number,
                                        sequence_number: pbft_state.sequence_number,
                                        digest: prepare.digest,
                                        node_id: node_info.local_node_id,
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

                                    pbft_state.commits.insert(node_info.local_node_id);

                                    if pbft_state.commits.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) + 1 {
                                        println!("\n2f + 1 个节点达成共识");
                                        pbft_state.pbft_step = PbftStep::InIdle;
                                        let mut replication_state = replication_state.lock().await;
                                        replication_state.add_operations_of_requests(pbft_state.preprepare.clone().unwrap().requests);
                                        replication_state.store_to_file(&format!("config/node_{}/replication_state.json", node_info.local_node_id)).await;

                                        if node_info.is_primarry(pbft_state.view_number) {
                                            replication_state.request_buffer.drain(0..pbft_state.preprepare.clone().unwrap().requests.len());
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // 反序列化失败，跳过当前循环
                        continue;
                    }
                    
                }
            }
            // 处理提交消息
            MessageType::Commit => {
                let mut pbft_state = pbft_state.lock().await;
                if pbft_state.pbft_step == PbftStep::ReceiveingCommit {
                    if let Ok(commit) = serde_json::from_slice::<Commit>(&content) {
                        // 成功反序列化，继续处理
                        println!("\n处理commit消息");
                        if verify_commit(&node_info.node_configs[commit.node_id as usize].public_key, &commit, &commit.signature) {
                            if !pbft_state.commits.contains(&commit.node_id) {
                                pbft_state.commits.insert(commit.node_id);
        
                                if pbft_state.commits.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) + 1 {
                                    println!("\n2f + 1 个节点达成共识");
                                    pbft_state.pbft_step = PbftStep::InIdle;
                                    let mut replication_state = replication_state.lock().await;
                                    replication_state.add_operations_of_requests(pbft_state.preprepare.clone().unwrap().requests);
                                    replication_state.store_to_file(&format!("config/node_{}/replication_state.json", node_info.local_node_id)).await;
        
                                    if node_info.is_primarry(pbft_state.view_number) {
                                        replication_state.request_buffer.drain(0..pbft_state.preprepare.clone().unwrap().requests.len());
                                    }
                                }
                            }
                        }
                    } else {
                        // 反序列化失败，跳过当前循环
                        continue;
                    }
                }
            },
            _ => println!("unkown message type"),
        }
    }
}


// ---

/// PBFT 初始化函数
pub async  fn init() -> Result<(Arc<UdpSocket>, Arc<NodeInfo>, Arc<Vec<SocketAddr>>, Arc<Mutex<ReplicationState>>, Arc<Mutex<PbftState>>), std::io::Error> {
    // 解析命令行参数
    let env_args: Vec<String> = std::env::args().collect();
    if env_args.len() != 3 {
        eprintln!("\n输入参数格式错误，正确格式为：{} local_node_id nodes_config_path\n", env_args[0]);
        std::process::exit(1);
    }

    // 获取节点 id
    let local_node_id: u64 = env_args[1].parse().expect("\n输入 local_node_id 不是数字");

    // 从配置文件读取节点配置信息
    let nodes_config_path = &env_args[2];
    let nodes_config_jsonstring = std::fs::read_to_string(nodes_config_path).expect("\n节点配置路径对应文件不存在");
    let node_configs: Vec<NodeConfig> = serde_json::from_str(&nodes_config_jsonstring).expect("\n节点配置文件json格式错误");
    
    // 查找自身节点配置
    let local_node_config: &NodeConfig = node_configs.iter().find(|node| (**node).node_id == local_node_id).expect("\nlocal_node_id 不在节点配置文件中");
    let local_addr_string = format!("{}:{}", local_node_config.ip, local_node_config.port);
    let private_key = load_private_key_from_file(&format!("config/node_{}/private_key.pem", local_node_id));
    let public_key = load_public_key_from_file(&format!("config/node_{}/public_key.pem", local_node_id));
    
    // 广播套接字地址
    let multicast_nodes_addr: Vec<std::net::SocketAddr> = node_configs.iter()
        .filter(|node| (**node).node_id != local_node_id)
        .map(|node| {
            format!("{}:{}", node.ip, node.port)
                .parse()
                .expect("\n节点配置文件中包含无效的节点地址")
        })
        .collect();
    let multicast_nodes_addr = Arc::new(multicast_nodes_addr);

    // 输出本地节点初始化信息
    println!("\n本地节点 {} 启动，绑定到地址：{}", local_node_id, local_addr_string);
    
    // 创建本地 UDP 异步套接字
    let udp_socket = Arc::new(tokio::net::UdpSocket::bind(&local_addr_string).await.expect("\n创建本地节点套接字失败"));

    
    // 初始化节点信息
    let node_info = NodeInfo::new(
        local_node_id,
        local_addr_string.parse::<std::net::SocketAddr>().expect("\n节点配置文件中包含无效的节点地址"),
        private_key,
        public_key, 
        node_configs,
    );
    let node_info = Arc::new(node_info);


    // 初始化复制状态信息
    let replication_state: ReplicationState;
    if let Some(block) = ReplicationState::load_last_block_from_file(&format!("config/node_{}/replication_state.json", local_node_id)).await {
        replication_state = ReplicationState {
            blockchain: vec![block],
            operation_buffer: Vec::new(),
            request_buffer: Vec::new(),
        };
    } else {
        replication_state = ReplicationState::new();
    }
    let replication_state = Arc::new(Mutex::new(replication_state));


    // 初始化 pbft 共识状态
    let pbft_state = PbftState::new(
        0, // view_number 待改进，采用动态视图。
        replication_state.lock().await.last_block().unwrap().index, 
        node_info.node_configs.len() as u64
    );
    let pbft_state = Arc::new(Mutex::new(pbft_state));
    Ok((udp_socket, node_info, multicast_nodes_addr, replication_state, pbft_state))
}