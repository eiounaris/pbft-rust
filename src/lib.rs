pub mod utils;
use utils::*;

use serde::{Deserialize, Serialize};

use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding}, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use std::{ collections::{HashSet,HashMap}, fs::{ File, OpenOptions }, io::{ Read, Write }, net::SocketAddr, sync::Arc, time::{SystemTime, UNIX_EPOCH} };

use sha2::{Sha256, Digest};

use tokio::{ net::UdpSocket, sync::Mutex, io::{AsyncBufReadExt, BufReader}};

use tokio::time::{interval, Duration, sleep};

use tokio::sync::mpsc;
// ---

/// 节点配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig{
    pub node_id: u64,
    pub ip: String,
    pub port: u16,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: RsaPublicKey,
}

/// 节点存储配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config{
    pub view_number: u64,
}

// ---

/// 区块
const BLOCK_SIZE: usize = 25;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub hash: String, // 方便调试，放在最前面
    pub index: u64,
    pub timestamp: u64,
    pub operations: Vec<Operation>,
    pub previous_hash: String,
    
}

// ---

/// PBFT 复制状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationState {
    pub blockchain: Vec<Block>, // 区块链
    pub operation_buffer: Vec<Operation>, // 操作缓冲
    pub request_buffer: Vec<Request>, // 请求缓冲
}

// ---

/// PBFT 操作
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    ReadOperation(ReadOperation),
    WriteOperation(WriteOperation),
}

/// 读操作
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReadOperation {
    Read1,
    Read2,
}

/// 写操作
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WriteOperation {
    Write1,
    Write2,
}

// ---

/// 消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Request = 0,
    PrePrepare = 1,
    Prepare = 2,
    Commit = 3,
    Reply = 4,
    ViewChange = 5,
    NewView = 6,
    Hearbeat = 7,
    Unknown = 8,
    DeterminingPrimaryNode = 9, // 待使用
    ReplingPrimaryNode = 10, // 待使用
    DeterminingLatestReplicationState = 11, // 待使用
    ReplingLatestReplicationState = 12, // 待使用
    SyncRequest = 13,
    SyncResponse = 14,
}

/// 请求消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub operation: Operation,
    pub timestamp: u64,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 预准备消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrePrepare {
    pub view_number: u64,
    pub sequence_number: u64,
    pub digest: Vec<u8>,
    pub node_id: u64, // 可以不要
    pub signature: Vec<u8>,
    pub requests: Vec<Request>,
    pub proof_of_previous_hash: String,
}

/// 准备消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prepare {
    pub view_number: u64,
    pub sequence_number: u64,
    pub digest: Vec<u8>,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 提交消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub view_number: u64,
    pub sequence_number: u64,
    pub digest: Vec<u8>,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 回应消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub view_number: u64,
    pub timestamp: u64,
    pub client_id: u64,
    pub node_id: u64,
    pub result: String, // 可以只接受结果摘要（待改进）
    pub signature: Vec<u8>,
}

/// 视图切换消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewChange {
    pub view_number: u64,
    pub sequence_number: u64,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 新试图消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewView {
    pub view_number: u64,
    pub sequence_number: u64,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 心跳消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hearbeat {
    pub view_number: u64,
    pub sequence_number: u64,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 同步请求消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub from_index: u64,
    pub to_index: u64,
}

/// 同步响应消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub blocks: Vec<Block>,
}



// ---

#[derive(Debug, PartialEq)]
pub enum PbftStep {
    InIdle = 0,
    ReceiveingPrepare = 1,
    ReceiveingCommit = 2,
    RequestingLatestState = 3,
    DeterminingPrimaryNode = 4, // 待使用
    DeterminingLatestReplicationState = 5, // 待使用
    RequestingLatestReplicationState = 6, // 待使用
}

/// 存储 pbft 共识过程状态信息
pub struct PbftState {
    pub view_number: u64,
    pub sended_view_number: u64,
    pub sequence_number: u64,
    pub pbft_step: PbftStep,
    pub start_time: u64,
    pub nodes_number: u64,
    pub preprepare: Option<PrePrepare>,
    pub prepares: HashSet<u64>,
    pub commits: HashSet<u64>,
    pub view_change_mutiple_set: HashMap<u64, HashSet<u64>>, 
    // pub hashchain_of_unreceived_block: Vec<String>, // 待使用
    // pub proof_of_latest_replication_state: Vec<Commit>, // 待使用
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