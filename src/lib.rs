// lib.rs
pub mod utils;
pub mod actix_web_demo;
pub mod db;
use utils::*;
use crate::db::*;
use serde::{Deserialize, Serialize};

use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding}, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use std::{ collections::{HashMap, HashSet}, fs::{ File, OpenOptions }, io::{ Read, Write }, net::{SocketAddr, Ipv4Addr}, sync::Arc, time::{SystemTime, UNIX_EPOCH} };

use sha2::{Sha256, Digest};

use tokio::{ net::UdpSocket, sync::Mutex, io::{AsyncBufReadExt, BufReader}};

use tokio::time::{interval, Duration, sleep};

use tokio::sync::mpsc;

// ---

/// 所有节点初始化配置（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: u64,
    pub ip: String,
    pub port: u16,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pub public_key: RsaPublicKey,
}

// ---

/// 自身节点节点持久化配置（暂时选择state存储路径，后续待调整）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateConfig {
    pub view_number: u64,
    pub state_file_path: String, // （后续调整为数据库路径）
}

// ---

// 区块链公有配置（待调整）
pub struct PublicConfig {
    pub multi_cast_socket: String,
    pub block_size: u64,
}

// ---

/// 区块大小（可手动调整区块大小，也可通过配置文件设置区块大小）
const BLOCK_SIZE: usize = 1;

/// 区块（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub operations: Vec<Operation>,
    pub previous_hash: String,
    pub hash: String, // 若调试，则放在最上面
}

// ---

/// PBFT 复制状态 （后续考虑采用State命名）
pub struct ReplicationState {
    pub request_buffer: Vec<Request>, // 请求缓冲
    pub rocksdb: RocksDBBlockStore,
}

// ---

/// PBFT 操作，封装操作，后续添加智能合约功能模块（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    Operation0 = 0,
    Operation1 = 1,
    Operation2 = 2,
}

// ---

/// 消息类型（顺序待调整）
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
    
    DeterminingPrimaryNode = 9,
    ReplingPrimaryNode = 10,
    DeterminingLatestReplicationState = 11,
    ReplingLatestReplicationState = 12,
    SyncRequest = 13,
    SyncResponse = 14,

    Unknown = 20,
}

/// 请求消息（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub operation: Operation,
    pub timestamp: u64,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 预准备消息 （后续考虑把主节点本地构造好的区块添加进去）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrePrepare {
    pub view_number: u64,
    pub sequence_number: u64,
    pub digest: Vec<u8>,
    pub node_id: u64, // （可以不要后续考虑删掉）
    pub signature: Vec<u8>,
    pub requests: Vec<Request>, // （后续考虑把主节点本地构造好的区块添加进去pub operations: Vec<Operation>， 之后可把proof_of_previous_hash删掉） 
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

/// 回应消息（暂时保留，该场景使用不到，该场景下共识节点等同于用户节点）
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct Reply {
//     pub view_number: u64,
//     pub timestamp: u64,
//     pub client_id: u64,
//     pub node_id: u64,
//     pub result: String, // 可以只接受结果摘要（待改进）
//     pub signature: Vec<u8>,
// }

/// 视图切换消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewChange {
    pub view_number: u64, 
    pub sequence_number: u64,
    // 考虑添加 pub next_view_number: u64, 
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 新试图消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewView {
    pub view_number: u64,
    pub sequence_number: u64,
    // 考虑添加 pub next_view_number: u64, 
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

/// 存储节点运行不变配置信息
pub struct NodeInfo {
    pub local_node_id: u64,
    pub local_socket_addr: std::net::SocketAddr,
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub node_configs: Vec<NodeConfig>,
}