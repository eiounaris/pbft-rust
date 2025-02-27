// lib.rs
pub mod utils;
pub mod actix_web_demo;
pub mod db;

use utils::*;
use crate::db::*;

use serde::{Deserialize, Serialize};

use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding}, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use std::{ collections::{HashMap, HashSet}, fs::File, io::Read, net::{SocketAddr, Ipv4Addr}, sync::Arc, time::{SystemTime, UNIX_EPOCH} };

use sha2::{Sha256, Digest};

use tokio::{ net::UdpSocket, sync::Mutex, io::AsyncBufReadExt};

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

/// 自身节点节点持久化配置（待调整）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateConfig {
    pub view_number: u64,
    pub database_name: String,
}

// ---

// 区块链公有配置（待调整）
pub struct PublicConfig {
    pub multi_cast_socket: String,
    pub block_size: u64,
}

// ---

/// 区块大小（待调整）
const BLOCK_SIZE: usize = 50;

/// 区块（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub operations: Vec<Operation>,
    pub previous_hash: String,
    pub hash: String,
}

// ---

/// PBFT 复制状态（fine）
pub struct ReplicationState {
    pub request_buffer: Vec<Request>, // 用户请求消息缓冲
    pub rocksdb: RocksDBBlockStore,
}

// ---

/// PBFT 操作，抽象，后续添加智能合约功能模块（待调整）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    Operation0 = 0,
    Operation1 = 1,
    Operation2 = 2,
}

// ---

/// 消息类型（待调整）
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

/// 预准备消息（后续考虑把主节点本地构造好的区块添加进去）（待调整）
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

/// 准备消息（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prepare {
    pub view_number: u64,
    pub sequence_number: u64,
    pub digest: Vec<u8>,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 提交消息（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub view_number: u64,
    pub sequence_number: u64,
    pub digest: Vec<u8>,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 回应消息（PBFT 论文中需要，目前暂时保留，该场景使用不到，该场景下共识节点等同于用户节点）
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct Reply {
//     pub view_number: u64,
//     pub timestamp: u64,
//     pub client_id: u64,
//     pub node_id: u64,
//     pub result: String, // 可以只接受结果摘要（待改进）
//     pub signature: Vec<u8>,
// }

/// 视图切换消息（待调整）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewChange {
    pub view_number: u64, 
    pub sequence_number: u64,
    // 考虑添加 pub next_view_number: u64, 
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 新试图消息（待调整）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewView {
    pub view_number: u64,
    pub sequence_number: u64,
    // 考虑添加 pub next_view_number: u64, 
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 心跳消息（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hearbeat {
    pub view_number: u64,
    pub sequence_number: u64,
    pub node_id: u64,
    pub signature: Vec<u8>,
}

/// 同步请求消息（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub from_index: u64,
    pub to_index: u64,
}

/// 同步响应消息（fine）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub blocks: Vec<Block>,
}



// ---
/// PBFT 共识过程（待调整）
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

/// 存储 pbft 共识过程状态信息（待调整）
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
    // pub hashchain_of_unreceived_block: Vec<String>, // 待使用，用于从节点验证主节点发送区块正确性
    // pub proof_of_latest_replication_state: Vec<Commit>, // 待使用，用于主节点向从节点证明区块链正确性
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
