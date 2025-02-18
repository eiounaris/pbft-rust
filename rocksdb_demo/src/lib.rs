// src/lib.rs
use rocksdb::{DB, IteratorMode, Direction};
use serde::{Serialize, Deserialize};
use bincode;
use std::error::Error;
use std::convert::TryInto;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
/// 区块结构体
#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub operations: Vec<String>,
    pub previous_hash: String,
    pub hash: String,
}

/// `BlockStore` trait 定义数据库操作接口
pub trait BlockStore {
    fn put_block(&self, block: &Block) -> Result<(), Box<dyn Error>>;
    fn get_block_by_index(&self, index: u64) -> Result<Option<Block>, Box<dyn Error>>;
    fn get_last_block(&self) -> Result<Option<Block>, Box<dyn Error>>;
    fn get_blocks_in_range(&self, begin_index: u64, end_index: u64) -> Result<Option<Vec<Block>>, Box<dyn Error>>;
    fn create_block(&self, operations: &[String]) -> Result<Option<Block>, Box<dyn Error>>;
}
/// 使用 RocksDB 实现 `BlockStore` trait
pub struct RocksDBBlockStore {
    db: DB,
}

impl RocksDBBlockStore {
    pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
        let db = DB::open_default(path)?;
        Ok(Self { db })
    }
}

impl BlockStore for RocksDBBlockStore {
    fn put_block(&self, block: &Block) -> Result<(), Box<dyn Error>> {
        let serialized = bincode::serialize(block)?;
        
        // 存储区块数据
        self.db.put(block.index.to_le_bytes(), serialized)?;

        // 更新 last_block_index，如果当前区块的 index 更大
        let last_block_index_key = b"last_block_index";
        match self.db.get(last_block_index_key)? {
            Some(last_index_bytes) => {
                let last_index: u64 = u64::from_le_bytes(last_index_bytes.try_into().expect("字节切片长度不足"));
                if block.index > last_index {
                    self.db.put(last_block_index_key, block.index.to_le_bytes())?;
                }
            },
            None => {
                // 如果没有 last_block_index 键，说明是第一次插入
                self.db.put(last_block_index_key, block.index.to_le_bytes())?;
            }
        }

        Ok(())
    }

    fn get_block_by_index(&self, index: u64) -> Result<Option<Block>, Box<dyn Error>> {
        let key = index.to_le_bytes();
        if let Some(value) = self.db.get(key)? {
            let block: Block = bincode::deserialize(&value)?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    fn get_last_block(&self) -> Result<Option<Block>, Box<dyn Error>> {
        let last_block_index_key = b"last_block_index";

        // 获取 last_block_index
        if let Some(last_index_bytes) = self.db.get(last_block_index_key)? {
            let last_index: u64 = u64::from_le_bytes(last_index_bytes.try_into().expect("字节切片长度不足"));
            // 通过 last_block_index 查找区块
            self.get_block_by_index(last_index)
        } else {
            // 如果没有找到 last_block_index，说明没有区块
            Ok(None)
        }
    }

    fn get_blocks_in_range(&self, begin_index: u64, end_index: u64) -> Result<Option<Vec<Block>>, Box<dyn Error>> {
        let mut iter = self.db.iterator(IteratorMode::From(&begin_index.to_le_bytes(), Direction::Forward));
        let mut blocks = Vec::new();
        while let Some(Ok((key, value))) = iter.next() {
            // 跳过长度不为8的键（非区块索引）
            if key.len() != 8 {
                continue;
            }
            // 安全转换为u64
            let index_bytes: [u8; 8] = key.as_ref().try_into()?;
            let index = u64::from_le_bytes(index_bytes);
            if index > end_index {
                break;
            }
            let block = bincode::deserialize(&value)?;
            blocks.push(block);
        }
        Ok(Some(blocks))
    }

    fn create_block(&self, operations: &[String]) -> Result<Option<Block>, Box<dyn Error>> {
        // 获取当前时间戳
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    
        // 获取最后一个区块
        let last_block = match self.get_last_block() {
            Ok(Some(block)) => block,
            Ok(None) => {
                // 创世区块处理
                let index = 0;
                let previous_hash = "genesis".to_string();
                let hash = calculate_hash(
                    index,
                    timestamp,
                    &operations,
                    &previous_hash
                );
    
                let genesis_block = Block {
                    index,
                    timestamp,
                    operations: operations.clone().to_vec(),
                    previous_hash,
                    hash,
                };
    
                self.put_block(&genesis_block)?;
            }
            Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
        };
    
        // 生成新区块
        let index = last_block.index + 1;
        let previous_hash = last_block.hash;
        let hash = calculate_hash(
            index,
            timestamp,
            &req.operations,
            &previous_hash
        );
    
        let new_block = Block {
            index,
            timestamp,
            operations: req.operations.clone(),
            previous_hash,
            hash,
        };
    
        match store.put_block(&new_block) {
            Ok(()) => HttpResponse::Created().json(new_block),
            Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        }
    }
    
    
}



// 计算区块哈希的函数
fn calculate_hash(index: u64, timestamp: u64, operations: &[String], previous_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(index.to_le_bytes());
    hasher.update(timestamp.to_le_bytes());
    for op in operations {
        hasher.update(op.as_bytes());
    }
    hasher.update(previous_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

