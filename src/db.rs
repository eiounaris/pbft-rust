use super::*;
use super::utils::*;

use rocksdb::{DB, IteratorMode, Direction};
use bincode;
use std::error::Error;
use std::convert::TryInto;


/// `BlockStore` trait 定义数据库操作接口
pub trait BlockStore {
    fn put_block(&self, block: &Block) -> Result<(), Box<dyn Error>>;
    fn get_block_by_index(&self, index: u64) -> Result<Option<Block>, Box<dyn Error>>;
    fn get_last_block(&self) -> Result<Option<Block>, Box<dyn Error>>;
    fn get_blocks_in_range(&self, begin_index: u64, end_index: u64) -> Result<Option<Vec<Block>>, Box<dyn Error>>;
    fn create_block(&self, operations: &Vec<Operation>) -> Result<Option<Block>, Box<dyn Error>>;
}


/// 使用 RocksDB 实现 `BlockStore` trait
pub struct RocksDBBlockStore {
    db: DB,
}

impl RocksDBBlockStore {
    pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
        let db = DB::open_default(path)?;
        
        let last_block_index_key = b"last_block_index";
        if let None = db.get(last_block_index_key)? {
            // 创建创世区块
            let index = 0;
            let timestamp = get_current_timestamp();
            let previous_hash = "genesis".to_string();
            let hash = "genesis".to_string();
            let genesis_block = Block {
                index,
                timestamp,
                operations: Vec::new(),
                previous_hash,
                hash,
            };
            // 存储区块数据,  更新 last_block_index
            let mut batch = rocksdb::WriteBatch::default();
            batch.put(genesis_block.index.to_le_bytes(), bincode::serialize(&genesis_block)?);
            batch.put(last_block_index_key, genesis_block.index.to_le_bytes());
            db.write(batch)?;
        }
        Ok(Self{db})
    }
}

impl BlockStore for RocksDBBlockStore {
    fn put_block(&self, block: &Block) -> Result<(), Box<dyn Error>> {
        if let Ok(Some(old_block)) =  self.get_last_block() {
            if old_block.index + 1 == block.index && old_block.hash == block.previous_hash {
                // 存储区块数据,  更新 last_block_index
                let mut batch = rocksdb::WriteBatch::default();
                batch.put(block.index.to_le_bytes(), bincode::serialize(block)?);
                batch.put(b"last_block_index", block.index.to_le_bytes());
                self.db.write(batch)?;
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
        if let Some(last_index_bytes) = self.db.get(last_block_index_key)? {
            let last_index: u64 = u64::from_le_bytes(last_index_bytes.try_into().expect("字节切片长度不足"));
            self.get_block_by_index(last_index)
        } else {
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

    fn create_block(&self, operations: &Vec<Operation>) -> Result<Option<Block>, Box<dyn Error>> {
        if let Ok(Some(last_block)) = self.get_last_block() {
            // 生成新区块
            let index = last_block.index + 1;
            let timestamp = get_current_timestamp();
            let previous_hash = last_block.hash;
            let hash = create_block_hash(index, timestamp, operations, &previous_hash);
        
            let new_block = Block {
                index,
                timestamp,
                operations: operations.clone(),
                previous_hash,
                hash,
            };
        
            Ok(Some(new_block))
        } else {
            Ok(None)
        }
    }
}

