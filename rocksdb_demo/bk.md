```rust
use rocksdb_demo::{Block, BlockStore, RocksDBBlockStore};

fn main() {
    let path = "rocksdb";
    let block_store = RocksDBBlockStore::new(path).unwrap();
    
    let block = Block {
        index: 2,
        timestamp: 0,
        operations: vec!["Hello, world!".to_string()],
        previous_hash: String::new(),
        hash: String::new(),
    };
    block_store.put_block(&block).unwrap();
    let block = Block {
        index: 3,
        timestamp: 0,
        operations: vec!["Hello, world!".to_string()],
        previous_hash: String::new(),
        hash: String::new(),
    };
    block_store.put_block(&block).unwrap();

    let block = block_store.get_last_block().unwrap();
    println!("{:?}", block);

    let block = block_store.get_block_by_index(0).unwrap();
    println!("{:?}", block);
    
    let blocks = block_store.get_blocks_in_range(0,  3).unwrap();
    println!("{:?}", blocks);
}
```