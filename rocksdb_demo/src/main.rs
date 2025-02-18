


use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use rocksdb_demo::{Block, BlockStore, RocksDBBlockStore}; // 请替换your_crate_name为实际包名
use std::sync::Arc;


// 客户端请求结构体
#[derive(Debug, Deserialize)]
struct BlockRequest {
    operations: Vec<String>,
}



// 应用程序状态
struct AppState {
    block_store: Arc<RocksDBBlockStore>,
}

// 查询参数结构
#[derive(Debug, Deserialize)]
struct RangeQuery {
    start: u64,
    end: u64,
}

// 获取单个区块
async fn get_block(
    data: web::Data<AppState>,
    index: web::Path<u64>,
) -> impl Responder {
    match data.block_store.get_block_by_index(*index) {
        Ok(Some(block)) => HttpResponse::Ok().json(block),
        Ok(None) => HttpResponse::NotFound().body("Block not found"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// 获取最后一个区块
async fn get_last_block(data: web::Data<AppState>) -> impl Responder {
    match data.block_store.get_last_block() {
        Ok(Some(block)) => HttpResponse::Ok().json(block),
        Ok(None) => HttpResponse::NotFound().body("No blocks found"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// 获取范围内的区块
async fn get_blocks_range(
    data: web::Data<AppState>,
    query: web::Query<RangeQuery>,
) -> impl Responder {
    match data.block_store.get_blocks_in_range(query.start, query.end) {
        Ok(Some(blocks)) => HttpResponse::Ok().json(blocks),
        Ok(None) => HttpResponse::NotFound().body("No blocks in range"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// 创建新区块
async fn create_block(
    data: web::Data<AppState>,
    block: web::Json<Block>,
) -> impl Responder {
    match data.block_store.put_block(&block.into_inner()) {
        Ok(()) => HttpResponse::Created().body("Block created"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    // 初始化数据库并用 Arc 包装
    let block_store = Arc::new(
        RocksDBBlockStore::new("./blocks_db")
            .expect("Failed to initialize database")
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                block_store: Arc::clone(&block_store),
            }))
            .service(
                web::scope("/blocks")
                    .route("", web::post().to(create_block))
                    .route("/last", web::get().to(get_last_block))
                    .route("/{index}", web::get().to(get_block))
                    .route("", web::get().to(get_blocks_range)),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
