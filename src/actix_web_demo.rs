use super::*;
use super::utils::*;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};

struct AppState {
    local_udp_socket: Arc<UdpSocket>, 
    node_info: Arc<NodeInfo>, 
    replication_state: Arc<Mutex<ReplicationState>>,
}

// 实现 RESTful API 路由配置
fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // 获取最新区块
        .route("/last", web::get().to(get_last_block))
        // 获取单个索引区块
        .route("/block/{index}", web::get().to(get_block))
        // 创建新区块
        .route("/block", web::post().to(create_block));
}

// 以下是各个 endpoint 的处理函数框架
// GET /block
async fn get_last_block(data: web::Data<AppState>) -> impl Responder {
    // 这里应返回全部区块数据
    let replication_state = data.replication_state.lock().await; 
    let found_block = replication_state.last_block();
    println!("{:?}", found_block);
    HttpResponse::Ok().json(&found_block)
}

// GET /block/{index}
async fn get_block(
    index: web::Path<u64>,
    data: web::Data<AppState>,
) -> impl Responder {
    // 根据 index 查找区块
    // let found_block = ReplicationState::load_block_by_index(&format!("config/node_{}/state.json", data.node_info.local_node_id), *index as usize).await;
    let replication_state = data.replication_state.lock().await; 
    let found_block = replication_state.rocksdb.get_last_block().unwrap();
    match found_block {
        Some(block) => {
            println!("{:?}", block);
            HttpResponse::Ok().json(&block)
        },
        None => {
            println!("查无区块{:?}", index);
            HttpResponse::NotFound().body("Block not found")
        }
    }
}

// POST /block
async fn create_block(
    operation: web::Json<Operation>,
    data: web::Data<AppState>,
) -> impl Responder {
    let mut request = Request {
        operation: operation.into_inner(),
        timestamp: get_current_timestamp(),
        node_id: data.node_info.local_node_id,
        signature: Vec::new(),
    };
    sign_request(&data.node_info.private_key, &mut request);
    let multicast_addr = "224.0.0.88:8888";
    // println!("发送多播数据");
    send_udp_data(
        &data.local_udp_socket,
        &multicast_addr.parse().unwrap(),
        MessageType::Request,
        serde_json::to_string(&request).unwrap().as_bytes(),
    ).await;
    HttpResponse::Created().json(true)
}

pub async fn actix_web_runweb_run(
    local_udp_socket: Arc<UdpSocket>, 
    node_info: Arc<NodeInfo>, 
    replication_state: Arc<Mutex<ReplicationState>>, 
) {
    // 初始化内存存储
    let app_state = web::Data::new(AppState {
        local_udp_socket: local_udp_socket,
        node_info: node_info,
        replication_state: replication_state,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .configure(configure_routes)
    })
    .bind("127.0.0.1:8080").unwrap()
    .run()
    .await.unwrap()
}






/*
curl http://localhost:8080/last

curl http://localhost:8080/block/index

curl -X POST http://localhost:8080/block \
  -H "Content-Type: application/json" \
  -d '"Operation1"'
*/
