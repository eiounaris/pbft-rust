#![allow(dead_code)]

mod pbft;
use pbft::*;
use tokio::{ net::UdpSocket, sync::Mutex }; // 待改进，采用读写锁。
use std::{ fs, env, sync::Arc, net::SocketAddr };

#[tokio::main]
async fn main() {
    // 解析命令行参数
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("\n用法：cargo run -- node_id config_path\n");
        std::process::exit(1);
    }

    // 从配置文件读取节点配置信息
    let config_path = &args[2];
    let config_content = fs::read_to_string(config_path).unwrap();
    let nodes: Vec<NodeConfigWithRsaPublickey> = serde_json::from_str(&config_content).unwrap();
    

    // 获取节点 id
    let node_id: u64 = args[1].parse().unwrap();

    // 查找自身节点配置
    let self_node = nodes.iter().find(|node| node.node_id == node_id).unwrap();
    let local_addr = format!("{}:{}", self_node.ip, self_node.port);
    let private_key = load_private_key_from_file(&format!("config/node_{}/private_key.pem", node_id));
    let public_key = load_public_key_from_file(&format!("config/node_{}/public_key.pem", node_id));
    
    // 创建一个节点列表，包含所有其他节点的套接字地址
    let target_nodes: Vec<SocketAddr> = nodes.iter()
        .filter(|node| node.node_id != node_id)
        .map(|node| {
            format!("{}:{}", node.ip, node.port)
                .parse()
                .expect("\n无效的目标地址")
        })
        .collect();
    let target_nodes = Arc::new(target_nodes);

    // 打印节点初始化提示信息
    println!("\n节点 {} 启动，绑定到地址：{}", node_id, local_addr);
    
    // 绑定本地 UDP 套接字
    let socket = UdpSocket::bind(&local_addr).await.unwrap();
    let socket = Arc::new(socket);

    

    let node_info = NodeInfo::new(
        node_id,
        node_id == 1, // 待改进，采用动态试图。
        local_addr.clone(),
        private_key.clone(),
        public_key.clone(), 
        nodes,
    );
    let node_info = Arc::new(node_info);


    let blockchain: Blockchain;
    if let Some(block) = Blockchain::load_last_block_from_file(&format!("config/node_{}/blockchain.json", node_id)).await {
        blockchain = Blockchain {
            blockchain: vec![block],
            transaction_pool: Vec::new(),
        }
    } else {
        blockchain = Blockchain::new()
    }
    let blockchain = Arc::new(Mutex::new(blockchain));


    let pbft_state = PbftState::new(
        1, // 待改进，采用动态视图。
        blockchain.lock().await.last_block().unwrap().index, 
        node_info.nodes.len() as u64
    );
    let pbft_state = Arc::new(Mutex::new(pbft_state));

    // 启动发送任务
    let send_task = tokio::spawn({
        let socket = Arc::clone(&socket);
        let node_info = Arc::clone(&node_info);
        let target_nodes = Arc::clone(&target_nodes);
        let pbft_state = pbft_state.clone();
        async move {
            send_message(&node_info, &target_nodes, socket, pbft_state).await;
        }
    });

    // 启动接收任务
    let recv_task: tokio::task::JoinHandle<()> = tokio::spawn({
        let socket = Arc::clone(&socket);
        let node_info = Arc::clone(&node_info);
        let target_nodes = Arc::clone(&target_nodes);
        let blockchain = blockchain.clone();
        let pbft_state = pbft_state.clone();
        async move {
            receive_message(socket, &node_info, blockchain, &target_nodes, pbft_state).await;
        }
    });

    tokio::try_join!(send_task, recv_task).unwrap();
}

