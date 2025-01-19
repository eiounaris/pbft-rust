#![allow(dead_code, unused_variables)]

use pbft::*;
use tokio::sync::Mutex; // 待改进，采用读写锁。tokio::sync::RwLock
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tokio::sync::mpsc;
use tokio::task;
#[tokio::main]
async fn main() {
    // 解析命令行参数
    let env_args: Vec<String> = std::env::args().collect();
    if env_args.len() != 3 {
        eprintln!("\n参数错误，正确用法应为：{} -- node_id nodes_config_path\n", env_args[0]);
        std::process::exit(1);
    }

    // 获取节点 id
    let self_node_id: u64 = env_args[1].parse().expect("\n输入的node_id不是数字");

    // 从配置文件读取节点配置信息
    let nodes_config_path = &env_args[2];
    let nodes_config_json = std::fs::read_to_string(nodes_config_path).unwrap();
    let node_configs: Vec<NodeConfig> = serde_json::from_str(&nodes_config_json).unwrap();
    
    // 查找自身节点配置
    let self_node: &NodeConfig = node_configs.iter().find(|node| (**node).node_id == self_node_id).expect("\n输入的node_id不在节点配置文件中");
    let local_addr_string = format!("{}:{}", self_node.ip, self_node.port);
    let private_key = load_private_key_from_file(&format!("config/node_{}/private_key.pem", self_node_id));
    let public_key = load_public_key_from_file(&format!("config/node_{}/public_key.pem", self_node_id));
    
    // 创建一个节点列表，包含所有其他节点的套接字地址
    let target_nodes_addr: Vec<std::net::SocketAddr> = node_configs.iter()
        .filter(|node| (**node).node_id != self_node_id)
        .map(|node| {
            format!("{}:{}", node.ip, node.port)
                .parse()
                .expect("\n节点配置文件中包含无效的节点地址")
        })
        .collect();
    let target_nodes_addr = Arc::new(target_nodes_addr);

    // 打印节点初始化提示信息
    println!("\n节点 {} 启动，绑定到地址：{}", self_node_id, local_addr_string);
    
    // 创建本地 UDP 异步套接字
    let socket = Arc::new(tokio::net::UdpSocket::bind(&local_addr_string).await.expect("\n创建本地节点套接字失败"));

    
    // 初始化节点信息
    let node_info = NodeInfo::new(
        self_node_id,
        local_addr_string.clone(),
        private_key.clone(),
        public_key.clone(), 
        node_configs,
    );
    let node_info = Arc::new(node_info);


    let replication_state: ReplicationState;
    if let Some(block) = ReplicationState::load_last_block_from_file(&format!("config/node_{}/replication_state.json", self_node_id)).await {
        replication_state = ReplicationState {
            blockchain: vec![block],
            operation_buffer: Vec::new(),
        };
    } else {
        replication_state = ReplicationState::new();
    }
    let replication_state = Arc::new(Mutex::new(replication_state));


    let pbft_state = PbftState::new(
        0, // 待改进，采用动态视图。
        replication_state.lock().await.last_block().unwrap().index, 
        node_info.nodes.len() as u64
    );
    let pbft_state = Arc::new(Mutex::new(pbft_state));

    // 启动发送任务
    let send_task = tokio::spawn({
        let socket = Arc::clone(&socket);
        let node_info = Arc::clone(&node_info);
        let target_nodes = Arc::clone(&target_nodes_addr);
        let pbft_state = pbft_state.clone();
        async move {
            send_message(&node_info, &target_nodes, socket, pbft_state).await;
        }
    });

    // 启动接收任务
    let recv_task: tokio::task::JoinHandle<()> = tokio::spawn({
        let socket = Arc::clone(&socket);
        let node_info = Arc::clone(&node_info);
        let target_nodes = Arc::clone(&target_nodes_addr);
        let replication_state = replication_state.clone();
        let pbft_state = pbft_state.clone();
        async move {
            handle_message(socket, &node_info,  &target_nodes, replication_state, pbft_state).await;
        }
    });


    
    // 创建一个通道用于发送重置信号
    let (tx, mut rx) = mpsc::channel(1);

    // 启动定时任务，定时任务使用 `Interval`
    let interval_task = task::spawn(async move {
        let mut interval = interval(Duration::from_secs(3));
        // 等待一段时间，确保 interval 不会立即执行
        interval.reset();
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    println!("Interval tick!");
                }
                _ = rx.recv() => {
                    // 收到重置信号时，重置定时器
                    println!("Interval reset!");
                    interval.reset(); // 使用 `reset` 来重置定时器
                }
            }
        }
    });

    // 模拟其他异步任务向定时器发送重置信号
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!("Sending reset signal...");
            tx.send(()).await.unwrap(); // 发送重置信号

            tokio::time::sleep(Duration::from_secs(2)).await;
            println!("Sending another reset signal...");
            tx.send(()).await.unwrap(); // 再次发送重置信号
        }
    });


    tokio::try_join!(send_task, recv_task).unwrap();
}