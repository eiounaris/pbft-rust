#[tokio::main]
async fn main() {
    if let Ok((local_udp_socket, node_info, multicast_nodes_addr, replication_state, pbft_state)) = pbft::utils::init().await {
        use tokio::time::{interval, Duration};
        use tokio::sync::mpsc;
        use tokio::task;
        
        // 创建一个通道用于发送重置信号
        let (tx, mut rx) = mpsc::channel(1);

        // 启动定时任务，定时任务使用 `Interval`
        let interval_task = task::spawn({
            let local_udp_socket = local_udp_socket.clone();
            let node_info = node_info.clone();
            let multicast_nodes_addr = multicast_nodes_addr.clone();
            let pbft_state = pbft_state.clone();
            async move {
                let mut interval = interval(Duration::from_secs(10));
                interval.reset(); // 确保 interval 不会立即执行
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let mut pbft_state = pbft_state.lock().await;
                            let mut view_change = pbft::ViewChange {
                                view_number: pbft_state.sended_view_number + 1,
                                sequence_number: pbft_state.sequence_number,
                                node_id: node_info.local_node_id,
                                signature: Vec::new(),
                            };
                            pbft::utils::sign_view_change(&node_info.private_key, &mut view_change);
                            println!("\n发送 view change 消息(view_number: {})", pbft_state.sended_view_number + 1);
                            pbft_state.view_change_mutiple_set.entry(view_change.view_number).or_insert(std::collections::HashSet::new()).insert(node_info.local_node_id);
                            for node_addr in multicast_nodes_addr.iter() {
                                pbft::utils::send_udp_data(&local_udp_socket, &node_addr, pbft::MessageType::ViewChange, serde_json::to_string(&view_change).unwrap().as_bytes()).await;
                            }
                            pbft_state.sended_view_number += 1;
                        }
                        _ = rx.recv() => {
                            // 收到重置信号时，重置定时器
                            interval.reset(); // 使用 `reset` 来重置定时器
                        }
                    }
                }
            }
        });

        // // 模拟其他异步任务向定时器发送重置信号
        // tokio::spawn(async move {
        //     loop {
        //         tokio::time::sleep(Duration::from_secs(5)).await;
        //         println!("Sending reset signal...");
        //         tx.send(()).await.unwrap(); // 发送重置信号

        //         tokio::time::sleep(Duration::from_secs(2)).await;
        //         println!("Sending another reset signal...");
        //         tx.send(()).await.unwrap(); // 再次发送重置信号
        //     }
        // });

        // 启动发送任务
        let send_task = tokio::spawn({
            let local_udp_socket = local_udp_socket.clone();
            let node_info = node_info.clone();
            let multicast_nodes_addr = multicast_nodes_addr.clone();
            async move {
                pbft::utils::send_message(local_udp_socket, &node_info, &multicast_nodes_addr).await;
            }
        });
    
        // 启动接收任务
        let recv_task: tokio::task::JoinHandle<()> = tokio::spawn({
            let local_udp_socket = local_udp_socket.clone();
            let node_info = node_info.clone();
            let multicast_nodes_addr = multicast_nodes_addr.clone();
            let replication_state = replication_state.clone();
            let pbft_state = pbft_state.clone();
            async move {
                pbft::utils::handle_message(local_udp_socket, &node_info,  &multicast_nodes_addr, replication_state, pbft_state, tx).await;
            }
        });

        tokio::try_join!(send_task, recv_task, interval_task).unwrap();
    };
}