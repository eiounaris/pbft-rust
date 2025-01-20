#[tokio::main]
async fn main() {
    if let Ok((udp_socket, node_info, multicast_nodes_addr, replication_state, pbft_state)) = pbft::init().await {
        // 启动发送任务
        let send_task = tokio::spawn({
            let udp_socket = udp_socket.clone();
            let node_info = node_info.clone();
            let multicast_nodes_addr = multicast_nodes_addr.clone();
            async move {
                pbft::send_message(udp_socket, &node_info, &multicast_nodes_addr).await;
            }
        });
    
        // 启动接收任务
        let recv_task: tokio::task::JoinHandle<()> = tokio::spawn({
            let udp_socket = udp_socket.clone();
            let node_info = node_info.clone();
            let multicast_nodes_addr = multicast_nodes_addr.clone();
            let replication_state = replication_state.clone();
            let pbft_state = pbft_state.clone();
            async move {
                pbft::handle_message(udp_socket, &node_info,  &multicast_nodes_addr, replication_state, pbft_state).await;
            }
        });

        tokio::try_join!(send_task, recv_task).unwrap();
    };
    {
        // use tokio::time::{interval, Duration};
        // use tokio::sync::mpsc;
        // use tokio::task;
        
        // // 创建一个通道用于发送重置信号
        // let (tx, mut rx) = mpsc::channel(1);

        // // 启动定时任务，定时任务使用 `Interval`
        // let interval_task = task::spawn(async move {
        //     let mut interval = interval(Duration::from_secs(3));
        //     // 等待一段时间，确保 interval 不会立即执行
        //     interval.reset();
        //     loop {
        //         tokio::select! {
        //             _ = interval.tick() => {
        //                 println!("Interval tick!");
        //             }
        //             _ = rx.recv() => {
        //                 // 收到重置信号时，重置定时器
        //                 println!("Interval reset!");
        //                 interval.reset(); // 使用 `reset` 来重置定时器
        //             }
        //         }
        //     }
        // });

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
        
        // tokio::try_join!(send_task, recv_task, interval_task).unwrap();
    } 
}