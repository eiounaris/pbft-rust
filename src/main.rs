#[tokio::main]
async fn main() {
    if let Ok((
        local_udp_socket, 
        node_info, 
        multicast_nodes_addr, 
        replication_state, 
        pbft_state, 
        tx, 
        rx
    )) = pbft::utils::init().await {

        // 启动节点时确定主节点
        tokio::spawn({
            let local_udp_socket = local_udp_socket.clone();
            let node_info = node_info.clone();
            let multicast_nodes_addr = multicast_nodes_addr.clone();
            let pbft_state = pbft_state.clone();
            async move {
                pbft::utils::determining_primary_node(local_udp_socket, &node_info, &multicast_nodes_addr, pbft_state).await;
            }
        });

        // 启动主节点定时心跳任务
        let primary_heartbeat_task = tokio::spawn({
            let local_udp_socket = local_udp_socket.clone();
            let node_info = node_info.clone();
            let multicast_nodes_addr = multicast_nodes_addr.clone();
            let pbft_state = pbft_state.clone();
            async move {
                pbft::utils::primary_heartbeat(local_udp_socket, &node_info, &multicast_nodes_addr, pbft_state).await;
            }
        });

        // 启动从节点定时试图切换任务
        let view_change_task = tokio::spawn({
            let local_udp_socket = local_udp_socket.clone();
            let node_info = node_info.clone();
            let multicast_nodes_addr = multicast_nodes_addr.clone();
            let pbft_state = pbft_state.clone();
            async move {
                pbft::utils::view_change(local_udp_socket, &node_info, &multicast_nodes_addr, pbft_state, rx).await;
            }
        });

        // 启动命令发送任务
        let send_task = tokio::spawn({
            let local_udp_socket = local_udp_socket.clone();
            let node_info = node_info.clone();
            let multicast_nodes_addr = multicast_nodes_addr.clone();
            async move {
                pbft::utils::send_message(local_udp_socket, &node_info, &multicast_nodes_addr).await;
            }
        });
    
        // 启动消息接收处理任务
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

        // 等待所有任务执行完毕
        tokio::try_join!(send_task, recv_task, view_change_task, primary_heartbeat_task).unwrap();
    };
}
