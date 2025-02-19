use crate::*;

// ---

/// 计算区块哈希
pub fn create_block_hash(index: u64, _timestamp: u64, operations: &Vec<Operation>, previous_hash: &str) -> String {
    let block_json_string = serde_json::to_string(&(index, &operations, &previous_hash)).unwrap(); // (这里暂时没使用时间戳，后续改进）
    let mut hasher = Sha256::new();
    hasher.update(block_json_string);
    format!("{:x}", hasher.finalize())
}

// ---

/// 加载时间戳
pub fn get_current_timestamp() -> u64 {
    let start = SystemTime::now();
    let since_epoch = start
        .duration_since(UNIX_EPOCH)
        .unwrap();
    since_epoch.as_secs()
}

// ---

/// 从文件加载私钥（错误处理待改进）
pub fn load_private_key_from_file(file_path: &str) -> RsaPrivateKey {
    let mut file = File::open(file_path).unwrap();
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read private key file");
    RsaPrivateKey::from_pkcs1_pem(&pem).expect("Failed to decode private key")
}

/// 从文件加载公钥（错误处理待改进）
pub fn load_public_key_from_file(file_path: &str) -> RsaPublicKey {
    let mut file = File::open(file_path).expect("Failed to open public key file");
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read public key file");
    RsaPublicKey::from_pkcs1_pem(&pem).expect("Failed to decode public key")
}

// ---

/// 使用私钥签名数据
fn sign_data(private_key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(data);  // 对原始数据进行 SHA-256 哈希
    // 使用私钥和哈希数据签名
    private_key.sign(Pkcs1v15Sign::new::<Sha256>(), &hashed_data).expect("failed to sign data")
}
/// 使用公钥验证签名
fn _verify_signature(pub_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(data);  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 签名请求消息
pub fn sign_request(priv_key: &RsaPrivateKey, request: &mut Request) {
    request.signature = sign_data(priv_key, serde_json::to_string(&request).unwrap().as_bytes());
}
/// 验证请求消息
pub fn verify_request(pub_key: &RsaPublicKey, request: &Request, signature: &[u8]) -> bool {
    let mut request = request.clone();
    request.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&request).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 签名预准备消息
pub fn sign_pre_prepare(priv_key: &RsaPrivateKey, pre_prepare: &mut PrePrepare) {
    pre_prepare.signature = sign_data(priv_key, serde_json::to_string(&pre_prepare).unwrap().as_bytes());
}
/// 验证预准备消息
pub fn verify_pre_prepare(pub_key: &RsaPublicKey, pre_prepare: & PrePrepare, signature: &[u8]) -> bool {
    let mut pre_prepare = pre_prepare.clone();
    pre_prepare.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&pre_prepare).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 签名准备消息
pub fn sign_prepare(priv_key: &RsaPrivateKey, prepare: &mut Prepare) {
    prepare.signature=sign_data(priv_key, serde_json::to_string(&prepare).unwrap().as_bytes());
}
/// 验证准备消息
pub fn verify_prepare(pub_key: &RsaPublicKey, prepare: & Prepare, signature: &[u8]) -> bool {
    let mut prepare = prepare.clone();
    prepare.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&prepare).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 签名提交消息
pub fn sign_commit(priv_key: &RsaPrivateKey, commit: &mut Commit) {
    commit.signature=sign_data(priv_key, serde_json::to_string(&commit).unwrap().as_bytes());
}
/// 验证提交消息
pub fn verify_commit(pub_key: &RsaPublicKey, commit: & Commit, signature: &[u8]) -> bool {
    let mut commit = commit.clone();
    commit.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&commit).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 签名试图切换消息
pub fn sign_view_change(priv_key: &RsaPrivateKey, view_change: &mut ViewChange) {
    view_change.signature=sign_data(priv_key, serde_json::to_string(&view_change).unwrap().as_bytes());
}
/// 验证图切换消息
pub fn verify_view_change(pub_key: &RsaPublicKey, view_change: & ViewChange, signature: &[u8]) -> bool {
    let mut view_change = view_change.clone();
    view_change.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&view_change).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

/// 签名新视图消息
pub fn sign_new_view(priv_key: &RsaPrivateKey, new_view: &mut NewView) {
    new_view.signature=sign_data(priv_key, serde_json::to_string(&new_view).unwrap().as_bytes());
}
/// 验证新视图消息
pub fn verify_new_view(pub_key: &RsaPublicKey, new_view: & NewView, signature: &[u8]) -> bool {
    let mut new_view = new_view.clone();
    new_view.signature = Vec::new();
    // 对数据进行哈希（SHA256）
    let hashed_data = Sha256::digest(serde_json::to_string(&new_view).unwrap().as_bytes());  // 对原始数据进行 SHA-256 哈希
    // 使用公钥和哈希数据验证签名
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_data, &signature[..]).is_ok()
}

// ---

// 发送UDP数据
pub async fn send_udp_data(local_udp_socket: &UdpSocket, target_udp_socket: &SocketAddr, message_type: MessageType, content: &[u8]) {
    // 生成消息的字节数组，先是类型字节，然后是消息内容的字节
    let mut message = Vec::new();
    message.push(message_type as u8);  // 将类型作为第一个字节
    message.extend_from_slice(&content);  // 将内容附加到字节数组后面
    // 发送消息
    local_udp_socket.send_to(&message, target_udp_socket).await.unwrap();
}

// ---

/// RsaPublicKey 序列化函数
pub fn serialize_public_key<S>(public_key: &RsaPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let pem = public_key.to_pkcs1_pem(LineEnding::default()).expect("Failed to convert public key to PEM");
    serializer.serialize_str(&pem)
}

/// RsaPublicKey 反序列化函数
pub fn deserialize_public_key<'de, D>(deserializer: D) -> Result<RsaPublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let pem: String = Deserialize::deserialize(deserializer)?;
    RsaPublicKey::from_pkcs1_pem(&pem).map_err(serde::de::Error::custom)
}

// ---

impl ReplicationState {
    /// 初始化状态
    pub fn new() -> Self {
        ReplicationState {
            blockchain: vec![
                Block {
                    index:  0,
                    timestamp: get_current_timestamp(),
                    operations: Vec::new(),
                    previous_hash: String::new(),
                    hash: String::new(),
                }
            ],
            operation_buffer: Vec::new(),
            request_buffer: Vec::new(),
        } 
    }

    /// 返回最新区块
    pub fn last_block(&self) -> Option<&Block> {
        self.blockchain.last()
    }

    /// 添加区块到区块链
    pub fn add_block(&mut self, block: Block) -> bool {
        let last_block = self.last_block().unwrap();
        if block.previous_hash == last_block.hash && block.index == last_block.index + 1 {
            self.blockchain.push(block);
            true
        } else {
            false
        }
    }

    /// 添加请求消息中的操作请求到操作缓冲池，若操作缓冲池大于区块大小则创建区块链
    pub fn add_operations_of_requests(&mut self, requests: Vec<Request>) {
        for request in requests {
            self.operation_buffer.push(request.operation);
        }
        let new_block = self.create_block(self.operation_buffer.clone());
        self.operation_buffer.clear();
        self.add_block(new_block);
    }

    /// 添加待处理请求添加到请求缓冲池
    pub fn add_request(&mut self, request: Request) {
        self.request_buffer.push(request);
    }

    /// 根据操作集创建区块
    pub fn create_block(&self, operations: Vec<Operation>) -> Block {
        let (index, previous_hash) = if let Some(last_block) = self.last_block() {
            (last_block.index + 1, last_block.hash.clone())
        } else {
            (0, String::new())
        };
        let timestamp: u64 = get_current_timestamp();
        let hash = create_block_hash(index, timestamp, &operations, &previous_hash);

        let block = Block {
            index,
            timestamp,
            operations,
            previous_hash,
            hash,
        };
        block
    }

    /// 存储区块链到文件，并清除内存中最近未使用的所有区块
    pub async fn store_to_file(&mut self, file_path: &str) {
        let mut num: u64 = 0;
        if let Some(block) = ReplicationState::load_last_block_from_file(file_path).await {
            num = block.index + 1;
        }
        let mut file: File = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path).expect("存储区块链到文件失败");

        for block in &self.blockchain {
            if block.index >= num {
                let block = serde_json::to_string(&block).expect("区块反序列化失败");
                writeln!(file, "{}", block).unwrap();
            }
        }
        self.drain_blockchain();
    }

    /// 保留内存中最新一个区块
    pub fn drain_blockchain(&mut self) {
        self.blockchain.drain(..self.blockchain.len() - 1);
    }

    /// 异步读取文件的指定索引区块
    pub async fn load_block_by_index(file_path: &str, index: usize) -> Option<Block> {
        ReplicationState::load_block_by_line(file_path, index + 1).await
    }

    /// 异步读取文件的指定行号所对应区块
    pub async fn load_block_by_line(file_path: &str, line_number: usize) -> Option<Block> {
        // 尝试异步打开文件
        let file = match tokio::fs::File::open(file_path).await {
            Ok(f) => f,
            Err(_) => return None,
        };
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        // 行号从 1 开始
        let mut current_line = 1;
        // 异步遍历每一行
        while let Ok(Some(line)) = lines.next_line().await {
            if current_line == line_number {
                // 尝试将该行解析为 Block
                match serde_json::from_str::<Block>(&line) {
                    Ok(block) => return Some(block),
                    Err(e) => {
                        eprintln!("解析 JSON 失败: {}", e);
                        return None; // 解析失败，返回 None
                    }
                }
            }
            current_line += 1;
        }
        // 如果没有找到指定行，返回 None
        None
    }
    

    /// 异步读取文件的最后一行并构造区块
    pub async fn load_last_block_from_file(file_path: &str) -> Option<Block> {
        // 尝试异步打开文件
        let file = match tokio::fs::File::open(file_path).await {
            Ok(f) => f,
            Err(_) => {
                // eprintln!("文件路径{}不存在, 初始化区块链", file_path);
                return None; // 打开文件失败，返回 None
            }
        };
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut last_line: Option<String> = None;
        // 异步遍历每一行
        while let Ok(Some(line)) = lines.next_line().await {
            last_line = Some(line);
        }
        if let Some(line) = last_line {
            let block = serde_json::from_str(&line).expect("区块序反列化失败");
            Some(block)
        } else {
            None
        }
    }
}

// ---

impl Request {
    pub fn digest_requests(requests: &Vec<Request>) -> Vec<u8> {
        Sha256::digest(serde_json::to_string(requests).unwrap().as_bytes()).to_vec()
    }
}

// ---

impl PbftState {
    /// 初始化pbft共识状态
    pub fn new(
        view_number: u64,
        sequence_number: u64,
        nodes_number: u64
    ) -> Self {
        PbftState {
            view_number: view_number,
            sended_view_number: view_number,
            sequence_number: sequence_number,
            pbft_step: PbftStep::InIdle,
            start_time: get_current_timestamp(),
            nodes_number: nodes_number,
            preprepare: None,
            prepares: HashSet::new(),
            commits: HashSet::new(),
            view_change_mutiple_set: HashMap::new(),
        }
    }

    pub fn is_primarry(&self, local_node_id: u64) -> bool {
        self.view_number % self.nodes_number as u64 == local_node_id
    }
}

// ---

impl NodeInfo {
    /// 初始化构造函数
    pub fn new(
        local_node_id: u64,
        local_socket_addr: std::net::SocketAddr,
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey,
        node_configs: Vec<NodeConfig>,
    ) -> Self {
        NodeInfo {
            local_node_id,
            local_socket_addr,
            private_key,
            public_key,
            node_configs,
        }
    }

    pub fn is_primarry(&self, view_number: u64) -> bool {
        view_number % self.node_configs.len() as u64 == self.local_node_id
    }
}

// ---

/// 任务: 发送命令行指令数据（待修改为Restful API 供本机用户调用）
pub async fn send_message(udp_socket: Arc<UdpSocket>, node_info: &NodeInfo, _multicast_nodes_addr: &[SocketAddr]) {
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let mut request = Request {
            operation: Operation::Operation1,
            timestamp: get_current_timestamp(),
            node_id: node_info.local_node_id,
            signature: Vec::new(),
        };
        sign_request(&node_info.private_key, &mut request);
        // 发送消息到主节点（这里发送给了全部节点，待改进，从节点收到请求消息需要记录请求消息超时时间，然后发送视图切换消息）
        // for node_addr in _multicast_nodes_addr {
        //     send_udp_data(
        //         &udp_socket,
        //         node_addr,
        //         MessageType::Request,
        //         serde_json::to_string(&request).unwrap().as_bytes(),
        //     ).await;
        // }
        let multicast_addr = "224.0.0.88:8888";
        // println!("发送多播数据");
        send_udp_data(
            &udp_socket,
            &multicast_addr.parse().unwrap(),
            MessageType::Request,
            serde_json::to_string(&request).unwrap().as_bytes(),
        ).await;
    }
}


/// 任务: 接收并处理数据
pub async fn handle_message(
    local_udp_socket: Arc<UdpSocket>, 
    node_info: &NodeInfo, 
    multicast_nodes_addr: &[SocketAddr], 
    replication_state: Arc<Mutex<ReplicationState>>, 
    pbft_state: Arc<Mutex<PbftState>>,
    tx: mpsc::Sender<()>,
) {
    let mut buf = [0u8; 102400]; // （待修改，将数据存储到堆上）
    loop {
        let (udp_data_size, src_socket_addr) = local_udp_socket.recv_from(&mut buf).await.expect("udp数据报过大，缓冲区溢出");
        // 提取消息类型（第一个字节）
        let message_type = match buf[0] {
            0 => MessageType::Request,
            1 => MessageType::PrePrepare,
            2 => MessageType::Prepare,
            3 => MessageType::Commit,
            4 => MessageType::Reply,
            5 => MessageType::ViewChange,
            6 => MessageType::NewView,
            7 => MessageType::Hearbeat,
            9 => MessageType::DeterminingPrimaryNode,
            11 => MessageType::DeterminingLatestReplicationState,
            13 => MessageType::SyncRequest,
            14 => MessageType::SyncResponse,
            _ => {
                eprintln!("Reiceive unknown message type");
                continue;
            },
        };

        // 提取消息内容（剩余的字节）
        let content = buf[1..udp_data_size].to_vec(); // 转换为 Vec<u8>
        
        match message_type {
            // 处理请求消息
            MessageType::Request => {
                let mut pbft_state = pbft_state.lock().await;
                if node_info.is_primarry(pbft_state.view_number) {
                    if let Ok(request) = serde_json::from_slice::<Request>(&content) {
                        // 成功反序列化，继续处理
                        if verify_request(&node_info.node_configs[request.node_id as usize].public_key, &request, &request.signature) {
                            // println!("\n主节点接收到合法 Request 消息");
                            let mut replication_state = replication_state.lock().await;
                            replication_state.add_request(request.clone());
                            println!("\n请求缓冲大小: {:?}", replication_state.request_buffer.len());
                            if pbft_state.pbft_step != PbftStep::InIdle && (get_current_timestamp() - pbft_state.start_time > 1) {
                                pbft_state.pbft_step = PbftStep::InIdle;
                                pbft_state.preprepare = None;
                                pbft_state.prepares.clear();
                                pbft_state.commits.clear();
                            }
                            if pbft_state.pbft_step == PbftStep::InIdle {
                                if replication_state.request_buffer.len() >= BLOCK_SIZE {
                                    pbft_state.prepares.clear();
                                    pbft_state.commits.clear();
                                    let mut pre_prepare = PrePrepare {
                                        view_number: pbft_state.view_number,
                                        sequence_number: pbft_state.sequence_number + 1,
                                        node_id: node_info.local_node_id,
                                        digest: Request::digest_requests(&replication_state.request_buffer),
                                        signature: Vec::new(),
                                        requests: replication_state.request_buffer.clone(),
                                        proof_of_previous_hash: replication_state.last_block().unwrap().previous_hash.clone(),
                                    };
                                    
                                    sign_pre_prepare(&node_info.private_key, &mut pre_prepare);
                                    pbft_state.preprepare = Some(pre_prepare.clone());

                                    // println!("\n发送 PrePrepare 消息");
                                    // for node_addr in multicast_nodes_addr {
                                    //     send_udp_data(
                                    //         &local_udp_socket,
                                    //         node_addr,
                                    //         MessageType::PrePrepare,
                                    //         serde_json::to_string(&pre_prepare).unwrap().as_bytes(),
                                    //     ).await;
                                    // }
                                    let multicast_addr = "224.0.0.88:8888";
                                    // println!("发送多播数据");
                                    send_udp_data(
                                        &local_udp_socket,
                                        &multicast_addr.parse().unwrap(),
                                        MessageType::PrePrepare,
                                        serde_json::to_string(&request).unwrap().as_bytes(),
                                    ).await;
                                    
                                    pbft_state.pbft_step = PbftStep::ReceiveingPrepare;
                                }
                            }
                        }
                    } else {
                        // 反序列化失败，跳过当前循环
                        continue;
                    }                    
                } else {
                    // println!("\n备份节点接收到 Request 消息");
                    // 判断是否发起 view_change 消息
                }
            }
            // 处理预准备消息
            MessageType::PrePrepare => {
                let mut pbft_state = pbft_state.lock().await;
                if !node_info.is_primarry(pbft_state.view_number) {
                    // println!("\n备份节点接收到 PrePrepare 消息");
                    if pbft_state.pbft_step != PbftStep::InIdle && (get_current_timestamp() - pbft_state.start_time > 1) {
                        pbft_state.pbft_step = PbftStep::InIdle;
                        pbft_state.preprepare = None;
                        pbft_state.prepares.clear();
                        pbft_state.commits.clear();
                    }
                    if pbft_state.pbft_step == PbftStep::InIdle {
                        if let Ok(pre_prepare) = serde_json::from_slice::<PrePrepare>(&content) {
                            // 成功反序列化，继续处理
                            // println!("{} == {}?", pre_prepare.proof_of_previous_hash, replication_state.lock().await.last_block().unwrap().hash);
                            if verify_pre_prepare(&node_info.node_configs[pre_prepare.node_id as usize].public_key, &pre_prepare, &pre_prepare.signature) && pre_prepare.proof_of_previous_hash == replication_state.lock().await.last_block().unwrap().previous_hash {
                                tx.send(()).await.unwrap(); // 发送重置信号
                                pbft_state.preprepare = Some(pre_prepare.clone());
                                pbft_state.pbft_step = PbftStep::ReceiveingPrepare;
                                pbft_state.prepares.clear();
                                pbft_state.commits.clear();
    
                                let mut prepare = Prepare {
                                    view_number: pbft_state.view_number,
                                    sequence_number: pbft_state.sequence_number,
                                    digest: pre_prepare.digest,
                                    node_id: node_info.local_node_id,
                                    signature: Vec::new(),
                                };
            
                                sign_prepare(&node_info.private_key, &mut prepare);
            
                                // println!("\n发送 prepare 消息");
                                // for target_addr in multicast_nodes_addr {
                                //     send_udp_data(
                                //         &local_udp_socket,
                                //         target_addr,
                                //         MessageType::Prepare,
                                //         serde_json::to_string(&prepare).unwrap().as_bytes(),
                                //     ).await;
                                // }
                                let multicast_addr = "224.0.0.88:8888";
                                    // println!("发送多播数据");
                                    send_udp_data(
                                        &local_udp_socket,
                                        &multicast_addr.parse().unwrap(),
                                        MessageType::Prepare,
                                        serde_json::to_string(&prepare).unwrap().as_bytes(),
                                    ).await;
            
                                pbft_state.prepares.insert(node_info.local_node_id);
                                
                                
                                if pbft_state.prepares.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) {
                                    // println!("\n发送commit消息");
            
                                    pbft_state.pbft_step = PbftStep::ReceiveingCommit;
            
                                    let mut commit = Commit {
                                        view_number: pbft_state.view_number,
                                        sequence_number: pbft_state.sequence_number,
                                        digest: prepare.digest,
                                        node_id: node_info.local_node_id,
                                        signature: Vec::new(),
                                    };
            
                                    sign_commit(&node_info.private_key, &mut commit);
            
                                    // for target_addr in multicast_nodes_addr {
                                    //     send_udp_data(
                                    //         &local_udp_socket,
                                    //         target_addr,
                                    //         MessageType::Commit,
                                    //         serde_json::to_string(&commit).unwrap().as_bytes(),
                                    //     ).await;
                                    // }
                                    let multicast_addr = "224.0.0.88:8888";
                                    // println!("发送多播数据");
                                    send_udp_data(
                                        &local_udp_socket,
                                        &multicast_addr.parse().unwrap(),
                                        MessageType::Commit,
                                        serde_json::to_string(&commit).unwrap().as_bytes(),
                                    ).await;
            
                                    pbft_state.commits.insert(node_info.local_node_id);
            
                                    if pbft_state.commits.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) + 1 {
                                        println!("\n2f + 1 个节点达成共识");
                                        pbft_state.sequence_number += 1;
                                        pbft_state.pbft_step = PbftStep::InIdle;
                                        let mut replication_state = replication_state.lock().await;
                                        replication_state.add_operations_of_requests(pbft_state.preprepare.clone().unwrap().requests);
                                        replication_state.store_to_file(&format!("config/node_{}/state.json", node_info.local_node_id)).await;
    
                                        if node_info.is_primarry(pbft_state.view_number) {
                                            replication_state.request_buffer.drain(0..pbft_state.preprepare.clone().unwrap().requests.len());
                                        }
                                    }
                                }
                            }
                        } else {
                            // 反序列化失败，跳过当前循环
                            continue;
                        }
                    }
                }
                
            }
            // 处理准备消息
            MessageType::Prepare => {
                let mut pbft_state = pbft_state.lock().await;
                if pbft_state.pbft_step == PbftStep::ReceiveingPrepare {
                    if let Ok(prepare) = serde_json::from_slice::<Prepare>(&content) {
                        // 成功反序列化，继续处理
                        // println!("\n处理 prepare 消息");
                        if verify_prepare(&node_info.node_configs[prepare.node_id as usize].public_key, &prepare, &prepare.signature) {
                            if !pbft_state.prepares.contains(&prepare.node_id) {
                                pbft_state.prepares.insert(prepare.node_id);
                                if pbft_state.prepares.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) {
                                    // println!("\n发送 commit 消息");
                                    pbft_state.pbft_step = PbftStep::ReceiveingCommit;
                                    let mut commit = Commit {
                                        view_number: pbft_state.view_number,
                                        sequence_number: pbft_state.sequence_number,
                                        digest: prepare.digest,
                                        node_id: node_info.local_node_id,
                                        signature: Vec::new(),
                                    };

                                    sign_commit(&node_info.private_key, &mut commit);

                                    // for target_addr in multicast_nodes_addr {
                                    //     send_udp_data(
                                    //         &local_udp_socket,
                                    //         target_addr,
                                    //         MessageType::Commit,
                                    //         serde_json::to_string(&commit).unwrap().as_bytes(),
                                    //     ).await;
                                    // }
                                    let multicast_addr = "224.0.0.88:8888";
                                    // println!("发送多播数据");
                                    send_udp_data(
                                        &local_udp_socket,
                                        &multicast_addr.parse().unwrap(),
                                        MessageType::Commit,
                                        serde_json::to_string(&commit).unwrap().as_bytes(),
                                    ).await;

                                    pbft_state.commits.insert(node_info.local_node_id);

                                    if pbft_state.commits.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) + 1 {
                                        println!("\n2f + 1 个节点达成共识");
                                        pbft_state.sequence_number += 1;
                                        pbft_state.pbft_step = PbftStep::InIdle;
                                        let mut replication_state = replication_state.lock().await;
                                        replication_state.add_operations_of_requests(pbft_state.preprepare.clone().unwrap().requests);
                                        replication_state.store_to_file(&format!("config/node_{}/state.json", node_info.local_node_id)).await;

                                        if node_info.is_primarry(pbft_state.view_number) {
                                            replication_state.request_buffer.drain(0..pbft_state.preprepare.clone().unwrap().requests.len());
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // 反序列化失败，跳过当前循环
                        continue;
                    }
                }
            }
            // 处理提交消息
            MessageType::Commit => {
                let mut pbft_state = pbft_state.lock().await;
                if pbft_state.pbft_step == PbftStep::ReceiveingCommit {
                    if let Ok(commit) = serde_json::from_slice::<Commit>(&content) {
                        // 成功反序列化，继续处理
                        // println!("\n处理 commit 消息");
                        if verify_commit(&node_info.node_configs[commit.node_id as usize].public_key, &commit, &commit.signature) {
                            if !pbft_state.commits.contains(&commit.node_id) {
                                pbft_state.commits.insert(commit.node_id);
        
                                if pbft_state.commits.len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) + 1 {
                                    println!("\n2f + 1 个节点达成共识");
                                    pbft_state.sequence_number += 1;
                                    pbft_state.pbft_step = PbftStep::InIdle;
                                    let mut replication_state = replication_state.lock().await;
                                    replication_state.add_operations_of_requests(pbft_state.preprepare.clone().unwrap().requests);
                                    replication_state.store_to_file(&format!("config/node_{}/state.json", node_info.local_node_id)).await;
        
                                    if node_info.is_primarry(pbft_state.view_number) {
                                        replication_state.request_buffer.drain(0..pbft_state.preprepare.clone().unwrap().requests.len());
                                    }
                                }
                            }
                        }
                    } else {
                        // 反序列化失败，跳过当前循环
                        continue;
                    }
                }
            },
            MessageType::Reply => {
                println!("接收到 Reply 消息");
            },
            MessageType::ViewChange => {
                if let Ok(view_change) = serde_json::from_slice::<ViewChange>(&content) {
                    let mut pbft_state = pbft_state.lock().await;
                    if view_change.view_number != pbft_state.view_number {
                        // 成功反序列化，继续处理
                        if verify_view_change(&node_info.node_configs[view_change.node_id as usize].public_key, &view_change, &view_change.signature) {
                            pbft_state.view_change_mutiple_set.entry(view_change.view_number).or_insert(HashSet::new()).insert(view_change.node_id);
                            println!("\n处理 view_change 消息(view_number: {})，总验证数量为：{}", view_change.view_number, pbft_state.view_change_mutiple_set.entry(view_change.view_number).or_insert(HashSet::new()).len());
                            if pbft_state.view_change_mutiple_set.entry(view_change.view_number).or_insert(HashSet::new()).len() as u64 >= 2 * ((node_info.node_configs.len() - 1) as u64 / 3u64) + 1 {
                                pbft_state.view_number = view_change.view_number;
                                pbft_state.sended_view_number = view_change.view_number;
                                println!("\n2f + 1 个节点达成共识达成共识，当前试图为{}", pbft_state.view_number);
                                tx.send(()).await.unwrap(); // 发送重置信号


                                // 解析 JSON 为 `Config` 结构体
                                let config_jsonstring = std::fs::read_to_string(&format!("config/node_{}/private_config.json", node_info.local_node_id)).unwrap();
                                let mut config: PrivateConfig = serde_json::from_str(&config_jsonstring).expect("JSON 解析失败");

                                // 修改 `port`
                                config.view_number = pbft_state.view_number;
                                std::fs::write(&format!("config/node_{}/private_config.json", node_info.local_node_id), serde_json::to_string_pretty(&config).expect("JSON 序列化失败")).expect("写入文件失败");




                                pbft_state.view_change_mutiple_set.clear();


                                let mut new_view_change = ViewChange {
                                    view_number: pbft_state.view_number,
                                    sequence_number: pbft_state.sequence_number,
                                    node_id: node_info.local_node_id,
                                    signature: Vec::new(),
                                };
                                sign_view_change(&node_info.private_key, &mut new_view_change);
                                send_udp_data(&local_udp_socket, &src_socket_addr, MessageType::ViewChange, serde_json::to_string(&new_view_change).unwrap().as_bytes()).await;

                                if node_info.is_primarry(pbft_state.view_number) {
                                    // println!("\n主节点发送 NewView 消息");
                                    let mut new_view = NewView {
                                        view_number: pbft_state.view_number,
                                        sequence_number: pbft_state.sequence_number,
                                        node_id: node_info.local_node_id,
                                        signature: Vec::new(),
                                    };
                                    sign_new_view(&node_info.private_key, &mut new_view);
                                    // for target_addr in multicast_nodes_addr.iter() {
                                    //     send_udp_data(&local_udp_socket, target_addr, MessageType::NewView, serde_json::to_string(&new_view).unwrap().as_bytes()).await;
                                    // }
                                    let multicast_addr = "224.0.0.88:8888";
                                    // println!("发送多播数据");
                                    send_udp_data(
                                        &local_udp_socket,
                                        &multicast_addr.parse().unwrap(),
                                        MessageType::NewView,
                                        serde_json::to_string(&new_view).unwrap().as_bytes(),
                                    ).await;
                                    
                                }
                            }
                        }
                    }
                } else {
                    // 反序列化失败，跳过当前循环
                    continue;
                }
            },
            MessageType::Hearbeat => {
                tx.send(()).await.unwrap(); // 发送重置信号
            },
            MessageType::DeterminingPrimaryNode => {
                // println!("接收到 DeterminingPrimaryNode 消息");
                let pbft_state = pbft_state.lock().await;
                let mut view_change = ViewChange {
                    view_number: pbft_state.view_number,
                    sequence_number: pbft_state.sequence_number,
                    node_id: node_info.local_node_id,
                    signature: Vec::new(),
                };
                
                utils::sign_view_change(&node_info.private_key, &mut view_change);
                utils::send_udp_data(&local_udp_socket, &src_socket_addr, MessageType::ViewChange, serde_json::to_string(&view_change).unwrap().as_bytes()).await;
            },
            MessageType::NewView => {
                if let Ok(new_view) = serde_json::from_slice::<NewView>(&content) {
                    if verify_new_view(&node_info.node_configs[new_view.node_id as usize].public_key, &new_view, &new_view.signature) {
                        // println!("\n接收到 NewView 消息");
                        let pbft_state = pbft_state.lock().await;
                        if new_view.view_number == pbft_state.view_number {
                            let local_last_index = replication_state.lock().await.blockchain.last().unwrap().index;
                            // println!("\n判断是否需要发送同步区块请求，{}，{}", new_view.sequence_number, local_last_index);
                            if new_view.sequence_number > local_last_index {
                                // 发送缺失区块请求
                                let sync_request = SyncRequest {
                                    from_index: local_last_index + 1,
                                    to_index: new_view.sequence_number,
                                };
                                send_udp_data(
                                    &local_udp_socket,
                                    &src_socket_addr,
                                    MessageType::SyncRequest,
                                    serde_json::to_string(&sync_request).unwrap().as_bytes(),
                                ).await;
                            }
                        }
                    }
                }
            },
            MessageType::SyncRequest => {
                if let Ok(sync_request) = serde_json::from_slice::<SyncRequest>(&content) {
                    // println!("\n接收到 SyncRequest 消息");
                    let mut blocks = Vec::new();
                    for index in sync_request.from_index..=sync_request.to_index {
                        if let Some(block) = ReplicationState::load_block_by_index(&format!("config/node_{}/state.json", node_info.local_node_id), index as usize).await {
                            blocks.push(block);
                        }
                    }
                    let sync_response = SyncResponse { blocks };
                    send_udp_data(
                        &local_udp_socket,
                        &src_socket_addr,
                        MessageType::SyncResponse,
                        serde_json::to_string(&sync_response).unwrap().as_bytes(),
                    ).await;
                }
            },
            MessageType::SyncResponse => {
                if let Ok(sync_response) = serde_json::from_slice::<SyncResponse>(&content) {
                    // println!("\n接收到 SyncResponse 消息");
                    let mut replication_state = replication_state.lock().await;
                    for block in sync_response.blocks {
                        if replication_state.add_block(block.clone()) {
                            replication_state.store_to_file(&format!("config/node_{}/tate.json", node_info.local_node_id)).await;
                            // println!("成功同步区块 {}", block.index);
                        } else {
                            println!("区块 {} 哈希验证失败，需重新请求", block.index);
                        }
                    }
                }
                
            },
            MessageType::DeterminingLatestReplicationState => {
                let pbft_state = pbft_state.lock().await;
                let mut new_view = NewView {
                    view_number: pbft_state.view_number,
                    sequence_number: pbft_state.sequence_number,
                    node_id: node_info.local_node_id,
                    signature: Vec::new(),
                };
                sign_new_view(&node_info.private_key, &mut new_view);
                send_udp_data(&local_udp_socket, &src_socket_addr, MessageType::NewView, serde_json::to_string(&new_view).unwrap().as_bytes()).await;
            }
            _ => println!("未知消息"),
        }
    }
}

// ---

/// 主节点定时心跳函数
pub async fn primary_heartbeat(
    local_udp_socket: Arc<UdpSocket>, 
    node_info: &NodeInfo, 
    multicast_nodes_addr: &[SocketAddr], 
    pbft_state: Arc<Mutex<PbftState>>,
) {
    let mut interval = interval(Duration::from_secs(3));
    interval.reset(); // 确保 interval 不会立即执行
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let pbft_state = pbft_state.lock().await;
                if node_info.is_primarry(pbft_state.view_number) {
                    let hearbeat = Hearbeat {
                        view_number: pbft_state.view_number,
                        sequence_number: pbft_state.sequence_number,
                        node_id: node_info.local_node_id,
                        signature: Vec::new(),
                    };
                    println!("\n主节点发送心跳消息");
                    // for node_addr in multicast_nodes_addr.iter() {
                    //     utils::send_udp_data(&local_udp_socket, &node_addr, MessageType::Hearbeat, serde_json::to_string(&hearbeat).unwrap().as_bytes()).await;
                    // }
                    let multicast_addr = "224.0.0.88:8888";
                    // println!("发送多播数据");
                    send_udp_data(
                        &local_udp_socket,
                        &multicast_addr.parse().unwrap(),
                        MessageType::Hearbeat,
                        serde_json::to_string(&hearbeat).unwrap().as_bytes(),
                    ).await;
                }
            }
        }
    }
}

// ---

/// PBFT 初始化函数
pub async  fn init() -> Result<(Arc<UdpSocket>, Arc<NodeInfo>, Arc<Vec<SocketAddr>>, Arc<Mutex<ReplicationState>>, Arc<Mutex<PbftState>>, tokio::sync::mpsc::Sender<()>, tokio::sync::mpsc::Receiver<()>), std::io::Error> {
    // 解析命令行参数
    let env_args: Vec<String> = std::env::args().collect();
    if env_args.len() != 3 {
        eprintln!("\n输入参数格式错误，正确格式为：{} local_node_id nodes_config_path\n", env_args[0]);
        std::process::exit(1);
    }

    // 获取节点 id
    let local_node_id: u64 = env_args[1].parse().expect("\n输入 local_node_id 不是数字");

    // 从配置文件读取节点配置信息
    let nodes_config_path = &env_args[2];
    let nodes_config_jsonstring = std::fs::read_to_string(nodes_config_path).expect("\n节点配置路径对应文件不存在");
    let node_configs: Vec<NodeConfig> = serde_json::from_str(&nodes_config_jsonstring).expect("\n节点配置文件json格式错误");
    
    // 查找自身节点配置
    let local_node_config: &NodeConfig = node_configs.iter().find(|node| (**node).node_id == local_node_id).expect("\nlocal_node_id 不在节点配置文件中");
    let local_addr_string = format!("{}:{}", local_node_config.ip, local_node_config.port);
    let private_key = load_private_key_from_file(&format!("config/node_{}/private_key.pem", local_node_id));
    let public_key = load_public_key_from_file(&format!("config/node_{}/public_key.pem", local_node_id));
    
    // 广播套接字地址
    let multicast_nodes_addr: Vec<std::net::SocketAddr> = node_configs.iter()
        .filter(|node| (**node).node_id != local_node_id)
        .map(|node| {
            format!("{}:{}", node.ip, node.port)
                .parse()
                .expect("\n节点配置文件中包含无效的节点地址")
        })
        .collect();
    let multicast_nodes_addr = Arc::new(multicast_nodes_addr);

    // 输出本地节点初始化信息
    println!("\n本地节点 {} 启动，绑定到地址：{}", local_node_id, local_addr_string);
    
    // 创建本地 UDP 异步套接字
    let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:8888").await.expect("\n创建本地节点套接字失败");

    let multicast_addr = Ipv4Addr::new(224, 0, 0, 88);

    let interface  = Ipv4Addr::new(0,0,0,0);
    udp_socket.join_multicast_v4(multicast_addr, interface ).expect("Failed to join multicast group");

    // 禁用多播数据回送
    udp_socket.set_multicast_loop_v4(false).expect("Failed to disable multicast loopback");
    let udp_socket = Arc::new(udp_socket);

    
    // 初始化节点信息
    let node_info = NodeInfo::new(
        local_node_id,
        local_addr_string.parse::<std::net::SocketAddr>().expect("\n节点配置文件中包含无效的节点地址"),
        private_key,
        public_key, 
        node_configs,
    );
    let node_info = Arc::new(node_info);


    // 初始化复制状态信息
    let replication_state: ReplicationState;
    if let Some(block) = ReplicationState::load_last_block_from_file(&format!("config/node_{}/state.json", local_node_id)).await {
        replication_state = ReplicationState {
            blockchain: vec![block],
            operation_buffer: Vec::new(),
            request_buffer: Vec::new(),
        };
    } else {
        replication_state = ReplicationState::new();
    }
    let replication_state = Arc::new(Mutex::new(replication_state));



    // 解析 JSON 为 `Config` 结构体
    let config_jsonstring = std::fs::read_to_string(&format!("config/node_{}/private_config.json", local_node_id)).expect("\n节点配置路径对应文件不存在");
    let config: PrivateConfig = serde_json::from_str(&config_jsonstring).expect("JSON 解析失败");

    // 修改 `port`
    let view_number = config.view_number;


    // 初始化 pbft 共识状态
    let pbft_state = PbftState::new(
        view_number, // view_number 待改进，采用动态视图。
        replication_state.lock().await.last_block().unwrap().index, 
        node_info.node_configs.len() as u64
    );
    let pbft_state = Arc::new(Mutex::new(pbft_state));

    // 创建一个通道用于发送重置信号
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    Ok((udp_socket, node_info, multicast_nodes_addr, replication_state, pbft_state, tx, rx))
}

// ---

/// 从节点定时视图切换函数
pub async fn view_change(
    local_udp_socket: Arc<UdpSocket>, 
    node_info: &NodeInfo, 
    multicast_nodes_addr: &[SocketAddr], 
    pbft_state: Arc<Mutex<PbftState>>,
    mut rx: mpsc::Receiver<()>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
    interval.reset(); // 确保 interval 不会立即执行
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut pbft_state = pbft_state.lock().await;
                if !node_info.is_primarry(pbft_state.view_number) {
                    let mut view_change = ViewChange {
                        view_number: pbft_state.sended_view_number + 1,
                        sequence_number: pbft_state.sequence_number,
                        node_id: node_info.local_node_id,
                        signature: Vec::new(),
                    };
                    utils::sign_view_change(&node_info.private_key, &mut view_change);
                    println!("\n从节点发送 view change 消息(view_number: {})", pbft_state.sended_view_number + 1);
                    pbft_state.view_change_mutiple_set.entry(view_change.view_number).or_insert(HashSet::new()).insert(node_info.local_node_id);
                    // for node_addr in multicast_nodes_addr.iter() {
                    //     utils::send_udp_data(&local_udp_socket, &node_addr, MessageType::ViewChange, serde_json::to_string(&view_change).unwrap().as_bytes()).await;
                    // }
                    let multicast_addr = "224.0.0.88:8888";
                    // println!("发送多播数据");
                    send_udp_data(
                        &local_udp_socket,
                        &multicast_addr.parse().unwrap(),
                        MessageType::ViewChange,
                        serde_json::to_string(&view_change).unwrap().as_bytes(),
                    ).await;

                    pbft_state.sended_view_number += 1;
                }
            }
            _ = rx.recv() => {
                interval.reset(); // 收到重置信号时，重置定时器
            }
        }
    }
}

// ---

// 节点启动发送获取所有节点视图编号函数
pub async fn determining_primary_node(
    local_udp_socket: Arc<UdpSocket>, 
    node_info: &NodeInfo, 
    multicast_nodes_addr: &[SocketAddr], 
    pbft_state: Arc<Mutex<PbftState>>,
) {
    // for node_addr in multicast_nodes_addr.iter() {
    //     utils::send_udp_data(&local_udp_socket, &node_addr, MessageType::DeterminingPrimaryNode, &Vec::new()).await;
    // }
    let multicast_addr = "224.0.0.88:8888";
    // println!("发送多播数据");
    send_udp_data(
        &local_udp_socket,
        &multicast_addr.parse().unwrap(),
        MessageType::DeterminingPrimaryNode,
        &Vec::new(),
    ).await;
    sleep(Duration::from_secs(2)).await;
    let pbft_state = pbft_state.lock().await;
    let primary_addr: SocketAddr = format!("{}:{}", &node_info.node_configs[pbft_state.view_number as usize % node_info.node_configs.len()].ip, &node_info.node_configs[pbft_state.view_number as usize % node_info.node_configs.len()].port).parse().unwrap();
    utils::send_udp_data(&local_udp_socket, &primary_addr, MessageType::DeterminingLatestReplicationState, &Vec::new()).await;
}

