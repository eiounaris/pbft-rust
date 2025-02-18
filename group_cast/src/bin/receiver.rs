// receiver.rs
use std::net::UdpSocket;
use std::net::Ipv4Addr;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:8888").expect("Failed to bind socket"); // 为什么只有当8888才能运行
    let multicast_addr = Ipv4Addr::new(224, 0, 0, 88);

    let mut buf = [0u8; 1024];
    let interface  = Ipv4Addr::new(0,0,0,0);
    socket.join_multicast_v4(&multicast_addr, &interface ).expect("Failed to join multicast group");

    loop {
        let (amt, src) = socket.recv_from(&mut buf).expect("Failed to receive data");
        println!("接收 {:?}， 来自 {:?}", String::from_utf8(buf[0..amt].to_vec()).unwrap(), src);
    }
}

