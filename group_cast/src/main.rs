// sender.rs
use std::net::UdpSocket;
use std::time::Duration;
use std::thread;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:9999").expect("Failed to bind socket");
    let multicast_addr = "224.0.0.88:8888";
    let data = b"Hello, Multicast!";
    loop {
        thread::sleep(Duration::from_secs(3));
        println!("发送多播数据 {:?}", String::from_utf8(data.to_vec()).unwrap());
        socket.send_to(data, multicast_addr).expect("Failed to send data");
    }
}
