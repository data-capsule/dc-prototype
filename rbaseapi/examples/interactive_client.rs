use std::net::SocketAddr;

use datacapsule::client::manager::ManagerConnection;

fn main() {
    let server_addr = "127.0.0.1:6142".parse::<SocketAddr>().unwrap();

    let mc = ManagerConnection::new(server_addr);
}
