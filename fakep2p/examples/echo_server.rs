use fakep2p::{P2PConfig, P2PComm, P2PSender, P2PReceiver};
use tokio::fs;




#[tokio::main]
async fn main() {
    let json = fs::read_to_string("examples/echo_server_config.json").await.unwrap();
    let config: P2PConfig = serde_json::from_str(&json).unwrap();

    let mut comm = P2PComm::new(config).await.unwrap();
    println!("comm set up");
    loop {
        let rcv = comm.accept().await.unwrap();
        let send = comm.new_sender();
        println!("accepted a connection");

        tokio::spawn(async move {
            handle(send, rcv).await;
        });
    }
}


async fn handle(mut send: P2PSender, mut rcv: P2PReceiver) {
    loop {
        let mut m = match rcv.receive().await {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                println!("oh no! {:?}", e);
                return;
            }
            None => {
                println!("connection ended peacefully");
                return;
            },
        };
        m.dest = m.sender;
        m.sender = "echo server".to_string(); 
        m.content.extend(b" cheese".iter());
        send.send_one(m).unwrap();
    }
}


