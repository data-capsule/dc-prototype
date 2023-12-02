use fakep2p::{P2PConfig, P2PComm, P2PSender, P2PReceiver, P2PMessageBody};
use futures::StreamExt;
use tokio::{fs, io::{self, Stdin}};
use tokio_util::codec::{LinesCodec, FramedRead};



#[tokio::main]
async fn main() {
    let mut stdin = FramedRead::new(io::stdin(), LinesCodec::new());
    println!("enter client name (client1, client2, client3, server2):");
    let name = stdin.next().await.unwrap().unwrap();

    let json = fs::read_to_string("examples/echo_server_config.json").await.unwrap();
    let mut config: P2PConfig = serde_json::from_str(&json).unwrap();

    config.name = name.clone();

    let mut comm = P2PComm::new(config).await.unwrap();
    println!("comm set up");

    let sender = comm.new_sender();
    tokio::spawn(async move {
        interact(sender, stdin, &name).await;
    });

    loop {
        let rcv = comm.accept().await.unwrap();
        println!("accepted a connection");

        tokio::spawn(async move {
            handle(rcv).await;
        });
    }
}


async fn handle(mut rcv: P2PReceiver) {
    loop {
        let msg = rcv.receive().await.unwrap().unwrap();
        println!("got {:?}", msg);
    }
}

async fn interact(mut sender: P2PSender, mut stdin: FramedRead<Stdin, LinesCodec>, name: &str) {
    loop {
        let line = stdin.next().await.unwrap().unwrap();
        println!("sending {:?}", line);
        let msg = P2PMessageBody {
            dest: "dc1".into(),
            sender: name.into(),
            content: line.as_bytes().to_vec(),
            metadata: "cheese".as_bytes().to_vec()
        };
        sender.send_multi(msg).unwrap();
    }
}






