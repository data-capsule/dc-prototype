use std::{error::Error, net::SocketAddr};

use futures::{future, SinkExt, StreamExt};
use tokio::{io, net::TcpStream};
use tokio_util::codec::{BytesCodec, Framed, FramedRead, FramedWrite};

async fn echo(b: &[u8]) -> Result<(), Box<dyn Error>> {
    // Parse what address we're going to connect to
    let addr = "127.0.0.1:5678".parse::<SocketAddr>()?;

    let mut stdin = FramedRead::new(io::stdin(), BytesCodec::new());
    let mut stdout = FramedWrite::new(io::stdout(), BytesCodec::new());

    let stream = Framed::new(TcpStream::connect(addr).await?, BytesCodec::new());
    let (mut r, mut w) = stream.split();

    let f1 = r.send_all(&mut stdin);
    let f2 = stdout.send_all(&mut w);

    match future::join(f1, f2).await {
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
        _ => Ok(()),
    }
}

async fn echo_many(b: &[u8], num: usize) -> Result<(), Box<dyn Error>> {
    Ok(())
}

fn main() {
    println!("This benchmark hasn't been written yet");
}
