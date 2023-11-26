use futures::{future, SinkExt, StreamExt};
use std::{error::Error, net::SocketAddr};
use tokio::io;
use tokio::net::TcpStream;
use tokio_util::codec::{BytesCodec, Framed, FramedRead, FramedWrite};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
