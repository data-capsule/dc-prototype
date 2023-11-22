use tokio::io;
use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite};
use futures::{future, SinkExt};
use std::{error::Error, net::SocketAddr};
use tokio::net::TcpStream;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Parse what address we're going to connect to
    let addr = "127.0.0.1:5678".parse::<SocketAddr>()?;

    let mut stdin = FramedRead::new(io::stdin(), BytesCodec::new());
    let mut stdout = FramedWrite::new(io::stdout(), BytesCodec::new());

    let mut stream = TcpStream::connect(addr).await?;
    let (r, w) = stream.split();
    let mut sink = FramedWrite::new(w, BytesCodec::new());
    let mut stream = FramedRead::new(r, BytesCodec::new());

    let f1 = sink.send_all(&mut stdin);
    let f2 = stdout.send_all(&mut stream);

    match future::join(f1, f2).await {
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
        _ => Ok(()),
    }
}
