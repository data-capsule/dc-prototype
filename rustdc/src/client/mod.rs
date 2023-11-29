pub mod manager;
pub mod reader;
pub mod subscriber;
pub mod writer;

use std::{io, net::SocketAddr};

use futures::{SinkExt, StreamExt};
use openssl::error::ErrorStack;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::shared::request::{ClientCodec, InitRequest, Request, Response};

#[derive(Debug)]
pub enum DCClientError {
    ServerError(String),
    Cryptographic(String),
    OpenSSL(ErrorStack),
    IO(io::Error),
    Other(String),
}

impl From<io::Error> for DCClientError {
    fn from(value: io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<ErrorStack> for DCClientError {
    fn from(value: ErrorStack) -> Self {
        Self::OpenSSL(value)
    }
}

async fn initialize_connection(
    server_address: SocketAddr,
    req: InitRequest,
) -> Result<Framed<TcpStream, ClientCodec>, DCClientError> {
    let tt = TcpStream::connect(server_address).await?;
    let mut stream = Framed::new(tt, ClientCodec::new());
    stream.send(Request::Init(req)).await?;
    let res = match stream.next().await {
        Some(r) => r?,
        None => return Err(DCClientError::Other("stream ended".into())),
    };
    match res {
        Response::Init => Ok(stream),
        _ => Err(DCClientError::ServerError("bad init".into())),
    }
}
