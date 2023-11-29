use std::{error::Error, net::SocketAddr};

use futures::{FutureExt, SinkExt, StreamExt};
use sled::Db;
use tokio::{
    fs::File,
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::codec::Framed;

use crate::shared::{
    crypto::{deserialize_private_key_from_pem, PrivateKey},
    request::{self, Request, ServerCodec},
};

use self::{manager::process_manager, reader::process_reader, writer::process_writer};

mod manager;
mod reader;
mod storage;
mod subscriber;
mod writer;

#[derive(Debug)]
pub enum DCServerError {
    Cryptographic(String),
    OpenSSL(openssl::error::ErrorStack),
    IO(std::io::Error),
    Storage(sled::Error),
    MissingStorage(String),
    Other(String),
}

impl From<std::io::Error> for DCServerError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<openssl::error::ErrorStack> for DCServerError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(value)
    }
}

impl From<sled::Error> for DCServerError {
    fn from(value: sled::Error) -> Self {
        Self::Storage(value)
    }
}

pub async fn run_server(
    addr: String,
    db_file: String,
    pk_file: String,
) -> Result<(), Box<dyn Error>> {
    // Bind a TCP listener to the socket address.
    // Note that this is the Tokio TcpListener, which is fully async.
    let listener = TcpListener::bind(&addr).await?;
    let db = sled::open(db_file).unwrap();

    let mut pk_file = File::open(pk_file).await?;
    let mut pk = Vec::new();
    pk_file.read_to_end(&mut pk).await?;
    let pk = deserialize_private_key_from_pem(&pk);

    tracing::info!("server running on {}", addr);

    loop {
        let (stream, addr) = listener.accept().await?;
        let db = db.clone();
        let pk = pk.clone();
        tokio::spawn(async move {
            tracing::debug!("accepted connection");
            if let Err(e) = process(&pk, db, stream, addr).await {
                tracing::info!("an error occurred; error = {:?}", e);
            }
        });
    }
}

/// Process an individual client
async fn process(
    pk: &PrivateKey,
    db: Db,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), DCServerError> {
    let mut framed = Framed::new(stream, ServerCodec::new());

    let init_req = match framed.next().await {
        Some(Ok(request::Request::Init(i))) => i,
        r => {
            tracing::error!("Failed to init {}: {:?}", addr, r);
            return Ok(());
        }
    };
    match init_req {
        request::InitRequest::Manage => process_manager(pk, db, framed, addr).await,
        request::InitRequest::Read(dc_name) => process_reader(db, &dc_name, framed, addr).await,
        request::InitRequest::Write(dc_name) => {
            process_writer(pk, db, &dc_name, framed, addr).await
        }
        request::InitRequest::Subscribe(_) => todo!(),
    }
}

// Waits for a request, flushing the previous request if it needs to wait
// Flushing does not happen if next request is already ready
async fn wait_for_request(stream: &mut Framed<TcpStream, ServerCodec>) -> Option<Request> {
    let req = match stream.next().now_or_never() {
        Some(r) => r,
        None => {
            if let Err(e) = stream.flush().await {
                tracing::error!("flushing error {:?}", e);
                return None;
            }
            stream.next().await
        }
    };

    match req {
        Some(Ok(r)) => Some(r),
        Some(Err(e)) => {
            tracing::error!("connection error: {:?}", e);
            None
        }
        None => {
            tracing::info!("connection ended peacefully");
            None
        }
    }
}
