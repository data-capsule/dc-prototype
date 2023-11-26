mod config;
mod crypto;
mod merkle;
mod readstate;
mod request;
mod server_internal;
use crypto::PrivateKey;
use request::ServerCodec;
use server_internal::reader::process_reader;
use server_internal::writer::process_writer;
use server_internal::DCServerError;
use sled::Db;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use std::env;
use std::error::Error;
use std::net::SocketAddr;

use crate::crypto::deserialize_private_key_from_pem;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
    // Configure a `tracing` subscriber that logs traces emitted by the chat
    // server.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("server=info".parse()?))
        .with_span_events(FmtSpan::FULL)
        .init();

    let args: Vec<String> = env::args().collect();
    let (addr, db_file, pk_file) = match args.len() {
        1 => ("127.0.0.1:6142".into(), "my_db".into(), "my_pk".into()),
        4 => (args[1].clone(), args[2].clone(), args[3].clone()),
        _ => {
            println!("3 arguments required: addr, db, pk");
            return Ok(());
        }
    };

    run_server(addr, db_file, pk_file).await
}

async fn run_server(addr: String, db_file: String, pk_file: String) -> Result<(), Box<dyn Error>> {
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
        _ => {
            tracing::error!("Failed to init {}", addr);
            return Ok(());
        }
    };
    match init_req {
        request::InitRequest::Create => todo!(),
        request::InitRequest::Read(dc_name) => process_reader(db, &dc_name, framed, addr).await,
        request::InitRequest::Write(dc_name) => {
            process_writer(pk, db, &dc_name, framed, addr).await
        }
        request::InitRequest::Subscribe(_) => todo!(),
    }
}
