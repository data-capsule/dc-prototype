use std::error::Error;

use fakep2p::{P2PComm, P2PConfig};
use tokio::fs;

use crate::{
    client::p2pclient::ClientConnection,
    shared::crypto::{PrivateKey, PublicKey, SymmetricKey},
};

pub mod p2pclient;

#[derive(Debug)]
pub enum DCClientError {
    ServerError(String),
    MismatchedHash,
    BadSignature,
    BadProof(String),
    OpenSSL(openssl::error::ErrorStack),
    IO(std::io::Error),
    StreamEnded,
    Other(String),
}

impl From<std::io::Error> for DCClientError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<openssl::error::ErrorStack> for DCClientError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(value)
    }
}

pub async fn run_client(
    name: &str,
    signing_key: PrivateKey,
    signing_pub_key: PublicKey,
    encryption_key: SymmetricKey,
    net_config: &str,
) -> Result<ClientConnection, Box<dyn Error>> {
    let net_config = fs::read_to_string(net_config).await?;
    let net_config: P2PConfig = serde_json::from_str(&net_config)?;

    let mut comm = P2PComm::new(name.into(), net_config).await?;

    let (client, to_client) = ClientConnection::new(
        name,
        signing_key,
        signing_pub_key,
        encryption_key,
        comm.new_sender(),
    );

    tokio::spawn(async move {
        loop {
            let to_client = to_client.clone();
            let mut rcv = comm.accept().await.unwrap();
            tokio::spawn(async move {
                loop {
                    let m = match rcv.receive().await {
                        Some(Ok(m)) => m,
                        _ => return,
                    };
                    to_client.send(m).unwrap();
                }
            });
        }
    });

    Ok(client)
}
