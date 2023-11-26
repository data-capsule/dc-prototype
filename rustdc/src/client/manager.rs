use std::net::SocketAddr;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::shared::{
    crypto::{
        hash_dc_metadata, serialize_pubkey, sign, verify_signature, DataCapsule, Hash, PrivateKey,
        PublicKey,
    },
    request::{ClientCodec, InitRequest, ManageRequest, Request, Response},
};

use super::{initialize_connection, DCError};

pub struct ManagerConnection {
    connection: Framed<TcpStream, ClientCodec>,
}

impl ManagerConnection {
    pub async fn new(server_address: SocketAddr) -> Result<Self, DCError> {
        let stream = initialize_connection(server_address, InitRequest::Manage).await?;
        Ok(Self { connection: stream })
    }

    pub async fn create(
        &mut self,
        creator_pub_key: &PublicKey,
        creator_private_key: &PrivateKey,
        writer_pub_key: &PublicKey,
        server_pub_key: &PublicKey,
        description: String,
    ) -> Result<(), DCError> {
        let creator_pub_key = serialize_pubkey(creator_pub_key);
        let writer_pub_key = serialize_pubkey(writer_pub_key);
        let meta_hash = hash_dc_metadata(&creator_pub_key, &writer_pub_key, &description);
        let dc = DataCapsule {
            creator_pub_key,
            writer_pub_key,
            description,
            signature: sign(&meta_hash, creator_private_key),
        };

        let req = Request::Manage(ManageRequest::Create(dc));
        self.connection.send(req).await?;
        let resp = match self.connection.next().await {
            Some(r) => r?,
            None => {
                return Err(DCError::Other("stream ended".to_string()));
            }
        };
        match resp {
            Response::ManageCreate(s) => match verify_signature(&s, server_pub_key) {
                Some(h) => {
                    if h != meta_hash {
                        Err(DCError::Cryptographic("mismatched hashes".into()))
                    } else {
                        Ok(())
                    }
                }
                None => Err(DCError::Cryptographic("bad signature".into())),
            },
            Response::Failed => Err(DCError::ServerError("server failed".into())),
            _ => Err(DCError::ServerError("mismatched response".into())),
        }
    }

    pub async fn read(&mut self, dc_name: Hash) -> Result<DataCapsule, DCError> {
        let req = Request::Manage(ManageRequest::Read(dc_name));
        self.connection.send(req).await?;
        let resp = match self.connection.next().await {
            Some(r) => r?,
            None => {
                return Err(DCError::Other("stream ended".to_string()));
            }
        };
        match resp {
            Response::ManageRead(dc) => {
                if hash_dc_metadata(&dc.creator_pub_key, &dc.writer_pub_key, &dc.description)
                    == dc_name
                {
                    Ok(dc)
                } else {
                    Err(DCError::Cryptographic("mismatched hashes".into()))
                }
            }
            Response::Failed => Err(DCError::ServerError("server failed".into())),
            _ => Err(DCError::ServerError("mismatched response".into())),
        }
    }
}