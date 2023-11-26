use std::net::SocketAddr;

use futures::{SinkExt, StreamExt};
use sled::Db;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::server::storage::MetaStorage;
use crate::shared::crypto::{
    deserialize_pubkey, hash_dc_metadata, sign, verify_signature, PrivateKey,
};
use crate::shared::request::{ManageRequest, Request, Response, ServerCodec};

use super::DCServerError;

pub async fn process_manager(
    signing_key: &PrivateKey,
    db: Db,
    mut stream: Framed<TcpStream, ServerCodec>,
    addr: SocketAddr,
) -> Result<(), DCServerError> {
    let mut ms = MetaStorage::new(&db)?;

    loop {
        let req = match stream.next().await {
            Some(Ok(Request::Manage(m))) => m,
            Some(Ok(_)) => {
                tracing::error!("mismatched request {}", addr);
                break;
            }
            Some(Err(e)) => {
                tracing::error!("connection error on {}: {:?}", addr, e);
                break;
            }
            None => {
                tracing::info!("connection ended peacefully {}", addr);
                break;
            }
        };
        match req {
            ManageRequest::Create(dc) => {
                let hash =
                    hash_dc_metadata(&dc.creator_pub_key, &dc.writer_pub_key, &dc.description);
                let creator_pk = deserialize_pubkey(&dc.creator_pub_key);
                let good = match verify_signature(&dc.signature, &creator_pk) {
                    Some(h) => h == hash,
                    None => false,
                };
                let r = if good {
                    match ms.store(&hash, &dc) {
                        Ok(()) => Response::ManageCreate(sign(&hash, signing_key)),
                        Err(_) => Response::Failed,
                    }
                } else {
                    Response::Failed
                };
                if let Err(e) = stream.send(r).await {
                    tracing::error!("sending error on {}: {:?}", addr, e);
                    break;
                }
            }
            ManageRequest::Read(hash) => {
                let r = match ms.get(&hash) {
                    Ok(Some(ds)) => Response::ManageRead(ds),
                    _ => Response::Failed,
                };
                if let Err(e) = stream.send(r).await {
                    tracing::error!("sending error on {}: {:?}", addr, e);
                    break;
                }
            }
        }
    }

    todo!()
}
