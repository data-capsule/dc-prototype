use std::net::SocketAddr;

use futures::SinkExt;
use sled::Db;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::server::storage::DCMetadataStorage;
use crate::shared::crypto::{
    deserialize_pubkey, hash_dc_metadata, sign, verify_signature, PrivateKey,
};
use crate::shared::request::{ManageRequest, Request, Response, ServerCodec};

use super::{wait_for_request, DCServerError};

pub async fn process_manager(
    signing_key: &PrivateKey,
    db: Db,
    mut stream: Framed<TcpStream, ServerCodec>,
    addr: SocketAddr,
) -> Result<(), DCServerError> {
    let mut ms = DCMetadataStorage::new(&db)?;

    // successfully initialized, start processing real requests
    stream.send(Response::Init).await?;
    loop {
        let req = match wait_for_request(&mut stream).await {
            Some(Request::Manage(m)) => m,
            Some(_) => {
                tracing::error!("mismatched request {}", addr);
                break;
            }
            None => break,
        };
        let resp = match req {
            ManageRequest::Create(dc) => {
                let hash =
                    hash_dc_metadata(&dc.creator_pub_key, &dc.writer_pub_key, &dc.description);
                let creator_pk = deserialize_pubkey(&dc.creator_pub_key);
                let good = verify_signature(&dc.signature, &hash, &creator_pk);
                if good {
                    match ms.store(&hash, &dc) {
                        Ok(()) => Response::ManageCreate(sign(&hash, signing_key)),
                        Err(_) => Response::Failed,
                    }
                } else {
                    Response::Failed
                }
            }
            ManageRequest::Read(hash) => match ms.get(&hash) {
                Ok(Some(ds)) => Response::ManageRead(ds),
                _ => Response::Failed,
            },
        };
        stream.feed(resp).await?;
    }

    Ok(())
}
