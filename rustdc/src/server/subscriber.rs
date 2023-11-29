use std::net::SocketAddr;

use futures::SinkExt;
use sled::Db;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::shared::config::FANOUT;
use crate::shared::crypto::{Hash, NULL_HASH};
use crate::shared::request::{Request, Response, ServerCodec, SubscribeRequest};

use super::storage::{NodeStorage, OrphanStorage};
use super::{wait_for_request, DCServerError};

pub async fn process_subscriber(
    db: Db,
    dc_name: &Hash,
    mut stream: Framed<TcpStream, ServerCodec>,
    addr: SocketAddr,
) -> Result<(), DCServerError> {
    let ns = NodeStorage::new(&db, dc_name)?;
    let os = OrphanStorage::new(&db, dc_name)?;

    // successfully initialized, start processing real requests
    stream.send(Response::Init).await?;
    loop {
        let req = match wait_for_request(&mut stream).await {
            Some(Request::Subscribe(s)) => s,
            Some(_) => {
                tracing::error!("mismatched request {}", addr);
                break;
            }
            None => break,
        };
        let resp = match req {
            SubscribeRequest::FreshestCommits() => match os.all_orphans() {
                Ok(Some(v)) => Response::SubscribeCommits(v),
                _ => Response::Failed,
            },
            SubscribeRequest::Records(hash) => get_all_leaves(&ns, &hash),
        };
        stream.feed(resp).await?;
    }

    Ok(())
}

fn get_all_leaves(ns: &NodeStorage, hash: &Hash) -> Response {
    let mut depth = match ns.get(hash) {
        Ok(Some(node)) => match node.root_info {
            Some((d, _)) => d,
            None => return Response::Failed,
        },
        _ => return Response::Failed,
    };

    let mut level = vec![*hash];
    while depth > 0 {
        let mut next_level = Vec::with_capacity(level.len() * FANOUT);
        for h in level {
            match ns.get(&h) {
                Ok(Some(node)) => {
                    for h in node.children {
                        if h != NULL_HASH {
                            next_level.push(h)
                        }
                    }
                }
                _ => return Response::Failed,
            }
        }
        level = next_level;
        depth -= 1;
    }

    let additional_hash = level.pop().unwrap();
    Response::SubscribeRecords(level, additional_hash)
}
