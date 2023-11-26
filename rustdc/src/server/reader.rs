use std::net::SocketAddr;

use futures::{SinkExt, StreamExt};
use sled::Db;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::shared::crypto::{get_hash_no_verify, Hash};
use crate::shared::readstate::ReadState;
use crate::shared::request::{ReadRequest, Request, Response, ServerCodec};

use super::storage::{DataStorage, NodeStorage, RecordStorage};
use super::DCServerError;

pub async fn process_reader(
    db: Db,
    dc_name: &Hash,
    mut stream: Framed<TcpStream, ServerCodec>,
    addr: SocketAddr,
) -> Result<(), DCServerError> {
    let ds = DataStorage::new(&db, dc_name)?;
    let rs = RecordStorage::new(&db, dc_name)?;
    let ns = NodeStorage::new(&db, dc_name)?;

    let mut read_state = ReadState::new();

    loop {
        let req = match stream.next().await {
            Some(Ok(Request::Read(r))) => r,
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
            ReadRequest::Data(hash) => {
                // just get the data block
                let r = match ds.get(&hash) {
                    Ok(Some(r)) => Response::ReadData(r),
                    _ => Response::Failed,
                };
                if let Err(e) = stream.send(r).await {
                    tracing::error!("sending error on {}: {:?}", addr, e);
                    break;
                }
            }
            ReadRequest::Proof(hash) => {
                // need to build merkle tree, check that signature is fine,
                // store all records, store all nodes, store sequence numbers
                let r = build_proof(&mut read_state, &rs, &ns, hash);
                if let Err(e) = stream.send(r).await {
                    tracing::error!("sending error on {}: {:?}", addr, e);
                    break;
                }
            }
        };
    }

    Ok(())
}

fn build_proof(
    read_state: &mut ReadState,
    rs: &RecordStorage,
    ns: &NodeStorage,
    mut hash: Hash,
) -> Response {
    // every committed record should have a parent
    let mut parent = match rs.get(&hash) {
        Ok(Some((_, p))) => p,
        _ => return Response::Failed,
    };

    let mut nodes = Vec::new();
    let mut root = None;

    // go up the chain (modifying hash and parent)
    while !read_state.contains(&hash) {
        let parent_node = match ns.get(&parent) {
            Ok(Some(p)) => p,
            _ => return Response::Failed,
        };
        nodes.push(parent_node.children);
        if let Some(s) = parent_node.signature {
            if !read_state.contains(&parent) {
                root = Some(s);
            }
            break;
        };
        hash = parent;
        parent = match parent_node.parent {
            Some(p) => p,
            None => return Response::Failed,
        }
    }

    // TODO: signature avoidance

    // add proof to read_state the same way the client does
    nodes.reverse();
    if let Some(s) = &root {
        read_state.add_signed_hash(&get_hash_no_verify(s));
    }
    for n in &nodes {
        read_state.add_proven_node(n);
    }
    Response::ReadProof { root, nodes }
}
