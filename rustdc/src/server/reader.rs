use std::net::SocketAddr;

use futures::SinkExt;
use sled::Db;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::shared::crypto::Hash;
use crate::shared::readstate::ReadState;
use crate::shared::request::{ReadRequest, Request, Response, ServerCodec};

use super::storage::{DataStorage, NodeStorage, RecordStorage};
use super::{wait_for_request, DCServerError};

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

    // successfully initialized, start processing real requests
    stream.send(Response::Init).await?;
    loop {
        let req = match wait_for_request(&mut stream).await {
            Some(Request::Read(r)) => r,
            Some(_) => {
                tracing::error!("mismatched request {}", addr);
                break;
            }
            None => break,
        };
        let resp = match req {
            ReadRequest::Data(hash) => {
                // just get the data block
                match ds.get(&hash) {
                    Ok(Some(r)) => Response::ReadData(r),
                    _ => Response::Failed,
                }
            }
            ReadRequest::Proof(hash) => build_proof(&mut read_state, &rs, &ns, hash),
        };
        stream.feed(resp).await?;
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
        Ok(Some(p)) => p,
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
        if let Some((_, signature)) = parent_node.root_info {
            if !read_state.contains(&parent) {
                root = Some((signature, parent));
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
    if let Some((_, h)) = &root {
        read_state.add_signed_hash(h);
    }
    for n in &nodes {
        read_state.add_proven_node(n);
    }
    Response::ReadProof { root, nodes }
}
