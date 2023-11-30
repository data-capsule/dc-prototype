use std::net::SocketAddr;

use futures::SinkExt;
use sled::Db;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::shared::config::SIG_AVOID;
use crate::shared::crypto::{
    deserialize_pubkey, hash_data, sign, verify_signature, Hash, PrivateKey, PublicKey, Signature,
};
use crate::shared::merkle::merkle_tree_storage;
use crate::shared::readstate::ReadState;
use crate::shared::request::{RWRequest, Request, Response, ServerCodec};

use super::storage::{
    DataStorage, MetaStorage, NodeStorage, OrphanStorage, RecordStorage, StoredNode,
};
use super::{wait_for_request, DCServerError};

pub async fn process_writer(
    signing_key: &PrivateKey,
    db: Db,
    dc_name: &Hash,
    mut stream: Framed<TcpStream, ServerCodec>,
    addr: SocketAddr,
) -> Result<(), DCServerError> {
    let mut ds = DataStorage::new(&db, dc_name)?;
    let mut rs = RecordStorage::new(&db, dc_name)?;
    let mut ns = NodeStorage::new(&db, dc_name)?;
    let mut os = OrphanStorage::new(&db, dc_name)?;

    let writer_pk = match MetaStorage::get_writer_pk(&db, dc_name)? {
        Some(v) => deserialize_pubkey(&v),
        None => return Err(DCServerError::MissingStorage("writer_pk".into())),
    };

    let mut uncommitted_hashes: Vec<Hash> = Vec::new();
    let mut read_state = ReadState::new();

    // successfully initialized, start processing real requests
    stream.send(Response::Init).await?;
    loop {
        let req = match wait_for_request(&mut stream).await {
            Some(Request::RW(w)) => w,
            Some(_) => {
                tracing::error!("mismatched request {}", addr);
                break;
            }
            None => break,
        };
        let resp = match req {
            RWRequest::Write(data) => {
                // need to store data block,
                // send response, and append to uncommitted_hashes vector
                let r = handle_data(&mut ds, data);
                if let Some(name) = r {
                    uncommitted_hashes.push(name);
                    Response::WriteData
                } else {
                    Response::Failed
                }
            }
            RWRequest::Commit {
                additional_hash,
                signature,
            } => {
                // need to build merkle tree, check that signature is fine,
                // store all records, store all nodes, replace orphan in orphan storage
                let r = handle_commit(
                    &mut rs,
                    &mut ns,
                    &mut os,
                    &writer_pk,
                    signing_key,
                    &uncommitted_hashes,
                    &additional_hash,
                    &signature,
                );
                uncommitted_hashes.clear();
                match r {
                    Some(s) => Response::WriteCommit(s),
                    None => Response::Failed,
                }
            }
            RWRequest::Read(hash) => {
                // just get the data block
                match ds.get(&hash) {
                    Ok(Some(r)) => Response::ReadData(r),
                    _ => Response::Failed,
                }
            }
            RWRequest::Proof(hash) => build_proof(&mut read_state, &rs, &ns, hash),
        };
        stream.feed(resp).await?
    }

    // beware of uncommitted hashes
    // but don't delete them, because they might existed before this connection
    // especially if someone malicious is trying to get a record deleted

    Ok(())
}

fn handle_data(ds: &mut DataStorage, data: Vec<u8>) -> Option<Hash> {
    let record_name = hash_data(&data);
    if let Err(e) = ds.store(&record_name, &data) {
        tracing::error!("ds error: {:?}", e);
        None
    } else {
        Some(record_name)
    }
}

fn handle_commit(
    rs: &mut RecordStorage,
    ns: &mut NodeStorage,
    os: &mut OrphanStorage,
    writer_pk: &PublicKey,
    signing_key: &PrivateKey,
    uncommitted_hashes: &[Hash],
    additional_hash: &Hash,
    client_signature: &Signature,
) -> Option<Signature> {
    let (rbs, tns, additional_hash_parent, root, tree_depth) =
        merkle_tree_storage(uncommitted_hashes, additional_hash);

    if !verify_signature(client_signature, &root.name, writer_pk) {
        tracing::error!("bad sig");
        return None;
    }

    for rb in rbs {
        if let Err(e) = rs.store(&rb.name, &rb.parent) {
            tracing::error!("ds error: {:?}", e);
            return None;
        }
    }

    for tn in tns {
        if let Err(e) = ns.store(
            &tn.name,
            &StoredNode {
                parent: tn.parent,
                root_info: None,
                children: tn.children,
            },
        ) {
            tracing::error!("ds error: {:?}", e);
            return None;
        }
    }

    // last, signed node
    if let Err(e) = ns.store(
        &root.name,
        &StoredNode {
            parent: None,
            root_info: Some((tree_depth, client_signature.clone())),
            children: root.children,
        },
    ) {
        tracing::error!("ds error: {:?}", e);
        return None;
    }

    // mark root node as orphan, and additional hash as non-orphan
    if let Err(e) = os.replace(additional_hash, &root.name, client_signature) {
        tracing::error!("ds error: {:?}", e);
        return None;
    }

    // set parent of additional hash if node exists
    // node may not exist, or may already have a parent if branching occurs
    match ns.get(additional_hash) {
        Ok(Some(mut stored_node)) => {
            if stored_node.parent.is_none() {
                stored_node.parent = Some(additional_hash_parent);
                if let Err(e) = ns.store(additional_hash, &stored_node) {
                    tracing::error!("ds error: {:?}", e);
                    return None;
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("ds error: {:?}", e);
            return None;
        }
    }

    Some(sign(&root.name, signing_key))
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
    let mut root_parent = None;

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
                root_parent = parent_node.parent;
            }
            break;
        };
        hash = parent;
        parent = match parent_node.parent {
            Some(p) => p,
            None => return Response::Failed,
        }
    }

    // signature avoidance
    // tends to make sequential benchmarks slower, do not use
    if root.is_some() && SIG_AVOID > 0 {
        let mut extras = Vec::new();
        while extras.len() < SIG_AVOID {
            if let Some(p) = root_parent {
                let parent_node = match ns.get(&p) {
                    Ok(Some(p)) => p,
                    _ => break,
                };
                extras.push(parent_node.children);
                if read_state.contains(&p) {
                    // found a replacement proof
                    root = None;
                    nodes.append(&mut extras);
                    break;
                }
                root_parent = parent_node.parent;
            } else {
                break;
            }
        }
    }

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
