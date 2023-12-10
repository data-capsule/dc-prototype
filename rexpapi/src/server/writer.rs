use std::time::Instant;

use fakep2p::{P2PMessageBody, P2PSender};
use postcard::{from_bytes, to_stdvec};
use sled::Db;
use tokio::sync::mpsc;

use crate::shared::config::{FANOUT, SIG_AVOID};
use crate::shared::crypto::{
    deserialize_pubkey, hash_data, hash_dc_metadata, sign, verify_signature, DataCapsule, Hash,
    PrivateKey, PublicKey, Signature, NULL_HASH,
};
use crate::shared::merkle::merkle_tree_storage;
use crate::shared::readstate::ReadState;
use crate::shared::request::{Request, Response};

use super::storage::{
    DataStorage, MetaStorage, NodeStorage, OrphanStorage, RecordStorage, StoredNode,
};
use super::withp2p::ServerContext;
use super::DCServerError;

struct DCContext {
    ds: DataStorage,
    rs: RecordStorage,
    ns: NodeStorage,
    os: OrphanStorage,
    writer_pk: PublicKey,
    uncommitted_hashes: Vec<Hash>,
    read_state: ReadState,
}

impl DCContext {
    fn new(dc_name: Hash, db: &Db, writer_pk: PublicKey) -> Result<Self, sled::Error> {
        Ok(Self {
            ds: DataStorage::new(db, &dc_name)?,
            rs: RecordStorage::new(db, &dc_name)?,
            ns: NodeStorage::new(db, &dc_name)?,
            os: OrphanStorage::new(db, &dc_name)?,
            writer_pk,
            uncommitted_hashes: Vec::new(),
            read_state: ReadState::new(),
        })
    }
}

/// Handles an individual client. All messages received from rcv will be from
/// the same client.
pub async fn handle_client(
    server_ctx: ServerContext,
    mut rcv: mpsc::UnboundedReceiver<P2PMessageBody>,
    mut send: P2PSender,
) -> Result<(), DCServerError> {
    let mut ms = MetaStorage::new(&server_ctx.db)?;
    let mut ctx: Option<DCContext> = None;

    loop {
        let req = match rcv.recv().await {
            Some(m) => m,
            None => break,
        };
        let client_name = req.sender;
        let many_requests: Vec<Request> = match from_bytes(&req.content) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("could not decode: {:?}", e);
                break;
            }
        };
        let tt = Instant::now();
        let many_responses: Vec<Response> = many_requests.into_iter().map(|r| request_to_response(&server_ctx, &mut ms, &mut ctx, r)).collect();
        println!("processing time: {:?}", tt.elapsed());
        let resp = to_stdvec(&many_responses).unwrap(); // TODO: handle well
        let resp = P2PMessageBody {
            dest: client_name,
            sender: server_ctx.server_name.clone(),
            content: resp,
            metadata: Vec::new(),
        };
        if let Err(e) = send.send_one(resp) {
            tracing::error!("sending error: {:?}", e);
            break;
        }
    }

    Ok(())
}


fn request_to_response(server_ctx: &ServerContext, ms: &mut MetaStorage, ctx: &mut Option<DCContext>, req: Request) -> Response {
    match (req, ctx) {
        (Request::NewDataCapsule(dc), _) => handle_create(dc, ms, &server_ctx.pk),
        (Request::ReadMetadata(dc), _) => handle_read_meta(dc, &ms),
        (Request::Init(dc_name), ctx) => handle_init(dc_name, &server_ctx.db, ctx),
        (Request::Write(data), Some(ctx)) => handle_write(data, ctx),
        (Request::Commit(additional_hash, sig), Some(ctx)) => {
            handle_commit(ctx, &server_ctx.pk, &additional_hash, &sig)
        }
        (Request::Read(hash), Some(ctx)) => handle_read(hash, &ctx.ds),
        (Request::Proof(hash), Some(ctx)) => build_proof(hash, ctx),
        (Request::FreshestCommits, Some(ctx)) => handle_freshness(&ctx.os),
        (Request::Records(hash), Some(ctx)) => get_all_leaves(&ctx.ns, &hash),
        _ => {
            // a request that needs to be in the context of a dc, but
            // no init message has been received
            Response::Failed
        }
    }
}



fn handle_create(dc: DataCapsule, ms: &mut MetaStorage, signing_key: &PrivateKey) -> Response {
    let hash = hash_dc_metadata(&dc.creator_pub_key, &dc.writer_pub_key, &dc.description);
    let creator_pk = deserialize_pubkey(&dc.creator_pub_key);
    let good = verify_signature(&dc.signature, &hash, &creator_pk);
    if good {
        match ms.store(&hash, &dc) {
            Ok(()) => Response::NewDataCapsule(sign(&hash, signing_key)),
            Err(_) => Response::Failed,
        }
    } else {
        Response::Failed
    }
}

fn handle_read_meta(dc: Hash, ms: &MetaStorage) -> Response {
    match ms.get(&dc) {
        Ok(Some(ds)) => Response::ReadMetadata(ds),
        _ => Response::Failed,
    }
}

fn handle_init(
    dc_name: Hash,
    db: &Db,
    ctx: &mut Option<DCContext>,
) -> Response {
    let writer_pk = match MetaStorage::get_writer_pk(&db, &dc_name) {
        Ok(Some(v)) => deserialize_pubkey(&v),
        _ => return Response::Failed,
    };
    let cc = match DCContext::new(dc_name, db, writer_pk) {
        Ok(c) => c,
        _ => return Response::Failed,
    };
    *ctx = Some(cc);
    Response::Init
}

fn handle_write(data: Vec<u8>, ctx: &mut DCContext) -> Response {
    let record_name = hash_data(&data);
    if let Err(e) = ctx.ds.store(&record_name, &data) {
        tracing::error!("ds error: {:?}", e);
        Response::Failed
    } else {
        ctx.uncommitted_hashes.push(record_name);
        Response::Write
    }
}

fn handle_commit(
    ctx: &mut DCContext,
    signing_key: &PrivateKey,
    additional_hash: &Hash,
    client_signature: &Signature,
) -> Response {
    let (rbs, tns, additional_hash_parent, root, tree_depth) =
        merkle_tree_storage(&ctx.uncommitted_hashes, additional_hash);

    ctx.uncommitted_hashes.clear();

    if !verify_signature(client_signature, &root.name, &ctx.writer_pk) {
        tracing::error!("bad sig");
        return Response::Failed;
    }

    for rb in rbs {
        if let Err(e) = ctx.rs.store(&rb.name, &rb.parent) {
            tracing::error!("ds error: {:?}", e);
            return Response::Failed;
        }
    }

    for tn in tns {
        if let Err(e) = ctx.ns.store(
            &tn.name,
            &StoredNode {
                parent: tn.parent,
                root_info: None,
                children: tn.children,
            },
        ) {
            tracing::error!("ds error: {:?}", e);
            return Response::Failed;
        }
    }

    // last, signed node
    if let Err(e) = ctx.ns.store(
        &root.name,
        &StoredNode {
            parent: None,
            root_info: Some((tree_depth, client_signature.clone())),
            children: root.children,
        },
    ) {
        tracing::error!("ds error: {:?}", e);
        return Response::Failed;
    }

    // mark root node as orphan, and additional hash as non-orphan
    if let Err(e) = ctx
        .os
        .replace(additional_hash, &root.name, client_signature)
    {
        tracing::error!("ds error: {:?}", e);
        return Response::Failed;
    }

    // set parent of additional hash if node exists
    // node may not exist, or may already have a parent if branching occurs
    match ctx.ns.get(additional_hash) {
        Ok(Some(mut stored_node)) => {
            if stored_node.parent.is_none() {
                stored_node.parent = Some(additional_hash_parent);
                if let Err(e) = ctx.ns.store(additional_hash, &stored_node) {
                    tracing::error!("ds error: {:?}", e);
                    return Response::Failed;
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("ds error: {:?}", e);
            return Response::Failed;
        }
    }

    Response::Commit(sign(&root.name, signing_key))
}

fn handle_read(hash: Hash, ds: &DataStorage) -> Response {
    match ds.get(&hash) {
        Ok(Some(r)) => Response::Read(r),
        _ => Response::Failed,
    }
}

fn build_proof(mut hash: Hash, ctx: &mut DCContext) -> Response {
    // every committed record should have a parent
    let mut parent = match ctx.rs.get(&hash) {
        Ok(Some(p)) => p,
        _ => return Response::Failed,
    };

    let mut nodes = Vec::new();
    let mut root = None;
    let mut root_parent = None;

    // go up the chain (modifying hash and parent)
    while !ctx.read_state.contains(&hash) {
        let parent_node = match ctx.ns.get(&parent) {
            Ok(Some(p)) => p,
            _ => return Response::Failed,
        };
        nodes.push(parent_node.children);
        if let Some((_, signature)) = parent_node.root_info {
            if !ctx.read_state.contains(&parent) {
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
                let parent_node = match ctx.ns.get(&p) {
                    Ok(Some(p)) => p,
                    _ => break,
                };
                extras.push(parent_node.children);
                if ctx.read_state.contains(&p) {
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
        ctx.read_state.add_signed_hash(h);
    }
    for n in &nodes {
        ctx.read_state.add_proven_node(n);
    }
    Response::Proof { root, nodes }
}

fn handle_freshness(os: &OrphanStorage) -> Response {
    match os.all_orphans() {
        Ok(Some(v)) => Response::FreshestCommits(v),
        _ => Response::Failed,
    }
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

    let additional_hash = level.remove(0);
    Response::Records(level, additional_hash)
}
