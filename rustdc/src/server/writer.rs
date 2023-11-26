use std::net::SocketAddr;

use futures::{SinkExt, StreamExt};
use sled::Db;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::shared::crypto::{
    deserialize_pubkey, hash_data, sign, verify_signature, Hash, PrivateKey, PublicKey, SignedHash,
};
use crate::shared::merkle::merkle_tree_storage;
use crate::shared::request::{Request, Response, ServerCodec, WriteRequest};

use super::storage::{
    DataStorage, MetaStorage, NodeStorage, RecordStorage, SequenceStorage, StoredNode,
};
use super::DCServerError;

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
    let mut ss = SequenceStorage::new(&db, dc_name)?;

    let writer_pk = match MetaStorage::get_writer_pk(&db, dc_name)? {
        Some(v) => deserialize_pubkey(&v),
        None => return Err(DCServerError::MissingStorage("writer_pk".into())),
    };

    let mut uncommitted_hashes: Vec<Hash> = Vec::new();
    let mut uncommitted_seqnos: Vec<u64> = Vec::new();

    loop {
        let req = match stream.next().await {
            Some(Ok(Request::Write(w))) => w,
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
            WriteRequest::Data(data) => {
                // need to get the sequence number, store data block,
                // send response, and append to uncommitted_* vectors
                let r = handle_data(&mut ds, data);
                let resp = if r.is_some() {
                    Response::WriteData
                } else {
                    Response::Failed
                };
                if let Err(e) = stream.send(resp).await {
                    tracing::error!("sending error on {}: {:?}", addr, e);
                    break;
                }
                if let Some((name, seqno)) = r {
                    uncommitted_hashes.push(name);
                    uncommitted_seqnos.push(seqno);
                }
            }
            WriteRequest::Commit {
                additional_hash,
                signature,
            } => {
                // need to build merkle tree, check that signature is fine,
                // store all records, store all nodes, store sequence numbers
                let r = handle_commit(
                    &mut rs,
                    &mut ns,
                    &mut ss,
                    &writer_pk,
                    signing_key,
                    &uncommitted_hashes,
                    &uncommitted_seqnos,
                    &additional_hash,
                    &signature,
                );
                let r = match r {
                    Some(s) => Response::WriteCommit(s),
                    None => Response::Failed,
                };
                if let Err(e) = stream.send(r).await {
                    tracing::error!("sending error on {}: {:?}", addr, e);
                    break;
                }
                uncommitted_hashes.clear();
                uncommitted_seqnos.clear();
            }
        };
    }

    // beware of uncommitted hashes
    // but don't delete them, because they might existed before this connection
    // especially if someone malicious is trying to get a record deleted

    Ok(())
}

fn handle_data(ds: &mut DataStorage, data: Vec<u8>) -> Option<(Hash, u64)> {
    let record_name = hash_data(&data);
    if data.len() < 8 + 16 {
        tracing::error!("data too short");
        return None;
    }
    let seqno = u64::from_le_bytes(data[0..8].try_into().unwrap());
    if let Err(e) = ds.store(&record_name, &data) {
        tracing::error!("ds error: {:?}", e);
        None
    } else {
        Some((record_name, seqno))
    }
}

fn handle_commit(
    rs: &mut RecordStorage,
    ns: &mut NodeStorage,
    ss: &mut SequenceStorage,
    writer_pk: &PublicKey,
    signing_key: &PrivateKey,
    uncommitted_hashes: &[Hash],
    uncommitted_seqnos: &[u64],
    additional_hash: &Hash,
    client_signature: &SignedHash,
) -> Option<SignedHash> {
    let (rbs, tns, root) =
        merkle_tree_storage(uncommitted_hashes, uncommitted_seqnos, additional_hash);

    let rcvd_hash = verify_signature(client_signature, writer_pk)?;
    if root != rcvd_hash {
        return None;
    }

    for rb in rbs {
        if let Err(e) = rs.store(&rb.name, rb.sequence_number, &rb.parent) {
            tracing::error!("ds error: {:?}", e);
            return None;
        }
        if let Err(e) = ss.store(rb.sequence_number, &rb.name) {
            tracing::error!("ds error: {:?}", e);
            return None;
        }
    }

    for tn in tns {
        if let Err(e) = ns.store(
            &tn.name,
            &StoredNode {
                parent: tn.parent,
                signature: if tn.signed {
                    Some(client_signature.clone())
                } else {
                    None
                },
                children: tn.children,
            },
        ) {
            tracing::error!("ds error: {:?}", e);
            return None;
        }
    }

    Some(sign(&root, signing_key))
}
