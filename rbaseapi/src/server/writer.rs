use std::time::Instant;

use fakep2p::{P2PMessageBody, P2PSender};
use postcard::{from_bytes, to_stdvec};
use quick_cache::sync::Cache;
use sled::Db;
use tokio::sync::mpsc;

use crate::shared::config;
use crate::shared::crypto::{
    deserialize_pubkey, hash_dc_metadata, hash_record_header, sign, verify_signature, Hash,
    PrivateKey, PublicKey, Signature,
};
use crate::shared::dc_repr::{self, Metadata};
use crate::shared::request::{ManageRequest, RWRequest, Request, Response, SubscribeRequest};
use crate::server::storage;

use super::storage::{
    DCMetadataStorage, RecordBodyStorage, RecordHeaderStorage, RecordWitnessStorage,
};
use super::withp2p::ServerContext;
use super::DCServerError;

struct DCContext {
    bs: RecordBodyStorage,
    hs: RecordHeaderStorage,
    ws: RecordWitnessStorage,
    writer_pk: PublicKey,
    client_proven_hash_cache: Cache<Hash, ()>,
}

impl DCContext {
    fn new(dc_name: Hash, db: &Db, writer_pk: PublicKey) -> Result<Self, sled::Error> {
        Ok(Self {
            bs: RecordBodyStorage::new(db, &dc_name)?,
            hs: RecordHeaderStorage::new(db, &dc_name)?,
            ws: RecordWitnessStorage::new(db, &dc_name)?,
            writer_pk,
            client_proven_hash_cache: Cache::new(config::CACHE_SIZE),
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
    let mut ms = DCMetadataStorage::new(&server_ctx.db)?;
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
        let many_responses: Vec<Response> = many_requests
            .into_iter()
            .map(|r| request_to_response(&server_ctx, &mut ms, &mut ctx, r))
            .collect();
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

fn request_to_response(
    server_ctx: &ServerContext,
    ms: &mut DCMetadataStorage,
    ctx: &mut Option<DCContext>,
    req: Request,
) -> Response {
    match (req, ctx) {
        (Request::Manage(ManageRequest::Create(dc)), _) => handle_create(dc, ms, &server_ctx.pk, &server_ctx.db),
        (Request::Manage(ManageRequest::Read(dc)), _) => handle_read_meta(dc, &ms),
        (Request::Init(dc_name), ctx) => handle_init(dc_name, &server_ctx.db, ctx),
        (Request::RW(RWRequest::Write(record)), Some(ctx)) => handle_write(&record, ctx),
        (Request::RW(RWRequest::Sign(hash, signature)), Some(ctx)) => {
            handle_sign(hash, signature, ctx, &server_ctx.pk)
        }
        (Request::RW(RWRequest::Read(hash)), Some(ctx)) => handle_read(&hash, &ctx.bs, &ctx.hs),
        (Request::RW(RWRequest::Proof(hash)), Some(ctx)) => Response::ReadProof(best_effort_proof(
            &hash,
            &mut ctx.hs,
            &mut ctx.ws,
            &ctx.client_proven_hash_cache,
        )),
        (Request::Subscribe(SubscribeRequest::FreshestSignedRecords), Some(ctx)) => todo!(),
        _ => {
            // a request that needs to be in the context of a dc, but
            // no init message has been received
            Response::Failed
        }
    }
}

fn handle_create(dc: Metadata, ms: &mut DCMetadataStorage, signing_key: &PrivateKey, db: &Db) -> Response {
    let hash = hash_dc_metadata(&dc.creator_pub_key, &dc.writer_pub_key, &dc.description);
    let creator_pk = deserialize_pubkey(&dc.creator_pub_key);
    let good = verify_signature(&dc.signature, &hash, &creator_pk);
    if good {
        let r: Result<(), DCServerError> = (|| {
            ms.store(&hash, &dc)?;
            storage::init_marked(db, &hash)?;
            Ok(())
        })();
        match r {
            Ok(()) => Response::ManageCreate(sign(&hash, signing_key)),
            Err(_) => Response::Failed,
        }
    } else {
        Response::Failed
    }
}

fn handle_read_meta(dc: Hash, ms: &DCMetadataStorage) -> Response {
    match ms.get(&dc) {
        Ok(Some(ds)) => Response::ManageRead(ds),
        _ => Response::Failed,
    }
}

fn handle_init(dc_name: Hash, db: &Db, ctx: &mut Option<DCContext>) -> Response {
    let writer_pk = match DCMetadataStorage::get_writer_pk(&db, &dc_name) {
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

fn handle_write(record: &dc_repr::Record, ctx: &mut DCContext) -> Response {
    match store_record(&record, &mut ctx.bs, &mut ctx.hs) {
        Ok(record_name) => {
            // Response::WriteData((record_name, sign(&record_name, signing_key)))
            Response::WriteData(record_name)
        }
        Err(e) => {
            tracing::error!("store record error: {:?}", e);
            Response::Failed
        }
    }
}

fn store_record(
    record: &dc_repr::Record,
    bs: &mut RecordBodyStorage,
    hs: &mut RecordHeaderStorage,
) -> Result<Hash, DCServerError> {
    // TODO: input validation eg making sure body_ptr is valid hash of body
    bs.store(&record.header.body_ptr, &record.body)?;
    let record_name = hash_record_header(&record.header);
    hs.store(&record_name, &record.header)?;
    Ok(record_name)
}

fn handle_read(record_name: &Hash, bs: &RecordBodyStorage, hs: &RecordHeaderStorage) -> Response {
    match read_record(record_name, bs, hs) {
        Ok(r) => Response::ReadRecord(r),
        Err(e) => {
            tracing::error!("read record error: {:?}", e);
            Response::Failed
        }
    }
}

fn read_record(
    record_name: &Hash,
    bs: &RecordBodyStorage,
    hs: &RecordHeaderStorage,
) -> Result<dc_repr::Record, DCServerError> {
    // TODO: organize error types/messages
    let header = hs.get(record_name)?.ok_or(DCServerError::MissingStorage(
        format!("missing header for record named {:?}", record_name).into(),
    ))?;
    let body = bs
        .get(&header.body_ptr)?
        .ok_or(DCServerError::MissingStorage(
            format!("missing body for record named {:?}", record_name).into(),
        ))?;
    Ok(dc_repr::Record { body, header })
}

fn handle_sign(
    record_name: Hash,
    signature: Signature,
    ctx: &mut DCContext,
    signing_key: &PrivateKey,
) -> Response {
    if !verify_signature(&signature, &record_name, &ctx.writer_pk) {
        tracing::error!("bad sig");
        Response::Failed
    } else {
        match ctx
            .ws
            .update_record_witness(&record_name, &dc_repr::RecordWitness::Signature(signature))
        {
            Ok(_) => {
                let hs2 = ctx.hs.clone();
                let ws2 = ctx.ws.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    match update_ancestor_witnesses(&record_name, hs2, ws2) {
                        Ok(_) => (),
                        Err(e) => {
                            tracing::error!("update_ancestor_witnesses error: {:?}", e);
                        }
                    }
                });
                Response::WriteSign((record_name, sign(&record_name, signing_key)))
            }
            Err(e) => {
                tracing::error!("store signature error: {:?}", e);
                Response::Failed
            }
        }
    }
}

// TODO: better error handling? shouldn't affect eventual correctness but might affect perf
fn update_ancestor_witnesses(
    base_record_name: &Hash,
    hs: RecordHeaderStorage,
    mut ws: RecordWitnessStorage,
) -> Result<(), DCServerError> {
    let mut curr_wave: Vec<(Hash, Hash)> = Vec::new(); // (record_name, parent_record_name)
    let base_record_header = hs
        .get(base_record_name)?
        .ok_or(DCServerError::MissingStorage(
            format!("missing header for record named {:?}", base_record_name).into(),
        ))?;
    // curr_wave.push((base_record_header.prev_record_ptr, *base_record_name));
    curr_wave.append(
        &mut base_record_header
            .record_backptrs
            .iter()
            .map(|p| (p.ptr, *base_record_name))
            .collect(),
    );
    let mut dist_from_new_sig: u64 = 1;

    while !curr_wave.is_empty() {
        let mut next_wave: Vec<(Hash, Hash)> = Vec::new();
        for (record_name, parent_record_name) in curr_wave.iter() {
            let record_header = hs.get(record_name)?.ok_or(DCServerError::MissingStorage(
                format!("missing header for record named {:?}", record_name).into(),
            ))?;
            let new_proposed_witness =
                dc_repr::RecordWitness::NextRecordPtr(*parent_record_name, dist_from_new_sig);

            // if new_proposed_witness is not closer than old_witness for this record,
            // then we know we can't get closer witnesses for ancestors of this record.
            let old_witness = ws.update_record_witness(record_name, &new_proposed_witness)?;
            if new_proposed_witness.closer_than(&old_witness) {
                // next_wave.push((record_header.prev_record_ptr, *record_name));
                next_wave.append(
                    &mut record_header
                        .record_backptrs
                        .iter()
                        .map(|p| (p.ptr, *record_name))
                        .collect(),
                )
            }
        }
        curr_wave = next_wave;
        dist_from_new_sig += 1;
    }

    Ok(())
}

// note that this builds a proof that is best-effort and not guaranteed to be complete
// e.g. in the presence of holes, we can still return a partial proof which the client
// can complete (faster now) by sending another proof request.
fn best_effort_proof(
    record_name: &Hash,
    hs: &mut RecordHeaderStorage,
    ws: &mut RecordWitnessStorage,
    client_proven_hash_cache: &Cache<Hash, ()>,
) -> dc_repr::BestEffortProof {
    let mut proof = dc_repr::BestEffortProof {
        chain: Vec::new(),
        signature: None,
    };
    let mut curr = *record_name;
    loop {
        if let Ok(Some(curr_header)) = hs.get(&curr) {
            proof.chain.push(curr_header);
        } else {
            // partial proof
            return proof;
        }

        // optimization: mirror client cache
        if let Some(_) = client_proven_hash_cache.get(&curr) {
            // completed proof
            // update client_proven_hash_cache to mirror client's instance
            for proven_record_header in &proof.chain {
                client_proven_hash_cache.insert(hash_record_header(&proven_record_header), ());
            }
            return proof;
        }

        let witness_for_curr: dc_repr::RecordWitness = ws.get(&curr).ok().into();
        match witness_for_curr {
            dc_repr::RecordWitness::Signature(signature) => {
                proof.signature = Some((curr, signature));
                // completed proof
                // update proven_hash_cache to mirror client's instance
                for proven_record_header in &proof.chain {
                    client_proven_hash_cache.insert(hash_record_header(&proven_record_header), ());
                }
                return proof;
            }
            dc_repr::RecordWitness::NextRecordPtr(next, _) => {
                curr = next;
            }
            dc_repr::RecordWitness::None => {
                // partial proof
                return proof;
            }
        }
    }
}
