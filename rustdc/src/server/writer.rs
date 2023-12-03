use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures::SinkExt;
use sled::Db;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::shared::crypto::{
    deserialize_pubkey, hash_record_header, sign, verify_signature, Hash, PrivateKey, PublicKey,
    Signature,
};
use crate::shared::dc_repr;
use crate::shared::request::{RWRequest, Request, Response, ServerCodec};

use super::storage::{
    DCMetadataStorage, RecordBodyStorage, RecordHeaderStorage, RecordWitnessStorage,
};
use super::{wait_for_request, DCServerError};

pub async fn process_writer(
    signing_key: &PrivateKey,
    db: Db,
    dc_name: &Hash,
    mut stream: Framed<TcpStream, ServerCodec>,
    addr: SocketAddr,
) -> Result<(), DCServerError> {
    let mut bs = RecordBodyStorage::new(&db, dc_name)?;
    let mut hs = RecordHeaderStorage::new(&db, dc_name)?;
    let mut ws = RecordWitnessStorage::new(&db, dc_name)?;

    // separate db connection for use by concurrent calls to `update_ancestor_witnesses`
    // without slowing down main loop.
    // TODO: would it be more or less efficient to just directly open a new connection on every invocation of update_ancestor_witnesses?
    // TODO: do we need to use tokio::sync::Mutex instead of std?
    let hs2 = Arc::new(Mutex::new(RecordHeaderStorage::new(&db, dc_name)?));
    let ws2 = Arc::new(Mutex::new(RecordWitnessStorage::new(&db, dc_name)?));

    let writer_pk = match DCMetadataStorage::get_writer_pk(&db, dc_name)? {
        Some(v) => deserialize_pubkey(&v),
        None => return Err(DCServerError::MissingStorage("writer_pk".into())),
    };

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
            RWRequest::Write(record) => {
                match store_record(&record, &mut bs, &mut hs) {
                    Ok(record_name) => {
                        // TODO: check that signing_key is server's private signing key
                        Response::WriteData(sign(&record_name, signing_key))
                    }
                    Err(e) => {
                        tracing::error!("store record error: {:?}", e);
                        Response::Failed
                    }
                }
            }
            RWRequest::Sign(record_name, signature) => {
                if !verify_signature(&signature, &record_name, &writer_pk) {
                    tracing::error!("bad sig");
                    Response::Failed
                } else {
                    match ws.update_record_witness(
                        &record_name,
                        &dc_repr::RecordWitness::Signature(signature),
                    ) {
                        Ok(_) => {
                            // TODO: check correctness
                            let hs2 = hs2.clone();
                            let ws2 = ws2.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                update_ancestor_witnesses(&record_name, hs2, ws2);
                            });
                            Response::WriteSign(sign(&record_name, signing_key))
                        }
                        Err(e) => {
                            tracing::error!("store signature error: {:?}", e);
                            Response::Failed
                        }
                    }
                }
            }
            RWRequest::Read(record_name) => {
                match read_record(&record_name, &mut bs, &mut hs) {
                    Ok(r) => Response::ReadRecord(r),
                    Err(e) => {
                        tracing::error!("read record error: {:?}", e);
                        Response::Failed
                    }
                }
            }
            RWRequest::Proof(record_name) => {
                Response::ReadProof(best_effort_proof(&record_name, &mut hs, &mut ws))
            }
        };
        stream.feed(resp).await?
    }

    // beware of uncommitted hashes
    // but don't delete them, because they might existed before this connection
    // especially if someone malicious is trying to get a record deleted

    Ok(())
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

fn read_record(
    record_name: &Hash,
    bs: &mut RecordBodyStorage,
    hs: &mut RecordHeaderStorage,
) -> Result<dc_repr::Record, DCServerError> {
    // TODO: organize error types/messages
    let header = hs.get(record_name)?.ok_or(DCServerError::MissingStorage(
        "missing header for record named ...".into(),
    ))?;
    let body = bs
        .get(&header.body_ptr)?
        .ok_or(DCServerError::MissingStorage(
            "missing body for record named ...".into(),
        ))?;
    Ok(dc_repr::Record { body, header })
}

// TODO: better error handling? shouldn't affect eventual correctness but might affect perf
fn update_ancestor_witnesses(
    base_record_name: &Hash,
    hs: Arc<Mutex<RecordHeaderStorage>>,
    ws: Arc<Mutex<RecordWitnessStorage>>,
) -> Result<(), DCServerError> {
    let mut curr_wave: Vec<Hash> = Vec::from([*base_record_name]);
    let mut dist_from_new_sig: u64 = 0;

    while !curr_wave.is_empty() {
        let mut next_wave: Vec<Hash> = Vec::new();
        for record_name in curr_wave.iter() {
            let header =
                hs.lock()
                    .unwrap()
                    .get(record_name)?
                    .ok_or(DCServerError::MissingStorage(
                        "missing header for record named ...".into(),
                    ))?;
            let new_proposed_witness =
                dc_repr::RecordWitness::NextRecordPtr(*record_name, dist_from_new_sig);

            // if new_proposed_witness is not closer than old_witness for this record,
            // then we know we can't get closer witnesses for ancestors of this record.
            let old_witness = ws
                .lock()
                .unwrap()
                .update_record_witness(record_name, &new_proposed_witness)?;
            if new_proposed_witness.closer_than(&old_witness) {
                next_wave.push(header.prev_record_ptr);
                next_wave.append(
                    &mut header
                        .additional_record_ptrs
                        .iter()
                        .map(|p| p.ptr)
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
) -> dc_repr::BestEffortProof {
    let mut proof = dc_repr::BestEffortProof {
        chain: Vec::new(),
        signature: None,
    };
    let mut curr = *record_name;
    // TODO: organize this loop better
    loop {
        let witness_for_curr: dc_repr::RecordWitness = ws.get(&curr).ok().into();
        match witness_for_curr {
            dc_repr::RecordWitness::Signature(signature) => {
                proof.signature = Some((curr, signature));
                return proof;
            }
            dc_repr::RecordWitness::NextRecordPtr(next, _) => {
                match hs.get(&curr) {
                    Ok(Some(curr_header)) =>  {
                        proof.chain.push(curr_header);
                        curr = next;
                    }
                    _ => return proof,
                }
            }
            dc_repr::RecordWitness::None => {
                return proof;
            }
        }
    }
}
