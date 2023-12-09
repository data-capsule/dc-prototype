use futures::{
    future,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    net::TcpStream,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tokio_util::codec::Framed;

use crate::{
    client::DCClientError,
    shared::crypto::{
        decrypt, encrypt, hash_data, sign, verify_signature, Hash, PrivateKey, PublicKey,
        Signature, SymmetricKey,
    },
    shared::{
        crypto::hash_record_header,
        request::{ClientCodec, InitRequest, RWRequest, Request, Response},
    },
    shared::{dc_repr, readstate::ReadState},
};

use super::initialize_connection;

/// This connection can perform reads and writes.
pub struct WriterConnection {
    send_half: SendHalf,
    receive_half: ReceiveHalf,
}

struct SendHalf {
    connection_w: SplitSink<Framed<TcpStream, ClientCodec>, Request>,
    inner_w: UnboundedSender<(WriterSync, Hash)>,
    encryption_key: SymmetricKey,
    writer_signing_key: PrivateKey,
    dc_name: Hash,
}

struct ReceiveHalf {
    connection_r: SplitStream<Framed<TcpStream, ClientCodec>>,
    inner_r: UnboundedReceiver<(WriterSync, Hash)>,
    encryption_key: SymmetricKey,
    server_public_key: PublicKey,
    writer_public_key: PublicKey,
    // read_state: ReadState,
}

enum WriterSync {
    Write,
    Sign,
    Read,
    Prove,
}

#[derive(Debug, Clone)]
pub enum WriterOperation {
    Write((dc_repr::RecordBody, Vec<dc_repr::RecordBackPtr>)), // (body, record_backptrs)
    Sign(Hash),                                                            // record name
    Read(Hash),                                                            // ^
    Prove(Hash),                                                           // ^
}

#[derive(Debug, Clone)]
pub enum WriterResponse {
    Write(Hash),                                                // record name (hash pointer)
    Sign(bool),  // whether server was able to persist signature
    Read(Option<(dc_repr::RecordBody, dc_repr::RecordHeader)>), // (body, header)
    Prove(bool), // whether server was able to return a proof
}

impl WriterConnection {
    pub async fn new(
        dc_name: Hash,
        server_address: SocketAddr,
        server_public_key: PublicKey,
        writer_public_key: PublicKey,
        writer_signing_key: PrivateKey,
        encryption_key: SymmetricKey,
    ) -> Result<Self, DCClientError> {
        let stream = initialize_connection(server_address, InitRequest::Write(dc_name)).await?;
        let (connection_w, connection_r) = stream.split();
        let (inner_w, inner_r) = mpsc::unbounded_channel();
        Ok(Self {
            send_half: SendHalf {
                connection_w,
                inner_w,
                encryption_key,
                writer_signing_key,
                dc_name,
            },
            receive_half: ReceiveHalf {
                connection_r,
                inner_r,
                encryption_key,
                server_public_key,
                writer_public_key,
                // read_state: ReadState::new(),
            },
        })
    }

    /// Does all the operations, in order. Concurrently sends and receives on
    /// the underlying TCP connection so that it does not have to wait for
    /// round trips. Fills responses with a hash for each successful operation
    /// (for records, the hash of the record. For commits, the commit's root hash).
    ///
    /// In case of failure, the `get_last_commit_hash` method can be used to figure
    /// out the last successful commit. A new connection should then be made,
    /// using the checkpoint as a starting point, then any unsuccessful
    /// operations may be re-done.
    pub async fn do_operations<'a>(
        &mut self,
        operations: &[WriterOperation],
        responses: &mut Vec<WriterResponse>,
    ) -> Result<(), DCClientError> {
        // Some implementation details:
        // in addition to the connection and encryption stuff, we have the
        // following state variables to worry about:
        //   last_commit_hash: Hash
        //   uncommitted_hashes: Vec<Hash>
        // The first one is the "checkpoint". Be careful that in the case of
        // errors, this should only reflect fully verified commits
        // Uncommitted hashes we won't worry about in the case of errors
        //
        // You may also be wondering: why not just do all the sends,
        // then all the receives? Why bother with the fancy future join stuff?
        // The answer is TCP backpressure. If we do all the sends without
        // processing any receives, at some point the server will stop being
        // able to send results back to us, and the connection will close.

        let f1 = Self::send_operations(&mut self.send_half, operations);
        let f2 = Self::receive_operations(&mut self.receive_half, operations.len(), responses);

        let (e1, e2) = future::join(f1, f2).await;

        let res = match (e1, e2) {
            (Err(e), _) | (_, Err(e)) => Err(e),
            (Ok(()), Ok(())) => Ok(()),
        };

        // if res.is_err() {
        //     // throw away transient variables
        //     self.send_half.uncommitted_hashes.clear();
        // }
        res
    }

    async fn send_operations<'a>(
        half: &mut SendHalf,
        operations: &[WriterOperation],
    ) -> Result<(), DCClientError> {
        for op in operations {
            let (req, sync, record_name) = match op {
                WriterOperation::Write((
                    body,
                    record_backptrs,
                )) => {
                    // let body = encrypt(plaintext_body, &half.encryption_key);
                    let body_ptr = hash_data(&body);
                    let header = dc_repr::RecordHeader {
                        body_ptr,
                        record_backptrs: record_backptrs.clone(),
                    };
                    let record_name = hash_record_header(&header);
                    (
                        Request::RW(RWRequest::Write(dc_repr::Record { body: body.to_vec(), header })),
                        WriterSync::Write,
                        record_name,
                    )
                }
                WriterOperation::Sign(record_name) => {
                    let signature = sign(record_name, &half.writer_signing_key);
                    (
                        Request::RW(RWRequest::Sign(*record_name, signature)),
                        WriterSync::Sign,
                        *record_name,
                    )
                }
                WriterOperation::Read(record_name) => (
                    Request::RW(RWRequest::Read(*record_name)),
                    WriterSync::Read,
                    *record_name,
                ),
                WriterOperation::Prove(record_name) => (
                    Request::RW(RWRequest::Proof(*record_name)),
                    WriterSync::Prove,
                    *record_name,
                ),
            };
            // NOTE: should not flush
            // we want the possibility of multiple messages per TCP frame
            half.connection_w.feed(req).await?;
            if half.inner_w.send((sync, record_name)).is_err() {
                return Err(DCClientError::Other("mpsc".to_string()));
            }
        }
        // make sure all the requests for this batch actually get sent
        half.connection_w.flush().await?;
        Ok(())
    }

    async fn receive_operations<'a>(
        half: &mut ReceiveHalf,
        num_recvs: usize,
        responses: &mut Vec<WriterResponse>,
    ) -> Result<(), DCClientError> {
        for _ in 0..num_recvs {
            let resp = match half.connection_r.next().await {
                Some(r) => r?,
                None => return Err(DCClientError::Other("stream ended".to_string())),
            };
            let (sync, record_name) = match half.inner_r.recv().await {
                Some(p) => p,
                None => return Err(DCClientError::Other("mpsc".to_string())),
            };
            let res = match (resp, sync) {
                (Response::Failed, WriterSync::Write | WriterSync::Sign) => {
                    return Err(DCClientError::ServerError("server failure".into()));
                }
                (Response::Failed, WriterSync::Read) => WriterResponse::Read(None),
                (Response::Failed, WriterSync::Prove) => WriterResponse::Prove(false),
                // (Response::WriteData((record_name, ack)), WriterSync::Write) => {
                //     if verify_signature(&ack, &record_name, &half.server_public_key) {
                //         WriterResponse::Write(record_name)
                //     } else {
                //         return Err(DCClientError::BadSignature);
                //     }
                // }
                (Response::WriteData(record_name), WriterSync::Write) => {
                    WriterResponse::Write(record_name)
                }
                (Response::WriteSign((record_name, ack)), WriterSync::Sign) => {
                    if verify_signature(&ack, &record_name, &half.server_public_key) {
                        WriterResponse::Sign(true)
                    } else {
                        return Err(DCClientError::BadSignature);
                    }
                }
                (Response::ReadRecord(record), WriterSync::Read) => {
                    // TODO: check well-formedness like in previous impl?
                    // if hash_data(&data) == expected_hash {
                    //     WriterResponse::Read(Some(decrypt(&data, &half.encryption_key)))
                    // } else {
                    //     return Err(DCClientError::MismatchedHash);
                    // }
                    let plaintext_body = decrypt(&record.body, &half.encryption_key);
                    WriterResponse::Read(Some((plaintext_body, record.header)))
                }
                (Response::ReadProof(best_effort_proof), WriterSync::Prove) => {
                    // TODO: potentially heavy synchronous block within async context
                    verify_proof(
                        &record_name,
                        &best_effort_proof,
                        &half.writer_public_key,
                        // &mut half.read_state,
                    )?;
                    WriterResponse::Prove(true)
                }
                _ => return Err(DCClientError::ServerError("mismatched response".into())),
            };
            responses.push(res)
        }
        Ok(())
    }
}

pub(crate) fn verify_proof(
    record_name_to_prove: &Hash,
    best_effort_proof: &dc_repr::BestEffortProof,
    writer_public_key: &PublicKey,
    // read_state: &mut ReadState,
) -> Result<(), DCClientError> {
    // TODO: actual witness cache
    let mut temp_witness_cache: HashMap<Hash, dc_repr::RecordWitness> = HashMap::new(); // record_name : witness

    if let Some((signed_record_name, signature)) = &best_effort_proof.signature {
        // if server returns a bad signature, assume rest of best-effort-proof doesn't help
        // (e.g. server is malicious) and end early
        if !verify_signature(&signature, &signed_record_name, writer_public_key) {
            return Err(DCClientError::BadProof(
                "bad proof for record_name ...".into(),
            ));
        }

        temp_witness_cache.insert(
            *signed_record_name,
            dc_repr::RecordWitness::Signature(signature.to_vec()),
        );

        if *signed_record_name == *record_name_to_prove {
            return Ok(());
        }
    }

    let mut iter = best_effort_proof.chain.clone().into_iter();
    match iter.next() {
        None => Err(DCClientError::BadProof(
            "bad proof for record_name ...".into(),
        )),
        Some(first_in_chain) => {
            if hash_record_header(&first_in_chain) != *record_name_to_prove {
                return Err(DCClientError::BadProof(
                    "bad proof for record_name ...".into(),
                ));
            }

            let mut prev_record_header = first_in_chain;
            while let Some(curr_record_header) = iter.next() {
                let prev_record_name = hash_record_header(&prev_record_header);
                let curr_record_name = hash_record_header(&curr_record_header);
                if temp_witness_cache.contains_key(&curr_record_name) {
                    return Ok(());
                }
                // if curr_record_header.prev_record_ptr == prev_record_name
                //     || curr_record_header
                //         .additional_record_ptrs
                if curr_record_header.record_backptrs
                        .clone()
                        .into_iter()
                        .any(|p| p.ptr == prev_record_name)
                {
                    prev_record_header = curr_record_header;
                } else {
                    return Err(DCClientError::BadProof(
                        "bad proof for record_name ...".into(),
                    ));
                }
            }
            Err(DCClientError::BadProof(
                "bad proof for record_name ...".into(),
            ))
        }
    }
}
