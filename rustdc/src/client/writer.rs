use futures::{
    future,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use std::net::SocketAddr;
use tokio::{
    net::TcpStream,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tokio_util::codec::Framed;

use crate::{
    client::DCClientError,
    shared::crypto::{
        encrypt, hash_data, sign, verify_signature, Hash, PrivateKey, PublicKey, SymmetricKey,
    },
    shared::request::{ClientCodec, InitRequest, RWRequest, Request, Response},
    shared::{
        crypto::{decrypt, hash_node, HashNode, Signature},
        merkle::merkle_tree_root,
        readstate::ReadState,
    },
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
    uncommitted_hashes: Vec<Hash>,
}

struct ReceiveHalf {
    connection_r: SplitStream<Framed<TcpStream, ClientCodec>>,
    inner_r: UnboundedReceiver<(WriterSync, Hash)>,
    encryption_key: SymmetricKey,
    server_public_key: PublicKey,
    writer_public_key: PublicKey,
    last_commit_hash: Hash,
    read_state: ReadState,
}

enum WriterSync {
    Write,
    Commit,
    Read,
    Prove,
}

#[derive(Debug, Clone)]
pub enum WriterOperation<'a> {
    Write(&'a [u8]),
    Commit,
    Read(Hash),
    Prove(Hash),
}

#[derive(Debug, Clone)]
pub enum WriterResponse {
    Write(Hash),           // hash of record
    Commit(Hash),          // hash of commit
    Read(Option<Vec<u8>>), // data, if read is successful
    Prove(bool),           // whether server was able to return a proof
}

impl WriterConnection {
    pub async fn new(
        datacapsule_name: Hash,
        server_address: SocketAddr,
        server_public_key: PublicKey,
        writer_public_key: PublicKey,
        writer_signing_key: PrivateKey,
        encryption_key: SymmetricKey,
        last_commit_hash: Hash,
    ) -> Result<Self, DCClientError> {
        let stream =
            initialize_connection(server_address, InitRequest::Write(datacapsule_name)).await?;
        let (connection_w, connection_r) = stream.split();
        let (inner_w, inner_r) = mpsc::unbounded_channel();
        Ok(Self {
            send_half: SendHalf {
                connection_w,
                inner_w,
                encryption_key,
                writer_signing_key,
                uncommitted_hashes: Vec::new(),
            },
            receive_half: ReceiveHalf {
                connection_r,
                inner_r,
                encryption_key,
                server_public_key,
                writer_public_key,
                last_commit_hash,
                read_state: ReadState::new(),
            },
        })
    }

    /// Gets the hash of the last verified commit.
    pub fn get_last_commit_hash(&self) -> Hash {
        self.receive_half.last_commit_hash
    }

    /// Sets the hash of the last commit. The next commit will be a successor of this hash.
    pub fn set_last_commit_hash(&mut self, h: Hash) {
        self.receive_half.last_commit_hash = h;
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
        operations: &[WriterOperation<'a>],
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

        let f1 = Self::send_operations(
            &mut self.send_half,
            self.receive_half.last_commit_hash,
            operations,
        );
        let f2 = Self::receive_operations(&mut self.receive_half, operations.len(), responses);

        let (e1, e2) = future::join(f1, f2).await;

        let res = match (e1, e2) {
            (Err(e), _) | (_, Err(e)) => Err(e),
            (Ok(()), Ok(())) => Ok(()),
        };

        if res.is_err() {
            // throw away transient variables
            self.send_half.uncommitted_hashes.clear();
        }
        res
    }

    async fn send_operations<'a>(
        half: &mut SendHalf,
        mut last_commit_hash: Hash,
        operations: &[WriterOperation<'a>],
    ) -> Result<(), DCClientError> {
        for op in operations {
            let (req, sync, hash) = match op {
                WriterOperation::Write(data) => {
                    // RECORD REQUEST
                    // encrypt the data, add the hash of encrypted data to uncommitted hashes
                    let encrypted_data = encrypt(data, &half.encryption_key);
                    let hash = hash_data(&encrypted_data);
                    half.uncommitted_hashes.push(hash);
                    (
                        Request::RW(RWRequest::Write(encrypted_data)),
                        WriterSync::Write,
                        hash,
                    )
                }
                WriterOperation::Commit => {
                    // COMMIT REQUEST
                    // build a merkle tree, clear the uncommitted hashes,
                    // send a commit request, update the last written hash
                    // updated finished with the root hash
                    let root_hash = merkle_tree_root(&half.uncommitted_hashes, &last_commit_hash);
                    let signature = sign(&root_hash, &half.writer_signing_key);
                    let req = Request::RW(RWRequest::Commit {
                        additional_hash: last_commit_hash,
                        signature,
                    });
                    last_commit_hash = root_hash;
                    half.uncommitted_hashes.clear();
                    (req, WriterSync::Commit, root_hash)
                }
                WriterOperation::Read(hash) => {
                    (Request::RW(RWRequest::Read(*hash)), WriterSync::Read, *hash)
                }
                WriterOperation::Prove(hash) => (
                    Request::RW(RWRequest::Proof(*hash)),
                    WriterSync::Prove,
                    *hash,
                ),
            };
            // NOTE: should not flush
            // we want the possibility of multiple messages per TCP frame
            half.connection_w.feed(req).await?;
            if half.inner_w.send((sync, hash)).is_err() {
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
            let (sync, expected_hash) = match half.inner_r.recv().await {
                Some(p) => p,
                None => return Err(DCClientError::Other("mpsc".to_string())),
            };
            let res = match (resp, sync) {
                (Response::Failed, WriterSync::Write | WriterSync::Commit) => {
                    return Err(DCClientError::ServerError("server failure".into()));
                }
                (Response::Failed, WriterSync::Read) => WriterResponse::Read(None),
                (Response::Failed, WriterSync::Prove) => WriterResponse::Prove(false),
                (Response::WriteData, WriterSync::Write) => WriterResponse::Write(expected_hash),
                (Response::WriteCommit(signature), WriterSync::Commit) => {
                    if verify_signature(&signature, &expected_hash, &half.server_public_key) {
                        // commit is confirmed! woohoo
                        // set checkpoint variable
                        half.last_commit_hash = expected_hash;
                        WriterResponse::Commit(expected_hash)
                    } else {
                        return Err(DCClientError::BadSignature);
                    }
                }
                (Response::ReadData(data), WriterSync::Read) => {
                    // DATA RESPONSE: where all the magic happens
                    // checks that the hash of the data is correct, then decrypts the data
                    if hash_data(&data) == expected_hash {
                        WriterResponse::Read(Some(decrypt(&data, &half.encryption_key)))
                    } else {
                        return Err(DCClientError::MismatchedHash);
                    }
                }
                (Response::ReadProof { root, nodes }, WriterSync::Prove) => {
                    verify_proof(
                        &expected_hash,
                        &root,
                        &nodes,
                        &half.writer_public_key,
                        &mut half.read_state,
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
    expected_hash: &Hash,
    root: &Option<(Signature, Hash)>,
    nodes: &[HashNode],
    writer_public_key: &PublicKey,
    read_state: &mut ReadState,
) -> Result<(), DCClientError> {
    // checks the root signature, checks the hash of each node
    // (adding to the cache as it goes)
    // then checks that the given hash is in the cache

    // if the root is provided, check it for validity and add it to the cache
    if let Some(s) = root {
        if verify_signature(&s.0, &s.1, writer_public_key) {
            read_state.add_signed_hash(&s.1);
        } else {
            return Err(DCClientError::BadSignature);
        }
    }
    // for each node in the chain, check it for validity and add it to the cache
    for b in nodes {
        if read_state.contains(&hash_node(b)) {
            read_state.add_proven_node(b);
        } else {
            return Err(DCClientError::BadProof("node not proven".into()));
        }
    }

    // check that the hash that we want to prove is in the cache
    if read_state.contains(expected_hash) {
        Ok(())
    } else {
        Err(DCClientError::BadProof("hash not proven".into()))
    }
}
