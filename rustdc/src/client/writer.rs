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
    shared::merkle::merkle_tree_root,
    shared::request::{ClientCodec, InitRequest, Request, Response, WriteRequest},
};

use super::initialize_connection;

pub struct WriterConnection {
    send_half: SendHalf,
    receive_half: ReceiveHalf,
}

struct SendHalf {
    connection_w: SplitSink<Framed<TcpStream, ClientCodec>, Request>,
    inner_w: UnboundedSender<(bool, Hash)>,
    encryption_key: SymmetricKey,
    signing_key: PrivateKey,
    uncommitted_hashes: Vec<Hash>,
}

struct ReceiveHalf {
    connection_r: SplitStream<Framed<TcpStream, ClientCodec>>,
    inner_r: UnboundedReceiver<(bool, Hash)>,
    server_public_key: PublicKey,
    last_commit_hash: Hash,
}

#[derive(Debug, Clone, Copy)]
pub enum WriterOperation<'a> {
    Record(&'a [u8]),
    Commit,
}

impl WriterConnection {
    pub async fn new(
        datacapsule_name: Hash,
        server_address: SocketAddr,
        server_public_key: PublicKey,
        encryption_key: SymmetricKey,
        signing_key: PrivateKey,
        last_commit_hash: Hash,
    ) -> Result<Self, DCClientError> {
        let stream =
            initialize_connection(server_address, InitRequest::Write(datacapsule_name)).await?;
        let (connection_w, connection_r) = stream.split();
        let (inner_w, inner_r) = mpsc::unbounded_channel::<(bool, Hash)>();
        Ok(Self {
            send_half: SendHalf {
                connection_w,
                inner_w,
                encryption_key,
                signing_key,
                uncommitted_hashes: Vec::new(),
            },
            receive_half: ReceiveHalf {
                connection_r,
                inner_r,
                server_public_key,
                last_commit_hash,
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
        responses: &mut Vec<Hash>,
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
            let req = match op {
                WriterOperation::Record(data) => {
                    // RECORD REQUEST: where all the magic happens
                    // encrypt the data, add the hash of encrypted data to uncommitted hashes
                    let encrypted_data = encrypt(data, &half.encryption_key);
                    let hash = hash_data(&encrypted_data);
                    half.uncommitted_hashes.push(hash);
                    if half.inner_w.send((false, hash)).is_err() {
                        return Err(DCClientError::Other("mpsc".to_string()));
                    }
                    Request::Write(WriteRequest::Data(encrypted_data))
                }
                WriterOperation::Commit => {
                    // COMMIT REQUEST: where all the magic happens
                    // build a merkle tree, clear the uncommitted hashes,
                    // send a commit request, update the last written hash
                    // updated finished with the root hash
                    let root_hash = merkle_tree_root(&half.uncommitted_hashes, &last_commit_hash);
                    let signature = sign(&root_hash, &half.signing_key);
                    let req = Request::Write(WriteRequest::Commit {
                        additional_hash: last_commit_hash,
                        signature,
                    });
                    last_commit_hash = root_hash;
                    half.uncommitted_hashes.clear();
                    if half.inner_w.send((true, root_hash)).is_err() {
                        return Err(DCClientError::Other("mpsc".to_string()));
                    }
                    req
                }
            };
            // NOTE: should not flush
            // we want the possibility of multiple messages per TCP frame
            half.connection_w.feed(req).await?;
        }
        // make sure all the requests for this batch actually get sent
        half.connection_w.flush().await?;
        Ok(())
    }

    async fn receive_operations<'a>(
        half: &mut ReceiveHalf,
        num_recvs: usize,
        responses: &mut Vec<Hash>,
    ) -> Result<(), DCClientError> {
        for _ in 0..num_recvs {
            let (is_commit, expected_hash) = match half.inner_r.recv().await {
                Some(p) => p,
                None => return Err(DCClientError::Other("mpsc".to_string())),
            };
            let resp = match half.connection_r.next().await {
                Some(r) => r?,
                None => return Err(DCClientError::Other("stream ended".to_string())),
            };
            match (resp, is_commit) {
                (Response::Failed, _) => {
                    return Err(DCClientError::ServerError("server failure".into()));
                }
                (Response::WriteData, false) => {
                    responses.push(expected_hash);
                }
                (Response::WriteCommit(signature), true) => {
                    if verify_signature(&signature, &expected_hash, &half.server_public_key) {
                        // commit is confirmed! woohoo
                        responses.push(expected_hash);
                        // set checkpoint variable
                        half.last_commit_hash = expected_hash;
                    } else {
                        return Err(DCClientError::Cryptographic("bad signature".into()));
                    }
                }
                _ => return Err(DCClientError::ServerError("mismatched response".into())),
            }
        }
        Ok(())
    }
}
