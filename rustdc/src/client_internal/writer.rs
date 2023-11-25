use futures::{
    future,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::{
    client_internal::DCError,
    crypto::{
        encrypt, hash_data, sign, verify_signature, Hash, PrivateKey, PublicKey, SymmetricKey,
    },
    merkle::merkle_tree_root,
    request::{ClientCodec, Request, Response, WriteRequest},
};

pub struct WriterConnection {
    connection_w: SplitSink<Framed<TcpStream, ClientCodec>, Request>,
    connection_r: SplitStream<Framed<TcpStream, ClientCodec>>,
    encryption_key: SymmetricKey,
    signing_key: PrivateKey,
    server_public_key: PublicKey,
    last_commit_hash: Hash,
    next_commit_start_number: u64,
    next_sequence_number: u64,
    uncommitted_hashes: Vec<Hash>,
}

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
        next_sequence_number: u64,
    ) -> Result<Self, DCError> {
        let tt = TcpStream::connect(server_address).await?;
        let stream = Framed::new(tt, ClientCodec::new());
        let (mut connection_w, mut connection_r) = stream.split();
        connection_w
            .send(Request::Init(crate::request::InitRequest::Write(
                datacapsule_name,
            )))
            .await?;
        let res = match connection_r.next().await {
            Some(x) => x?,
            None => return Err(DCError::Other("stream ended".to_string())),
        };

        match res {
            Response::Init(true) => {}
            _ => {
                return Err(DCError::ServerError("bad init".into()));
            }
        }

        Ok(Self {
            connection_w,
            connection_r,
            encryption_key,
            signing_key,
            server_public_key,
            last_commit_hash,
            next_commit_start_number: next_sequence_number,
            next_sequence_number,
            uncommitted_hashes: Vec::new(),
        })
    }

    /// Gets the sequence number corresponding to the start of the next
    /// commit, and the hash of the last commit.
    ///
    /// For example, if the last successful commit had 8 commits with sequence
    /// numbers 40..47 inclusive, and root hash ABCD, this would return
    /// (48, ABCD).
    pub fn get_checkpoint(&self) -> (u64, Hash) {
        (self.next_commit_start_number, self.last_commit_hash)
    }

    /// Does all the operations, in order. Concurrently sends and receives on
    /// the underlying TCP connection so that it does not have to wait for
    /// round trips.
    ///
    /// In case of failure, the `get_checkpoint` method can be used to figure
    /// out the last successful commit. A new connection should then be made,
    /// using the checkpoint as a starting point, then any unsuccessful
    /// operations may be re-done.
    pub async fn do_operations<'a>(
        &mut self,
        operations: &[WriterOperation<'a>],
    ) -> Result<(), DCError> {
        // Some implementation details:
        // in addition to the connection and encryption stuff, we have the
        // following state variables to worry about:
        //   last_commit_hash: Hash
        //   next_commit_start_number: u64
        //   next_sequence_number: u64
        //   uncommitted_hashes: Vec<Hash>
        // The first 2 are the "checkpoint". Be careful that in the case of
        // errors, these 2 should only reflect fully verified commits
        // The second 2 we don't have to be careful about; if an error
        // happens, those two should be thrown away.

        let mut hashes1 = Vec::new();
        let mut hashes2 = Vec::new();
        let f1 = Self::send_operations(
            &mut self.connection_w,
            &self.encryption_key,
            &self.signing_key,
            &mut self.uncommitted_hashes,
            &mut self.next_sequence_number,
            self.last_commit_hash,
            operations,
            &mut hashes1,
        );
        let f2 = Self::receive_operations(
            &mut self.connection_r,
            &self.server_public_key,
            operations,
            &mut hashes2,
        );
        let mut res = match future::join(f1, f2).await {
            (Err(e), _) | (_, Err(e)) => Err(e),
            (Ok(()), Ok(())) => Ok(()),
        };

        // verify that hashes match
        for a in 0..hashes2.len() {
            if hashes1[a].0 == hashes2[a] {
                // if a hash does match, that commit is confirmed
                // Update checkpoint accordingly
                self.last_commit_hash = hashes1[a].0;
                self.next_commit_start_number = hashes1[a].1;
            } else {
                res = Err(DCError::Cryptographic("mismatched hashes".to_string()));
            }
        }
        // throw away transient variables in case of an error
        if let Err(_) = res {
            self.next_sequence_number = self.next_commit_start_number;
            self.uncommitted_hashes.clear();
        }
        res
    }

    async fn send_operations<'a>(
        connection_w: &mut SplitSink<Framed<TcpStream, ClientCodec>, Request>,
        encryption_key: &SymmetricKey,
        signing_key: &PrivateKey,
        uncommitted_hashes: &mut Vec<Hash>,
        next_sequence_number: &mut u64,
        mut last_commit_hash: Hash,
        operations: &[WriterOperation<'a>],
        finished: &mut Vec<(Hash, u64)>,
    ) -> Result<(), DCError> {
        for op in operations {
            let req = match op {
                WriterOperation::Record(data) => {
                    // RECORD REQUEST: where all the magic happens
                    // encrypt the data, send it with a sequence number
                    // add the hash of seqno + encrypted data to uncommitted hashes
                    let encrypted_data = encrypt(*next_sequence_number, data, encryption_key);
                    uncommitted_hashes.push(hash_data(&encrypted_data));
                    let req = Request::Write(WriteRequest::Data(encrypted_data));
                    *next_sequence_number += 1;
                    req
                }
                WriterOperation::Commit => {
                    // COMMIT REQUEST: where all the magic happens
                    // build a merkle tree, clear the uncommitted hashes,
                    // send a commit request, update the last written hash
                    // updated finished with the root hash
                    let root_hash = merkle_tree_root(&uncommitted_hashes, &last_commit_hash);
                    let signature = sign(&root_hash, signing_key);
                    let req = Request::Write(WriteRequest::Commit {
                        additional_hash: last_commit_hash,
                        signature,
                    });
                    last_commit_hash = root_hash;
                    uncommitted_hashes.clear();
                    finished.push((root_hash, *next_sequence_number));
                    req
                }
            };
            // NOTE: should not flush
            // we want the possibility of multiple messages per TCP frame
            connection_w.feed(req).await?;
        }
        // make sure all the requests for this batch actually get sent
        connection_w.flush().await?;
        Ok(())
    }

    async fn receive_operations<'a>(
        connection_r: &mut SplitStream<Framed<TcpStream, ClientCodec>>,
        server_public_key: &PublicKey,
        operations: &[WriterOperation<'a>],
        finished: &mut Vec<Hash>,
    ) -> Result<(), DCError> {
        for op in operations {
            let resp = match connection_r.next().await {
                Some(r) => r?,
                None => return Err(DCError::Other("stream ended".to_string())),
            };
            match (resp, op) {
                (Response::WriteData(s), WriterOperation::Record(_)) => {
                    if !s {
                        return Err(DCError::ServerError("failed to write commit".into()));
                    }
                }
                (Response::WriteCommit(signed_hash), WriterOperation::Commit) => {
                    let signed_hash = match signed_hash {
                        Some(s) => s,
                        None => return Err(DCError::ServerError("could not commit".into())),
                    };
                    if verify_signature(&signed_hash, &server_public_key) {
                        finished.push(signed_hash.hash);
                    } else {
                        return Err(DCError::Cryptographic("bad signature".into()));
                    }
                }
                _ => return Err(DCError::ServerError("mismatched response".into())),
            }
        }
        Ok(())
    }
}
