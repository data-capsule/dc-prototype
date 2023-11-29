use futures::{
    future,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::{
    client::DCClientError,
    shared::crypto::{
        decrypt, hash_data, hash_node, verify_signature, Hash, PublicKey, SymmetricKey,
    },
    shared::readstate::ReadState,
    shared::request::{ClientCodec, InitRequest, ReadRequest, Request, Response},
};

use super::initialize_connection;

pub struct ReaderConnection {
    connection_w: SplitSink<Framed<TcpStream, ClientCodec>, Request>,
    connection_r: SplitStream<Framed<TcpStream, ClientCodec>>,
    encryption_key: SymmetricKey,
    writer_public_key: PublicKey,
    read_state: ReadState,
}

pub enum ReaderOperation {
    Data(Hash),
    Prove(Hash),
}

#[derive(Debug)]
pub enum ReaderResponse {
    Data(Vec<u8>),
    ValidProof,
    ServerFailure,
}

impl ReaderConnection {
    pub async fn new(
        datacapsule_name: Hash,
        server_address: SocketAddr,
        encryption_key: SymmetricKey,
        writer_public_key: PublicKey,
    ) -> Result<Self, DCClientError> {
        let stream =
            initialize_connection(server_address, InitRequest::Read(datacapsule_name)).await?;
        let (connection_w, connection_r) = stream.split();
        Ok(Self {
            connection_w,
            connection_r,
            encryption_key,
            writer_public_key,
            read_state: ReadState::new(),
        })
    }

    /// Does all the operations, in order. Concurrently sends and receives on
    /// the underlying TCP connection so that it does not have to wait for
    /// round trips.
    ///
    /// In case of failure, the `responses` vector will contain the successful
    /// results up until the first failure. A new connection should then be
    /// made, then any unsuccessful operations may be re-done.
    pub async fn do_operations(
        &mut self,
        operations: &[ReaderOperation],
        responses: &mut Vec<ReaderResponse>,
    ) -> Result<(), DCClientError> {
        // You may also be wondering: why not just do all the sends,
        // then all the receives? Why bother with the fancy future join stuff?
        // The answer is TCP backpressure. If we do all the sends without
        // processing any receives, at some point the server will stop being
        // able to send results back to us, and the connection will close.

        let f1 = Self::send_operations(&mut self.connection_w, operations);
        let f2 = Self::receive_operations(
            &mut self.connection_r,
            &self.encryption_key,
            &self.writer_public_key,
            &mut self.read_state,
            operations,
            responses,
        );

        let (e1, e2) = future::join(f1, f2).await;

        match (e1, e2) {
            (Err(e), _) | (_, Err(e)) => Err(e),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn send_operations(
        connection_w: &mut SplitSink<Framed<TcpStream, ClientCodec>, Request>,
        operations: &[ReaderOperation],
    ) -> Result<(), DCClientError> {
        for op in operations {
            let req = match op {
                ReaderOperation::Data(hash) => Request::Read(ReadRequest::Data(*hash)),
                ReaderOperation::Prove(hash) => Request::Read(ReadRequest::Proof(*hash)),
            };
            connection_w.feed(req).await?;
        }
        // NOTE: should not flush
        // we want the possibility of multiple messages per TCP frame
        connection_w.flush().await?;
        // make sure all the requests for this batch actually get sent
        Ok(())
    }

    async fn receive_operations(
        connection_r: &mut SplitStream<Framed<TcpStream, ClientCodec>>,
        encryption_key: &SymmetricKey,
        writer_public_key: &PublicKey,
        read_state: &mut ReadState,
        operations: &[ReaderOperation],
        responses: &mut Vec<ReaderResponse>,
    ) -> Result<(), DCClientError> {
        for op in operations {
            let resp = match connection_r.next().await {
                Some(r) => r?,
                None => {
                    return Err(DCClientError::Other("stream ended".to_string()));
                }
            };
            let resp = match (resp, op) {
                (Response::Failed, _) => ReaderResponse::ServerFailure,
                (Response::ReadData(data), ReaderOperation::Data(hash)) => {
                    // DATA RESPONSE: where all the magic happens
                    // checks that the hash of the data is correct, then decrypts the data
                    if hash_data(&data) == *hash {
                        ReaderResponse::Data(decrypt(&data, encryption_key))
                    } else {
                        return Err(DCClientError::MismatchedHash);
                    }
                }
                (Response::ReadProof { root, nodes }, ReaderOperation::Prove(hash)) => {
                    // PROOF RESPONSE: where all the magic happens
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
                        if read_state.contains(&hash_node(&b)) {
                            read_state.add_proven_node(&b);
                        } else {
                            return Err(DCClientError::BadProof("node not proven".into()));
                        }
                    }

                    // check that the hash that we want to prove is in the cache
                    if !read_state.contains(hash) {
                        return Err(DCClientError::BadProof("hash not proven".into()));
                    }
                    ReaderResponse::ValidProof
                }
                _ => return Err(DCClientError::ServerError("mismatched response".into())),
            };
            responses.push(resp);
        }
        Ok(())
    }
}
