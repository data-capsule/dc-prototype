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
    shared::crypto::{decrypt, hash_data, Hash, PublicKey, SymmetricKey},
    shared::request::{ClientCodec, InitRequest, Request, Response},
    shared::{readstate::ReadState, request::RWRequest},
};

use super::{initialize_connection, writer::verify_proof};

pub struct ReaderConnection {
    connection_w: SplitSink<Framed<TcpStream, ClientCodec>, Request>,
    connection_r: SplitStream<Framed<TcpStream, ClientCodec>>,
    encryption_key: SymmetricKey,
    writer_public_key: PublicKey,
    read_state: ReadState,
}

pub enum ReaderOperation {
    Read(Hash),
    Prove(Hash),
}

#[derive(Debug)]
pub enum ReaderResponse {
    Read(Option<Vec<u8>>),
    Prove(bool),
}

impl ReaderConnection {
    pub async fn new(
        datacapsule_name: Hash,
        server_address: SocketAddr,
        encryption_key: SymmetricKey,
        writer_public_key: PublicKey,
    ) -> Result<Self, DCClientError> {
        let stream =
            initialize_connection(server_address, InitRequest::Write(datacapsule_name)).await?;
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
                ReaderOperation::Read(hash) => Request::RW(RWRequest::Read(*hash)),
                ReaderOperation::Prove(hash) => Request::RW(RWRequest::Proof(*hash)),
            };
            connection_w.feed(req).await?;
        }
        // make sure all the requests for this batch actually get sent
        connection_w.flush().await?;
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
                (Response::Failed, ReaderOperation::Read(_)) => ReaderResponse::Read(None),
                (Response::Failed, ReaderOperation::Prove(_)) => ReaderResponse::Prove(false),
                (Response::ReadData(data), ReaderOperation::Read(hash)) => {
                    // checks that the hash of the data is correct, then decrypts the data
                    if hash_data(&data) == *hash {
                        ReaderResponse::Read(Some(decrypt(&data, encryption_key)))
                    } else {
                        return Err(DCClientError::MismatchedHash);
                    }
                }
                (Response::ReadProof { root, nodes }, ReaderOperation::Prove(hash)) => {
                    verify_proof(hash, &root, &nodes, writer_public_key, read_state)?;
                    ReaderResponse::Prove(true)
                }
                _ => return Err(DCClientError::ServerError("mismatched response".into())),
            };
            responses.push(resp);
        }
        Ok(())
    }
}
