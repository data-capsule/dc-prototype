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
    crypto::{decrypt, hash_data, hash_node, verify_signature, Hash, PublicKey, SymmetricKey},
    readstate::ReadState,
    request::{ClientCodec, InitRequest, ReadRequest, Request, Response},
};

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

pub enum ReaderResponse {
    Data { data: Vec<u8>, sequence_number: u64 },
    ValidProof,
}

impl ReaderConnection {
    pub async fn new(
        datacapsule_name: Hash,
        server_address: SocketAddr,
        encryption_key: SymmetricKey,
        writer_public_key: PublicKey,
    ) -> Result<Self, DCError> {
        let tt = TcpStream::connect(server_address).await?;
        let stream = Framed::new(tt, ClientCodec::new());
        let (mut connection_w, mut connection_r) = stream.split();
        connection_w
            .send(Request::Init(InitRequest::Read(datacapsule_name)))
            .await?;
        let res = match connection_r.next().await {
            Some(x) => x?,
            None => return Err(DCError::Other("stream ended".to_string())),
        };

        match res {
            Response::Init => {}
            _ => {
                return Err(DCError::ServerError("bad init".into()));
            }
        }

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
    ) -> Result<(), DCError> {
        let f1 = Self::send_operations(&mut self.connection_w, operations);
        let f2 = Self::receive_operations(
            &mut self.connection_r,
            &self.encryption_key,
            &self.writer_public_key,
            &mut self.read_state,
            operations,
            responses,
        );
        match future::join(f1, f2).await {
            (Err(e), _) | (_, Err(e)) => Err(e),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn send_operations(
        connection_w: &mut SplitSink<Framed<TcpStream, ClientCodec>, Request>,
        operations: &[ReaderOperation],
    ) -> Result<(), DCError> {
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
    ) -> Result<(), DCError> {
        for op in operations {
            let resp = match connection_r.next().await {
                Some(r) => r?,
                None => {
                    return Err(DCError::Other("stream ended".to_string()));
                }
            };
            let resp = match (resp, op) {
                (Response::Failed, _) => {
                    return Err(DCError::ServerError("server failed".into()));
                }
                (Response::ReadData(data), ReaderOperation::Data(hash)) => {
                    // DATA RESPONSE: where all the magic happens
                    // checks that the hash of the data is correct, then restures the data
                    if hash_data(&data) == *hash {
                        let decrypted = decrypt(&data, encryption_key);
                        ReaderResponse::Data {
                            data: decrypted.1,
                            sequence_number: decrypted.0,
                        }
                    } else {
                        return Err(DCError::Cryptographic("invalid hash".into()));
                    }
                }
                (Response::ReadProof { root, nodes }, ReaderOperation::Prove(hash)) => {
                    // PROOF RESPONSE: where all the magic happens
                    // checks the root signature, checks the hash of each node
                    // (adding to the cache as it goes)
                    // then checks that the given hash is in the cache

                    // if the root is provided, check it for validity and add it to the cache
                    if let Some(s) = root {
                        match verify_signature(&s, writer_public_key) {
                            Some(h) => read_state.add_signed_hash(&h),
                            None => return Err(DCError::Cryptographic("invalid signature".into())),
                        }
                    }
                    // for each node in the chain, check it for validity and add it to the cache
                    for b in nodes {
                        if read_state.contains(&hash_node(&b)) {
                            read_state.add_proven_node(&b);
                        } else {
                            return Err(DCError::Cryptographic("node not proven".into()));
                        }
                    }

                    // check that the hash that we want to prove is in the cache
                    if !read_state.contains(hash) {
                        return Err(DCError::Cryptographic("hash not proven".into()));
                    }
                    ReaderResponse::ValidProof
                }
                _ => return Err(DCError::ServerError("mismatched response".into())),
            };
            responses.push(resp);
        }
        Ok(())
    }
}
