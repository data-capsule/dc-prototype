use std::io;

use bytes::{BufMut, BytesMut};
use postcard::{from_bytes, to_stdvec};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

use crate::shared::crypto::{DataCapsule, Hash, HashNode};

use super::crypto::Signature;

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    Init(InitRequest),
    Manage(ManageRequest),
    Read(ReadRequest),
    Write(WriteRequest),
    Subscribe(SubscribeRequest),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Init,                    // successful initialization
    ManageCreate(Signature), // sig of hash of created datacapsule
    ManageRead(DataCapsule),
    ReadData(Vec<u8>), // encrypted data
    ReadProof {
        root: Option<(Signature, Hash)>,
        nodes: Vec<HashNode>,
    },
    ReadSeed,
    WriteData,
    WriteCommit(Signature),
    SubscribeCommits(Vec<(Hash, Signature)>), // freshest commits
    SubscribeRecords(Vec<Hash>, Hash),        // records in a commit, and prev commit
    Failed,                                   // if any operation could not complete
}

#[derive(Serialize, Deserialize, Debug)]
pub enum InitRequest {
    Manage,
    Read(Hash),
    Write(Hash),
    Subscribe(Hash),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ManageRequest {
    Create(DataCapsule), // create a datacapsule
    Read(Hash),          // read a datacapsule
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ReadRequest {
    Data(Hash),
    Proof(Hash),
    // Seed(Vec<Hash>) TODO: implement option to seed with hashes
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WriteRequest {
    Data(Vec<u8>), // encrypted data
    Commit {
        additional_hash: Hash,
        signature: Signature,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SubscribeRequest {
    FreshestCommits(),
    Records(Hash),
}

fn io_err<T>(s: &str) -> Result<T, io::Error> {
    Err(io::Error::new(io::ErrorKind::Other, s))
}

fn encode<T: Serialize>(item: T, dst: &mut BytesMut) -> Result<(), io::Error> {
    let cheese = match to_stdvec(&item) {
        Ok(v) => v,
        Err(_) => return io_err("postcard serialization"),
    };
    let message_len: u64 = match cheese.len().try_into() {
        Ok(x) => x,
        Err(_) => return io_err("message len"),
    };
    let message_len = message_len.to_le_bytes();
    dst.reserve(8 + cheese.len());
    dst.put_slice(&message_len);
    dst.put_slice(&cheese);
    Ok(())
}

fn decode<T: Serialize + DeserializeOwned>(src: &mut BytesMut) -> Result<Option<T>, io::Error> {
    if src.len() < 8 {
        return Ok(None);
    }
    let message_len = &src[0..8];
    let message_len = u64::from_le_bytes(message_len.try_into().unwrap());
    let message_len: usize = match message_len.try_into() {
        Ok(x) => x,
        Err(_) => return io_err("message len"),
    };
    if src.len() < 8 + message_len {
        return Ok(None);
    }

    match from_bytes(&src.split_to(8 + message_len)[8..]) {
        Ok(item) => Ok(Some(item)),
        Err(_) => io_err("postcard deserialization"),
    }
}

pub struct ClientCodec(());

impl ClientCodec {
    pub fn new() -> Self {
        Self(())
    }
}

impl Encoder<Request> for ClientCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Request, dst: &mut BytesMut) -> Result<(), Self::Error> {
        encode(item, dst)
    }
}

impl Decoder for ClientCodec {
    type Item = Response;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode(src)
    }
}

pub struct ServerCodec(());

impl ServerCodec {
    pub fn new() -> Self {
        Self(())
    }
}

impl Encoder<Response> for ServerCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<(), Self::Error> {
        encode(item, dst)
    }
}

impl Decoder for ServerCodec {
    type Item = Request;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode(src)
    }
}
