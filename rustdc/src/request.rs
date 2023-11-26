use std::io;

use bytes::{BufMut, BytesMut};
use postcard::{from_bytes, to_stdvec};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

use crate::crypto::{Hash, HashNode, SignedHash};

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    Init(InitRequest),
    Create(CreateRequest),
    Read(ReadRequest),
    Write(WriteRequest),
    Subscribe(SubscribeRequest),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Init,               // successful initialization
    Create(SignedHash), // hash of created datacapsule
    ReadData(Vec<u8>),  // encrypted data, includes seqno
    ReadProof {
        root: Option<SignedHash>,
        nodes: Vec<HashNode>,
    },
    ReadSeed,
    WriteData,
    WriteCommit(SignedHash),
    SubscribeNum(u64),   // last_num, num, wait_after
    SubscribeName(Hash), // name
    Failed,              // if any operation could not complete
}

#[derive(Serialize, Deserialize, Debug)]
pub enum InitRequest {
    Create,
    Read(Hash),
    Write(Hash),
    Subscribe(Hash),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateRequest {
    creator_pub_key: Vec<u8>,
    writer_pub_key: Vec<u8>,
    description: String,
    signature: SignedHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ReadRequest {
    Data(Hash),
    Proof(Hash),
    // Seed(Vec<Hash>) TODO: implement option to seed with hashes
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WriteRequest {
    Data(Vec<u8>), // encrypted data, includes seqno
    Commit {
        additional_hash: Hash,
        signature: SignedHash,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SubscribeRequest {
    LastNum(u64),
    Name(u64),
    Num(Hash),
    Wait(u64),
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

    match from_bytes(&src.split_to(8 + message_len)) {
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
