use std::io;

use bytes::{BufMut, BytesMut};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use tokio_util::codec::{Encoder, Decoder};
use postcard::{to_stdvec, from_bytes};

use crate::crypto::{Hash, PublicKey, SignedHash};

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    Init(InitRequest),
    Create(CreateRequest),
    Read(ReadRequest),
    Write(WriteRequest),
    Subscribe(SubscribeRequest)
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Init(bool), // bool success
    Create(SignedHash), // hash of created datacapsule
    ReadData(Vec<u8>),
    ReadProof{root: SignedHash, hashes: Vec<Hash>},
    ReadSeed(bool),
    WriteData(bool),
    WriteCommit(SignedHash),
    SubscribeNum(u64), // last_num, num, wait_after
    SubscribeName(Hash) // name
}

#[derive(Serialize, Deserialize, Debug)]
pub enum InitRequest {
    Create,
    Read(Hash),
    Write(Hash),
    Subscribe(Hash)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateRequest {
    creator: PublicKey,
    writer: PublicKey,
    description: String,
    signature: SignedHash
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ReadRequest {
    Data(Hash),
    Proof(Hash),
    Seed(Vec<Hash>)
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WriteRequest {
    Data {
        data: Vec<u8>, 
        sequence_number: u64
    },
    Commit {
        additional_hash: Hash,
        signature: SignedHash
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SubscribeRequest {
    LastNum(u64),
    Name(u64),
    Num(Hash),
    Wait(u64)
}



fn io_err<T>(s: &str) -> Result<T, io::Error> {
    Err(io::Error::new(io::ErrorKind::Other, s))
}

fn encode<T: Serialize>(item: T, dst: &mut BytesMut) -> Result<(), io::Error> {
    let cheese = match to_stdvec(&item) {
        Ok(v) => v,
        Err(_) => {return io_err("postcard serialization")}
    };
    let message_len: u64 = match cheese.len().try_into() {
        Ok(x) => x,
        Err(_) => {return io_err("message len")}
    };
    let message_len = message_len.to_le_bytes();
    dst.reserve(8 + cheese.len());
    dst.put_slice(&message_len);
    dst.put_slice(&cheese);
    Ok(())
}

fn decode<'a, T: Serialize + DeserializeOwned>(src: &mut BytesMut) -> Result<Option<T>, io::Error> {
    if src.len() < 8 {
        return Ok(None)
    }
    let message_len = &src[0..8];
    let message_len = u64::from_le_bytes(message_len.try_into().unwrap());
    let message_len: usize = match message_len.try_into() {
        Ok(x) => x,
        Err(_) => {return io_err("message len")}
    };
    if src.len() < 8 + message_len {
        return Ok(None)
    }

    match from_bytes(&src.split_to(8 + message_len)) {
        Ok(item) => Ok(Some(item)),
        Err(_) => io_err("postcard deserialization")
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
