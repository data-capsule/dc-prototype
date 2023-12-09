use std::io;

use bytes::{BufMut, BytesMut};
use postcard::{from_bytes, to_stdvec};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

use crate::shared::crypto::{DataCapsule, Hash, HashNode};

use super::crypto::Signature;

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    NewDataCapsule(DataCapsule), // create a datacapsule
    ReadMetadata(Hash), // dc name
    Init(Hash), // dc name
    Write(Vec<u8>), // encrypted data
    Commit(Hash, Signature), // additional hash, signature of root 
    Read(Hash),
    Proof(Hash),
    FreshestCommits,
    Records(Hash)
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    NewDataCapsule(Signature), // sig of hash of created datacapsule
    ReadMetadata(DataCapsule),
    Init, // successful init
    Write,
    Commit(Signature), // signed ack of commit root
    Read(Vec<u8>), // encrypted data
    Proof {
        root: Option<(Signature, Hash)>,
        nodes: Vec<HashNode>,
    },
    FreshestCommits(Vec<(Hash, Signature)>), // freshest commits
    Records(Vec<Hash>, Hash),        // records in a commit, and prev commit
    Failed,                                   // if any operation could not complete
}


