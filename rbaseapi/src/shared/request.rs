use serde::{Deserialize, Serialize};

use crate::shared::crypto::Hash;
use crate::shared::dc_repr;

use super::crypto::Signature;

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    Init(Hash), // read/write/subscribe to a certain datacapsule
    Manage(ManageRequest),
    RW(RWRequest),
    Subscribe(SubscribeRequest),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Init,                    // successful initialization
    ManageCreate(Signature), // sig of hash of created datacapsule
    ManageRead(dc_repr::Metadata),
    ReadRecord(dc_repr::Record),
    ReadProof(dc_repr::BestEffortProof),
    // TODO: batch server durability acks with separate `Ack(Vec<(Hash, Signature)>)`?
    // NOTE: temporarily changing Response::WriteData to match experimental API for benchmarking
    // WriteData((Hash, Signature)), // server durability ack (server-signed record name)
    WriteData(Hash),
    WriteSign((Hash, Signature)), // server durability ack (server-signed record name)
    SubscribeFresh(Vec<(Hash, Signature)>), // freshest commits
    Failed,                       // if any operation could not complete
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ManageRequest {
    Create(dc_repr::Metadata), // create a datacapsule
    Read(Hash),                // read a datacapsule
}

#[derive(Serialize, Deserialize, Debug)]
pub enum RWRequest {
    Write(dc_repr::Record),
    Sign(Hash, Signature), // (record name, signature of record header)
    Read(Hash),            // record name
    Proof(Hash),           // record name
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SubscribeRequest {
    FreshestSignedRecords,
}
