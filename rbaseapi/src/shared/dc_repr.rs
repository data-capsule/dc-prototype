use std::convert::From;

use serde::{Deserialize, Serialize};

use crate::shared::crypto::{Hash, Signature};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Metadata {
    pub creator_pub_key: Vec<u8>,
    pub writer_pub_key: Vec<u8>,
    pub description: String,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
    pub body: RecordBody,
    pub header: RecordHeader,
}

pub type RecordBody = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordHeader {
    // pub dc_name: Hash, // "GDP name"
    pub body_ptr: Hash,
    // pub prev_record_ptr: Hash,
    pub record_backptrs: Vec<RecordBackPtr>,
}

// TODO: not super sure about this
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordBackPtr {
    pub ptr: Hash,           // hash of pointed-to record header
    pub offset: Option<u64>, // num hops from current record to this `ptr`
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RecordWitness {
    Signature(Signature),
    NextRecordPtr(Hash, u64), // on path to closest signed record. u64 is num hops to closest signed record.
    None,
}

impl RecordWitness {
    pub fn closer_than(&self, other: &RecordWitness) -> bool {
        match (self, other) {
            (RecordWitness::None, RecordWitness::None) => false,
            (RecordWitness::Signature(_), RecordWitness::None) => true,
            (RecordWitness::None, RecordWitness::Signature(_)) => false,
            (RecordWitness::NextRecordPtr(_, _), RecordWitness::None) => true,
            (RecordWitness::None, RecordWitness::NextRecordPtr(_, _)) => false,
            (RecordWitness::Signature(_), RecordWitness::Signature(_)) => false,
            (RecordWitness::Signature(_), RecordWitness::NextRecordPtr(_, _)) => true,
            (RecordWitness::NextRecordPtr(_, _), RecordWitness::Signature(_)) => false,
            (RecordWitness::NextRecordPtr(_, d1), RecordWitness::NextRecordPtr(_, d2)) => d1 < d2,
        }
    }

    pub fn closer<'a>(w1: &'a RecordWitness, w2: &'a RecordWitness) -> &'a RecordWitness {
        if w1.closer_than(w2) {
            w1
        } else {
            w2
        }
    }
}

impl From<Option<RecordWitness>> for RecordWitness {
    fn from(other: Option<RecordWitness>) -> Self {
        match other {
            Some(w) => w,
            None => RecordWitness::None,
        }
    }
}

// best-effort and not guaranteed to be complete.
// see server/writer.rs for details.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BestEffortProof {
    pub chain: Vec<RecordHeader>, // from earlier to later
    pub signature: Option<(Hash, Signature)>,
}
