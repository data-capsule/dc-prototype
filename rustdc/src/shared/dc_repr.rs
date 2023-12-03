use serde::{Deserialize, Serialize};

use crate::shared::crypto::{Hash, Signature};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Metadata {
    pub creator_pub_key: Vec<u8>,
    pub writer_pub_key: Vec<u8>,
    pub description: String,
    pub signature: Signature,
}

pub type RecordBody = [u8];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordHeader {
    pub dc_name: Hash, // "GDP name"
    pub body_ptr: Hash,
    pub prev_record_ptr: Hash,
    pub additional_record_ptrs: Vec<AdditionalRecordPtr>,
}

// TODO: not super sure about this
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AdditionalRecordPtr {
    pub ptr: Hash,
    pub offset: Option<u64>, // num hops from current record to this `ptr`
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum RecordWitness {
    Signature(Signature),
    NextRecordPtr(Hash, u64), // on path to closest signed record. u64 is num hops to closest signed record.
    None,
}

pub fn closer_witness<'a>(w1: &'a RecordWitness, w2: &'a RecordWitness) -> &'a RecordWitness {
    match (&w1, &w2) {
        (RecordWitness::None, RecordWitness::None) => &w1, // arbitrary
        (RecordWitness::Signature(_), RecordWitness::None) => &w1,
        (RecordWitness::None, RecordWitness::Signature(_)) => &w2,
        (RecordWitness::NextRecordPtr(_, _), RecordWitness::None) => &w1,
        (RecordWitness::None, RecordWitness::NextRecordPtr(_, _)) => &w2,
        (RecordWitness::Signature(_), RecordWitness::Signature(_)) => &w1, // arbitrary
        (RecordWitness::Signature(_), RecordWitness::NextRecordPtr(_, _)) => &w1,
        (RecordWitness::NextRecordPtr(_, _), RecordWitness::Signature(_)) => &w2,
        (RecordWitness::NextRecordPtr(_, d1), RecordWitness::NextRecordPtr(_, d2)) => {
            if d1 <= d2 {
                &w1
            } else {
                &w2
            }
        }
    }
}
